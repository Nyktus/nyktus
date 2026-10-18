// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenarioapi

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/platform/apispec"
	"nyktus.org/nyktus/internal/platform/schematest"
)

const sshConfig = `{"name": "Jump server", "language": "de", "persona": {"Domain": "corp.example.com", "Account": "j.doe"}}`

func (f fixture) apply(t *testing.T, deception, body string) applyResponse {
	t.Helper()
	rec := f.serve(t, f.h.Apply, http.MethodPost, "/api/v1/catalog/deceptions/"+deception+"/apply", deception, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST apply %s: %d %s", deception, rec.Code, rec.Body)
	}
	return decode[applyResponse](t, rec)
}

// Applying a deception answers with the scenario, its honeytokens with their
// names under every zone and its artifacts, and the guide can be read.
func TestApply_ReturnsTheScenarioWithItsResources(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	got := f.apply(t, "ssh-config", sshConfig)
	sc := got.Scenario
	if sc.Name != "Jump server" || sc.DeceptionID == nil || *sc.DeceptionID != "ssh-config" || sc.Language == nil ||
		*sc.Language != "de" || sc.Persona["Account"] != "j.doe" || len(sc.EngageActivities) == 0 {
		t.Errorf("scenario = %+v", sc)
	}
	if len(got.Honeytokens) != 1 || got.Honeytokens[0].ScenarioID == nil || *got.Honeytokens[0].ScenarioID != sc.ID ||
		len(got.Honeytokens[0].TriggerNames) != 2 || got.Honeytokens[0].TriggerNames[0] != got.Honeytokens[0].TriggerValue+"."+dnsZone {
		t.Errorf("honeytokens = %+v, want one in the scenario with a name under each zone", got.Honeytokens)
	}
	if len(got.Artifacts) != 1 || got.Artifacts[0].FileName != "config" || got.Artifacts[0].MediaType != "application/octet-stream" ||
		got.Artifacts[0].Size == 0 {
		t.Errorf("artifacts = %+v", got.Artifacts)
	}

	rec := f.serve(t, f.h.Guide, http.MethodGet, "/", sc.ID, "")
	guide := decode[guideResponse](t, rec)
	if rec.Code != http.StatusOK || guide.Language != "de" || !strings.Contains(guide.Content, got.Honeytokens[0].TriggerNames[0]) {
		t.Errorf("GET guide = %d %s", rec.Code, rec.Body)
	}
	// Without a language, the guide is English.
	en := f.apply(t, "ssh-config", `{"name": "s", "persona": {"Domain": "corp.example.com", "Account": "j.doe"}}`)
	if en.Scenario.Language == nil || *en.Scenario.Language != "en" {
		t.Errorf("language without one = %v, want en", en.Scenario.Language)
	}
}

func TestApply_RejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	for _, tt := range []struct {
		deception, body string
		status          int
		code, message   string
	}{
		{"telnet", sshConfig, http.StatusNotFound, "not_found", ""},
		{"ssh-config", `{"persona": {"Domain": "corp.example.com", "Account": "j.doe"}}`, http.StatusBadRequest, "invalid_request", "name"},
		{"ssh-config", strings.Replace(sshConfig, `"de"`, `"fr"`, 1), http.StatusBadRequest, "invalid_request", "language must be one of en, de"},
		{"ssh-config", strings.Replace(sshConfig, `"de"`, `null`, 1), http.StatusBadRequest, "invalid_request", ""},
		{"ssh-config", `{"name": "s"}`, http.StatusBadRequest, "invalid_request", "persona Domain: is required"},
		{"ssh-config", `{"name": "s", "persona": null}`, http.StatusBadRequest, "invalid_request", ""},
		{"ssh-config", strings.Replace(sshConfig, "corp.example.com", "Corp Example", 1), http.StatusBadRequest, "invalid_request", "persona Domain: must be a host name"},
		{"ssh-config", strings.Replace(sshConfig, `"Account": "j.doe"`, `"Account": "j.doe", "Zone": "x"`, 1), http.StatusBadRequest, "invalid_request", "persona Zone: is not a value"},
		{"ssh-config", strings.Replace(sshConfig, `"name"`, `"deception_id": "netrc", "name"`, 1), http.StatusBadRequest, "invalid_request", ""},
		{"ssh-config", strings.Replace(sshConfig, "corp.example.com", "decoy.example.com", 1), http.StatusUnprocessableEntity, "artifact_reveals_decoy", "the artifact config would contain"},
	} {
		rec := f.serve(t, f.h.Apply, http.MethodPost, "/", tt.deception, tt.body)
		if rec.Code != tt.status || errorCode(t, rec) != tt.code || !strings.Contains(rec.Body.String(), tt.message) {
			t.Errorf("POST %s %s = %d %s, want %d %s with %q", tt.deception, tt.body, rec.Code, rec.Body, tt.status, tt.code, tt.message)
		}
		// The value that reveals the artifact is not repeated in the answer.
		if strings.Contains(rec.Body.String(), "decoy.example.com") {
			t.Errorf("POST %s: the answer repeats the value of the persona", tt.body)
		}
	}
	var n int
	if err := f.owner.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM scenarios) + (SELECT count(*) FROM honeytokens) + (SELECT count(*) FROM artifacts)`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d rows, %v; want none", n, err)
	}
}

// A deception with a DNS honeytoken needs a zone; one without does not.
func TestApply_DNSHoneytokenNeedsZones(t *testing.T) {
	t.Parallel()
	ownerURL, consoleURL := schematest.Console(t)
	f := newFixture(t)
	f.h = NewHandler(slog.New(slog.DiscardHandler), schematest.Open(t, consoleURL), testCatalog(t), triggerURL, nil)
	f.owner = schematest.Open(t, ownerURL)
	if _, err := f.owner.Exec(t.Context(), `INSERT INTO users (id, email, display_name, role, status, password_hash)
VALUES ($1, 'user@example.com', 'Test User', 'user', 'active', '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA')`, f.principal.UserID); err != nil {
		t.Fatal(err)
	}

	rec := f.serve(t, f.h.Apply, http.MethodPost, "/", "ssh-config", sshConfig)
	if rec.Code != http.StatusUnprocessableEntity || errorCode(t, rec) != "dns_not_configured" {
		t.Errorf("POST ssh-config without zones = %d %s, want 422 dns_not_configured", rec.Code, rec.Body)
	}
	got := f.apply(t, "windows-shortcut", `{"name": "s", "persona": {}}`)
	if len(got.Honeytokens) != 1 || got.Honeytokens[0].TriggerURL == nil || !strings.HasPrefix(*got.Honeytokens[0].TriggerURL, triggerURL+"/") {
		t.Errorf("honeytokens = %+v, want a URL of the trigger", got.Honeytokens)
	}
}

// The guide of a scenario by hand, or of none, is not found.
func TestGuide_NotFound(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	sc := f.create(t, `{"name": "s"}`)

	for _, id := range []string{sc.ID, "00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if rec := f.serve(t, f.h.Guide, http.MethodGet, "/", id, ""); rec.Code != http.StatusNotFound || errorCode(t, rec) != "not_found" {
			t.Errorf("GET guide of %s = %d %s, want 404", id, rec.Code, rec.Body)
		}
	}
}

// The deletion keeps the artifacts of the scenario unless the request asks
// to delete them, independently of the honeytokens.
func TestDelete_KeepsOrDeletesTheArtifacts(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	for _, tt := range []struct {
		query                string
		artifacts, honeytoks int
	}{
		{"", 1, 1},
		{"?artifacts=delete", 0, 1},
		{"?artifacts=keep&honeytokens=delete", 1, 0},
	} {
		got := f.apply(t, "ssh-config", sshConfig)
		rec := f.serve(t, f.h.Delete, http.MethodDelete, "/api/v1/scenarios/"+got.Scenario.ID+tt.query, got.Scenario.ID, "")
		if rec.Code != http.StatusNoContent {
			t.Errorf("DELETE %s = %d %s, want 204", tt.query, rec.Code, rec.Body)
		}
		var artifacts, honeytokens int
		if err := f.owner.QueryRow(t.Context(), `
SELECT (SELECT count(*) FROM artifacts WHERE id = $1 AND scenario_id IS NULL),
	(SELECT count(*) FROM honeytokens WHERE id = $2 AND scenario_id IS NULL)`, got.Artifacts[0].ID, got.Honeytokens[0].ID).Scan(&artifacts, &honeytokens); err != nil {
			t.Fatal(err)
		}
		if artifacts != tt.artifacts || honeytokens != tt.honeytoks {
			t.Errorf("DELETE %s: %d artifacts and %d honeytokens kept, want %d and %d", tt.query, artifacts, honeytokens, tt.artifacts, tt.honeytoks)
		}
	}
	for _, query := range []string{"?artifacts=cascade", "?artifacts=", "?artifacts=keep&artifacts=delete"} {
		got := f.apply(t, "ssh-config", sshConfig)
		rec := f.serve(t, f.h.Delete, http.MethodDelete, "/api/v1/scenarios/"+got.Scenario.ID+query, got.Scenario.ID, "")
		if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
			t.Errorf("DELETE %s = %d %s, want 400 invalid_request", query, rec.Code, rec.Body)
		}
	}
}

// What applying a deception and reading a guide answer matches the schemas
// of the specification, also for a scenario of a deception.
func TestApplyAndGuide_MatchTheSpecification(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	schemas, err := apispec.ParseSchemas(api.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}

	applied := f.serve(t, f.h.Apply, http.MethodPost, "/", "ssh-config", sshConfig)
	id := decode[applyResponse](t, applied).Scenario.ID
	for _, b := range []struct {
		schema string
		body   []byte
	}{
		{"AppliedDeception", applied.Body.Bytes()},
		{"AppliedDeception", f.serve(t, f.h.Apply, http.MethodPost, "/", "browser-bookmarks", `{"name": "b", "persona": {"Company": "Example Ltd", "PortalName": "Intranet"}}`).Body.Bytes()},
		{"ScenarioGuide", f.serve(t, f.h.Guide, http.MethodGet, "/", id, "").Body.Bytes()},
		{"Scenario", f.serve(t, f.h.Get, http.MethodGet, "/", id, "").Body.Bytes()},
	} {
		for _, p := range schemas.Check(b.schema, b.body) {
			t.Errorf("%s: %s", b.schema, p)
		}
	}
}
