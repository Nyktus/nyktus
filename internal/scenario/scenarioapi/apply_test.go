// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenarioapi

import (
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/honeytoken/honeytokenapi"
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

	got := f.apply(t, "remote-access", sshConfig)
	sc := got.Scenario
	if sc.Name != "Jump server" || len(sc.Deceptions) != 1 || sc.Deceptions[0].DeceptionID != "remote-access" ||
		sc.Deceptions[0].Language != "de" || sc.Persona["Account"] != "j.doe" ||
		!slices.Equal(sc.EngageActivities, []string{"EAC0005", "EAC0011", "EAC0022", "EAC0012"}) {
		t.Errorf("scenario = %+v", sc)
	}
	if len(got.Honeytokens) != 4 {
		t.Errorf("honeytokens = %+v, want the four of the deception", got.Honeytokens)
	}
	for _, h := range got.Honeytokens {
		if h.ScenarioID == nil || *h.ScenarioID != sc.ID || len(h.TriggerNames) != 2 || h.TriggerNames[0] != h.TriggerValue+"."+dnsZone {
			t.Errorf("honeytoken = %+v, want one in the scenario with a name under each zone", h)
		}
	}
	if len(got.Artifacts) != 6 {
		t.Errorf("artifacts = %+v, want the six of the deception", got.Artifacts)
	}
	var jumpHost string
	for _, a := range got.Artifacts {
		if a.CatalogArtifact != "ssh-config" {
			continue
		}
		jumpHost = a.Bindings["JumpHost"]
		if a.FileName != "config" || a.MediaType != "application/octet-stream" || a.Size == 0 {
			t.Errorf("artifact = %+v", a)
		}
	}
	if !slices.ContainsFunc(got.Honeytokens, func(h honeytokenapi.Response) bool { return h.ID == jumpHost }) {
		t.Errorf("the artifact ssh-config is bound to %q, want a honeytoken of the scenario", jumpHost)
	}

	rec := f.serve(t, f.h.Guide, http.MethodGet, "/", sc.ID, "")
	guides := decode[guidesResponse](t, rec)
	if rec.Code != http.StatusOK || len(guides.Guides) != 1 || guides.Guides[0].DeceptionID != "remote-access" ||
		guides.Guides[0].Language != "de" || !strings.Contains(guides.Guides[0].Content, got.Honeytokens[0].TriggerNames[0]) {
		t.Errorf("GET guide = %d %s", rec.Code, rec.Body)
	}
	// Without a language, the guide is English.
	en := f.apply(t, "remote-access", `{"name": "s", "persona": {"Domain": "corp.example.com", "Account": "j.doe"}}`)
	if len(en.Scenario.Deceptions) != 1 || en.Scenario.Deceptions[0].Language != "en" {
		t.Errorf("language without one = %+v, want en", en.Scenario.Deceptions)
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
		{"remote-access", `{"persona": {"Domain": "corp.example.com", "Account": "j.doe"}}`, http.StatusBadRequest, "invalid_request", "name"},
		{"remote-access", strings.Replace(sshConfig, `"de"`, `"fr"`, 1), http.StatusBadRequest, "invalid_request", "language must be one of en, de"},
		{"remote-access", strings.Replace(sshConfig, `"de"`, `null`, 1), http.StatusBadRequest, "invalid_request", ""},
		{"remote-access", `{"name": "s"}`, http.StatusBadRequest, "invalid_request", "persona Domain: is required"},
		{"remote-access", `{"name": "s", "persona": null}`, http.StatusBadRequest, "invalid_request", ""},
		{"remote-access", strings.Replace(sshConfig, "corp.example.com", "Corp Example", 1), http.StatusBadRequest, "invalid_request", "persona Domain: must be a host name"},
		{"remote-access", strings.Replace(sshConfig, `"Account": "j.doe"`, `"Account": "j.doe", "Zone": "x"`, 1), http.StatusBadRequest, "invalid_request", "persona Zone: is not a value"},
		{"remote-access", strings.Replace(sshConfig, `"name"`, `"deception_id": "netrc", "name"`, 1), http.StatusBadRequest, "invalid_request", ""},
		{"remote-access", strings.Replace(sshConfig, `"name"`, `"artifacts": ["netrc"], "name"`, 1), http.StatusBadRequest, "invalid_request", "artifacts must name"},
		{"remote-access", strings.Replace(sshConfig, `"name"`, `"artifacts": ["ssh-config", "ssh-config"], "name"`, 1), http.StatusBadRequest, "invalid_request", "artifacts must name"},
		{"remote-access", strings.Replace(sshConfig, `"name"`, `"artifacts": null, "name"`, 1), http.StatusBadRequest, "invalid_request", ""},
		{"remote-access", strings.Replace(sshConfig, "corp.example.com", "decoy.example.com", 1), http.StatusUnprocessableEntity, "artifact_reveals_decoy", "the artifact rdp-connection would contain"},
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

	rec := f.serve(t, f.h.Apply, http.MethodPost, "/", "remote-access", sshConfig)
	if rec.Code != http.StatusUnprocessableEntity || errorCode(t, rec) != "dns_not_configured" {
		t.Errorf("POST remote-access without zones = %d %s, want 422 dns_not_configured", rec.Code, rec.Body)
	}
	got := f.apply(t, "adcs-template-catalog", `{"name": "s", "persona": {"Company": "Example Ltd", "Authority": "Example CA"}}`)
	if len(got.Honeytokens) != 1 || got.Honeytokens[0].TriggerURL == nil || !strings.HasPrefix(*got.Honeytokens[0].TriggerURL, triggerURL+"/") {
		t.Errorf("honeytokens = %+v, want a URL of the trigger", got.Honeytokens)
	}
}

// A scenario by hand has no guides, and an unknown one is not found.
func TestGuide_OfAScenarioByHandAndOfNone(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	sc := f.create(t, `{"name": "s"}`)

	rec := f.serve(t, f.h.Guide, http.MethodGet, "/", sc.ID, "")
	if got := decode[guidesResponse](t, rec); rec.Code != http.StatusOK || got.Guides == nil || len(got.Guides) != 0 {
		t.Errorf("GET guide of a scenario by hand = %d %s, want an empty list", rec.Code, rec.Body)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
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
		got := f.apply(t, "remote-access", sshConfig)
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
		got := f.apply(t, "remote-access", sshConfig)
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

	applied := f.serve(t, f.h.Apply, http.MethodPost, "/", "remote-access", sshConfig)
	id := decode[applyResponse](t, applied).Scenario.ID
	for _, b := range []struct {
		schema string
		body   []byte
	}{
		{"AppliedDeception", applied.Body.Bytes()},
		{"AppliedDeception", f.serve(t, f.h.Apply, http.MethodPost, "/", "adcs-template-catalog", `{"name": "b", "persona": {"Company": "Example Ltd", "Authority": "Example CA"}}`).Body.Bytes()},
		{"ScenarioGuides", f.serve(t, f.h.Guide, http.MethodGet, "/", id, "").Body.Bytes()},
		{"Scenario", f.serve(t, f.h.Get, http.MethodGet, "/", id, "").Body.Bytes()},
	} {
		for _, p := range schemas.Check(b.schema, b.body) {
			t.Errorf("%s: %s", b.schema, p)
		}
	}
}
