// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenarioapi

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/artifact/artifactapi"
	"nyktus.org/nyktus/internal/platform/apispec"
	"nyktus.org/nyktus/internal/platform/schematest"
)

const (
	// adcsCatalog has a URL honeytoken and asks for the company and the name
	// of the authority; directoryAndShares a DNS honeytoken, the domain and a
	// contact; sshConfig the domain and an account.
	adcsCatalog        = `{"deception_id": "adcs-template-catalog", "persona": {"Company": "Example Ltd", "Authority": "Example CA"}}`
	directoryAndShares = `{"deception_id": "directory-and-shares", "language": "de", "persona": {"Contact": "IT service desk", "ComputerName": "fs-archive01"}}`
)

func (f fixture) addDeception(t *testing.T, scenarioID, body string) applyResponse {
	t.Helper()
	rec := f.serve(t, f.h.AddDeception, http.MethodPost, "/", scenarioID, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST deceptions %s: %d %s", body, rec.Code, rec.Body)
	}
	return decode[applyResponse](t, rec)
}

func (f fixture) addArtifact(t *testing.T, scenarioID, body string) addArtifactResponse {
	t.Helper()
	rec := f.serve(t, f.h.AddArtifact, http.MethodPost, "/", scenarioID, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST artifacts %s: %d %s", body, rec.Code, rec.Body)
	}
	return decode[addArtifactResponse](t, rec)
}

// A deception joins a scenario that was applied: the answer holds the scenario
// after the change with the honeytokens and artifacts that were created, the
// guides are those of both, and the persona keeps the domain.
func TestAddDeception_ReturnsTheScenarioAfterTheChange(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	first := f.apply(t, "remote-access", sshConfig)
	id := first.Scenario.ID

	got := f.addDeception(t, id, `{"deception_id": "directory-and-shares", "language": "de", "persona": {"Domain": "corp.example.com", "Contact": "IT service desk", "ComputerName": "fs-archive01"}}`)
	sc := got.Scenario
	if sc.ID != id || len(sc.Deceptions) != 2 || sc.Deceptions[1].DeceptionID != "directory-and-shares" || sc.Deceptions[1].Language != "de" ||
		sc.Deceptions[0].Language != "de" || sc.Persona["Domain"] != "corp.example.com" || sc.Persona["Contact"] != "IT service desk" ||
		sc.Persona["Account"] != "j.doe" {
		t.Errorf("scenario = %+v", sc)
	}
	if len(got.Honeytokens) != 3 || got.Honeytokens[0].ScenarioID == nil || *got.Honeytokens[0].ScenarioID != id ||
		len(got.Artifacts) != 5 || got.Artifacts[0].CatalogArtifact != "dfs-namespace-map" ||
		len(got.Artifacts[0].Bindings) != 1 || got.Artifacts[0].Bindings["FileServer"] != got.Honeytokens[0].ID {
		t.Errorf("honeytokens %+v, artifacts %+v", got.Honeytokens, got.Artifacts)
	}

	rec := f.serve(t, f.h.Guide, http.MethodGet, "/", id, "")
	guides := decode[guidesResponse](t, rec)
	if len(guides.Guides) != 2 || guides.Guides[0].DeceptionID != "remote-access" || guides.Guides[1].DeceptionID != "directory-and-shares" ||
		!strings.Contains(guides.Guides[1].Content, got.Honeytokens[0].TriggerNames[0]) {
		t.Errorf("guides = %+v", guides)
	}
	// The value may be left out: the scenario has it.
	again := f.apply(t, "remote-access", sshConfig)
	left := f.addDeception(t, again.Scenario.ID, directoryAndShares)
	if left.Scenario.Persona["Domain"] != "corp.example.com" {
		t.Errorf("persona = %v, want the domain of the scenario", left.Scenario.Persona)
	}
	// A scenario put together by hand takes a deception as well.
	byHand := f.create(t, `{"name": "by hand"}`)
	hand := f.addDeception(t, byHand.ID, adcsCatalog)
	if len(hand.Scenario.Deceptions) != 1 || len(hand.Honeytokens) != 1 {
		t.Errorf("by hand = %+v", hand)
	}
}

func TestAddDeception_RejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	applied := f.apply(t, "remote-access", sshConfig)
	id := applied.Scenario.ID
	other := f.apply(t, "adcs-template-catalog", `{"name": "b", "persona": {"Company": "Example Ltd", "Authority": "Example CA"}}`)

	for _, tt := range []struct {
		name, scenario, body string
		status               int
		code, message        string
	}{
		{"unknown scenario", "00000000-0000-4000-8000-000000000000", directoryAndShares, http.StatusNotFound, "not_found", ""},
		{"identifier that is no uuid", "not-a-uuid", directoryAndShares, http.StatusNotFound, "not_found", ""},
		{"unknown deception", id, `{"deception_id": "telnet"}`, http.StatusBadRequest, "invalid_request", "deception_id must be a deception of the catalog"},
		{"no deception", id, `{}`, http.StatusBadRequest, "invalid_request", "deception_id must be a deception"},
		{"the deception twice", id, `{"deception_id": "remote-access", "persona": {}}`, http.StatusConflict, "deception_already_added", "part of the scenario already"},
		{"another value of the persona", id, `{"deception_id": "directory-and-shares", "persona": {"Domain": "other.example.com", "Contact": "IT", "ComputerName": "fs-archive01"}}`, http.StatusConflict, "persona_conflict", "persona Domain"},
		{"a key that is missing", other.Scenario.ID, `{"deception_id": "directory-and-shares"}`, http.StatusBadRequest, "invalid_request", "persona Domain: is required"},
		{"a value of the wrong kind", id, `{"deception_id": "directory-and-shares", "persona": {"Contact": "a\nb"}}`, http.StatusBadRequest, "invalid_request", "persona Contact: must be text"},
		{"a key that is not asked for", id, `{"deception_id": "directory-and-shares", "persona": {"Contact": "IT", "ComputerName": "fs-archive01", "Zone": "x"}}`, http.StatusBadRequest, "invalid_request", "persona Zone: is not a value"},
		{"artifacts of another deception", id, `{"deception_id": "directory-and-shares", "persona": {"Contact": "IT", "ComputerName": "fs-archive01"}, "artifacts": ["ssh-config"]}`, http.StatusBadRequest, "invalid_request", "artifacts must name"},
		{"unknown language", id, `{"deception_id": "directory-and-shares", "language": "fr", "persona": {"Contact": "IT", "ComputerName": "fs-archive01"}}`, http.StatusBadRequest, "invalid_request", "language must be one of en, de"},
		{"null persona", id, `{"deception_id": "directory-and-shares", "persona": null}`, http.StatusBadRequest, "invalid_request", ""},
		{"null artifacts", id, `{"deception_id": "directory-and-shares", "artifacts": null}`, http.StatusBadRequest, "invalid_request", ""},
		{"unknown member", id, `{"deception_id": "directory-and-shares", "name": "x"}`, http.StatusBadRequest, "invalid_request", ""},
		{"trailing data", id, directoryAndShares + ` {}`, http.StatusBadRequest, "invalid_request", ""},
		{"not JSON", id, `deception`, http.StatusBadRequest, "invalid_request", ""},
	} {
		rec := f.serve(t, f.h.AddDeception, http.MethodPost, "/", tt.scenario, tt.body)
		if rec.Code != tt.status || errorCode(t, rec) != tt.code || !strings.Contains(rec.Body.String(), tt.message) {
			t.Errorf("%s: POST %s = %d %s, want %d %s with %q", tt.name, tt.body, rec.Code, rec.Body, tt.status, tt.code, tt.message)
		}
		// Neither the value of the request nor the one the scenario has is repeated.
		for _, value := range []string{"other.example.com", "corp.example.com"} {
			if strings.Contains(rec.Body.String(), value) {
				t.Errorf("%s: the answer repeats the value %s", tt.name, value)
			}
		}
	}
	// The body is bounded.
	big := `{"deception_id": "directory-and-shares", "persona": {"Contact": "` + strings.Repeat("a", maxBodyBytes) + `"}}`
	if rec := f.serve(t, f.h.AddDeception, http.MethodPost, "/", id, big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("POST a body of %d bytes = %d, want 413", len(big), rec.Code)
	}
	// Nothing was stored by the refusals.
	var n int
	if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM scenario_deceptions`).Scan(&n); err != nil || n != 2 {
		t.Errorf("%d deceptions, %v; want the two that were applied", n, err)
	}
}

// The limits of a scenario answer 409, a value that makes a file reveal what
// it is 422, and a DNS honeytoken without a zone 422.
func TestAddDeception_AnswersTheLimitsAndTheConditionsOfTheInstallation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	full := f.create(t, `{"name": "full"}`)
	if _, err := f.owner.Exec(t.Context(), `
INSERT INTO scenario_deceptions (scenario_id, deception_id, language, guide)
SELECT $1, 'filler-' || n, 'en', 'g' FROM generate_series(1, 20) AS n`, full.ID); err != nil {
		t.Fatal(err)
	}
	if rec := f.serve(t, f.h.AddDeception, http.MethodPost, "/", full.ID, adcsCatalog); rec.Code != http.StatusConflict || errorCode(t, rec) != "scenario_limit" {
		t.Errorf("POST to a scenario with 20 deceptions = %d %s, want 409 scenario_limit", rec.Code, rec.Body)
	}
	crowded := f.create(t, `{"name": "crowded"}`)
	if _, err := f.owner.Exec(t.Context(), `
INSERT INTO artifacts (scenario_id, catalog_artifact, file_name, format, content)
SELECT $1, 'filler', 'f', 'text', '\x41' FROM generate_series(1, 200)`, crowded.ID); err != nil {
		t.Fatal(err)
	}
	if rec := f.serve(t, f.h.AddDeception, http.MethodPost, "/", crowded.ID, adcsCatalog); rec.Code != http.StatusConflict || errorCode(t, rec) != "scenario_limit" {
		t.Errorf("POST to a scenario with 200 artifacts = %d %s, want 409 scenario_limit", rec.Code, rec.Body)
	}

	byHand := f.create(t, `{"name": "s"}`)
	reveal := `{"deception_id": "remote-access", "persona": {"Domain": "decoy.example.com", "Account": "j.doe"}}`
	rec := f.serve(t, f.h.AddDeception, http.MethodPost, "/", byHand.ID, reveal)
	if rec.Code != http.StatusUnprocessableEntity || errorCode(t, rec) != "artifact_reveals_decoy" || strings.Contains(rec.Body.String(), "decoy.example.com") {
		t.Errorf("POST with a revealing value = %d %s, want 422 artifact_reveals_decoy without the value", rec.Code, rec.Body)
	}

	ownerURL, consoleURL := schematest.Console(t)
	nz := newFixture(t)
	nz.h = NewHandler(slog.New(slog.DiscardHandler), schematest.Open(t, consoleURL), testCatalog(t), triggerURL, nil)
	nz.owner = schematest.Open(t, ownerURL)
	if _, err := nz.owner.Exec(t.Context(), `INSERT INTO users (id, email, display_name, role, status, password_hash)
VALUES ($1, 'user@example.com', 'Test User', 'user', 'active', '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA')`, nz.principal.UserID); err != nil {
		t.Fatal(err)
	}
	sc := nz.create(t, `{"name": "s"}`)
	rec = nz.serve(t, nz.h.AddDeception, http.MethodPost, "/", sc.ID, `{"deception_id": "remote-access", "persona": {"Domain": "corp.example.com", "Account": "j.doe"}}`)
	if rec.Code != http.StatusUnprocessableEntity || errorCode(t, rec) != "dns_not_configured" {
		t.Errorf("POST without zones = %d %s, want 422 dns_not_configured", rec.Code, rec.Body)
	}
}

// An artifact is added with a honeytoken of the scenario, and it has the
// properties of one that applying a deception created: the format, the
// download, and no marker.
func TestAddArtifact_HasThePropertiesOfAnAppliedArtifact(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	applied := f.apply(t, "remote-access", sshConfig)
	id, jumpHost := applied.Scenario.ID, applied.Honeytokens[0]

	got := f.addArtifact(t, id, `{"catalog_artifact": "ssh-config", "bindings": {"JumpHost": "`+jumpHost.ID+`"}}`)
	art := got.Artifact
	if got.Scenario.ID != id || art.CatalogArtifact != "ssh-config" || art.ScenarioID == nil || *art.ScenarioID != id ||
		art.FileName != "config" || art.Format != applied.Artifacts[0].Format || art.MediaType != applied.Artifacts[0].MediaType ||
		art.Bindings["JumpHost"] != jumpHost.ID || art.Size == 0 {
		t.Errorf("artifact = %+v", art)
	}

	download := artifactapi.NewHandler(slog.New(slog.DiscardHandler), f.h.db)
	fetch := func(artifactID string) *recorded {
		rec := f.serve(t, download.Download, http.MethodGet, "/", artifactID, "")
		return &recorded{code: rec.Code, header: rec.Header(), body: rec.Body.String()}
	}
	old, added := fetch(applied.Artifacts[0].ID), fetch(art.ID)
	if added.code != http.StatusOK || added.code != old.code {
		t.Fatalf("download = %d, want %d", added.code, old.code)
	}
	for _, h := range []string{"Content-Type", "X-Content-Type-Options", "Cache-Control", "Content-Security-Policy"} {
		if added.header.Get(h) != old.header.Get(h) {
			t.Errorf("header %s = %q, want %q like the applied artifact", h, added.header.Get(h), old.header.Get(h))
		}
	}
	if d := added.header.Get("Content-Disposition"); !strings.HasPrefix(d, "attachment") || !strings.Contains(d, "config") {
		t.Errorf("Content-Disposition = %q, want an attachment named config", d)
	}
	catalogArtifact, ok := f.h.catalog.LookupArtifact("ssh-config")
	if !ok {
		t.Fatal("no artifact ssh-config")
	}
	if m := catalogArtifact.Reveals([]byte(added.body), "ssh-config"); m != "" {
		t.Errorf("the added file contains %q", m)
	}
	if !strings.Contains(added.body, jumpHost.TriggerNames[0]) || len(added.body) != art.Size {
		t.Errorf("file = %q, want the name %s and %d bytes", added.body, jumpHost.TriggerNames[0], art.Size)
	}
}

type recorded struct {
	code   int
	header http.Header
	body   string
}

func TestAddArtifact_RejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	applied := f.apply(t, "remote-access", sshConfig)
	id, jumpHost := applied.Scenario.ID, applied.Honeytokens[0].ID
	other := f.apply(t, "remote-access", sshConfig)
	foreign := other.Honeytokens[0].ID
	bind := func(slot, honeytoken string) string {
		return `{"catalog_artifact": "ssh-config", "bindings": {"` + slot + `": "` + honeytoken + `"}}`
	}

	var foreignMessage string
	for _, tt := range []struct {
		name, scenario, body string
		status               int
		code, message        string
	}{
		{"unknown scenario", "00000000-0000-4000-8000-000000000000", bind("JumpHost", jumpHost), http.StatusNotFound, "not_found", ""},
		{"identifier that is no uuid", "not-a-uuid", bind("JumpHost", jumpHost), http.StatusNotFound, "not_found", ""},
		{"unknown artifact", id, `{"catalog_artifact": "telnet"}`, http.StatusBadRequest, "invalid_request", "catalog_artifact must be an artifact of the catalog"},
		{"no artifact", id, `{}`, http.StatusBadRequest, "invalid_request", "catalog_artifact must be an artifact"},
		{"required slot left out", id, `{"catalog_artifact": "ssh-config"}`, http.StatusBadRequest, "invalid_request", "binding JumpHost: needs a honeytoken"},
		{"unknown slot", id, bind("Other", jumpHost), http.StatusBadRequest, "invalid_request", "binding Other: is not a slot"},
		{"honeytoken of another scenario", id, bind("JumpHost", foreign), http.StatusBadRequest, "invalid_request", "binding JumpHost: is not filled by a honeytoken of the scenario"},
		{"honeytoken that does not exist", id, bind("JumpHost", "00000000-0000-4000-8000-000000000000"), http.StatusBadRequest, "invalid_request", "binding JumpHost: is not filled by a honeytoken of the scenario"},
		{"identifier that is no uuid", id, bind("JumpHost", "not-a-uuid"), http.StatusBadRequest, "invalid_request", "binding JumpHost: is not filled by a honeytoken of the scenario"},
		{"another persona", id, `{"catalog_artifact": "ssh-config", "persona": {"Domain": "other.example.com"}, "bindings": {"JumpHost": "` + jumpHost + `"}}`, http.StatusConflict, "persona_conflict", "persona Domain"},
		{"unknown language", id, `{"catalog_artifact": "ssh-config", "language": "fr", "bindings": {"JumpHost": "` + jumpHost + `"}}`, http.StatusBadRequest, "invalid_request", "language must be one of en, de"},
		{"null bindings", id, `{"catalog_artifact": "ssh-config", "bindings": null}`, http.StatusBadRequest, "invalid_request", ""},
		{"unknown member", id, `{"catalog_artifact": "ssh-config", "artifacts": []}`, http.StatusBadRequest, "invalid_request", ""},
		{"trailing data", id, bind("JumpHost", jumpHost) + ` {}`, http.StatusBadRequest, "invalid_request", ""},
	} {
		rec := f.serve(t, f.h.AddArtifact, http.MethodPost, "/", tt.scenario, tt.body)
		if rec.Code != tt.status || errorCode(t, rec) != tt.code || !strings.Contains(rec.Body.String(), tt.message) {
			t.Errorf("%s: POST %s = %d %s, want %d %s with %q", tt.name, tt.body, rec.Code, rec.Body, tt.status, tt.code, tt.message)
		}
		if strings.Contains(rec.Body.String(), foreign) || strings.Contains(rec.Body.String(), "other.example.com") {
			t.Errorf("%s: the answer repeats the honeytoken of another scenario or a value of the persona: %s", tt.name, rec.Body)
		}
		if tt.name == "honeytoken of another scenario" {
			foreignMessage = rec.Body.String()
		}
		if tt.name == "honeytoken that does not exist" && rec.Body.String() != foreignMessage {
			t.Errorf("the answer for a honeytoken that does not exist differs from the one for a honeytoken of another scenario: %s and %s", rec.Body, foreignMessage)
		}
	}
	// The slot of the DNS role needs its zones.
	ownerURL, consoleURL := schematest.Console(t)
	nz := newFixture(t)
	nz.h = NewHandler(slog.New(slog.DiscardHandler), schematest.Open(t, consoleURL), testCatalog(t), triggerURL, nil)
	nz.owner = schematest.Open(t, ownerURL)
	if _, err := nz.owner.Exec(t.Context(), `INSERT INTO users (id, email, display_name, role, status, password_hash)
VALUES ($1, 'user@example.com', 'Test User', 'user', 'active', '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA')`, nz.principal.UserID); err != nil {
		t.Fatal(err)
	}
	sc := nz.create(t, `{"name": "s"}`)
	var dns string
	if err := nz.owner.QueryRow(t.Context(), `
INSERT INTO honeytokens (type, name, severity, trigger_value, scenario_id)
VALUES ('dns', 'h', 'medium', translate(substr(md5(random()::text), 1, 26), '0189', 'wxyz'), $1) RETURNING id`, sc.ID).Scan(&dns); err != nil {
		t.Fatal(err)
	}
	rec := nz.serve(t, nz.h.AddArtifact, http.MethodPost, "/", sc.ID,
		`{"catalog_artifact": "ssh-config", "persona": {"Domain": "corp.example.com", "Account": "j.doe"}, "bindings": {"JumpHost": "`+dns+`"}}`)
	if rec.Code != http.StatusUnprocessableEntity || errorCode(t, rec) != "dns_not_configured" {
		t.Errorf("POST without zones = %d %s, want 422 dns_not_configured", rec.Code, rec.Body)
	}
	// A value that makes the file reveal what it is.
	reveal := f.create(t, `{"name": "r"}`)
	portal := f.createHoneytoken(t, reveal.ID)
	rec = f.serve(t, f.h.AddArtifact, http.MethodPost, "/", reveal.ID,
		`{"catalog_artifact": "browser-bookmarks", "persona": {"Company": "Canary Ltd", "PortalName": "Intranet"}, "bindings": {"Portal": "`+portal+`"}}`)
	if rec.Code != http.StatusUnprocessableEntity || errorCode(t, rec) != "artifact_reveals_decoy" || strings.Contains(rec.Body.String(), "Canary") {
		t.Errorf("POST with a revealing value = %d %s, want 422 artifact_reveals_decoy without the value", rec.Code, rec.Body)
	}
	// The body is bounded.
	big := `{"catalog_artifact": "ssh-config", "persona": {"Domain": "` + strings.Repeat("a", maxBodyBytes) + `"}}`
	if rec := f.serve(t, f.h.AddArtifact, http.MethodPost, "/", id, big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("POST a body of %d bytes = %d, want 413", len(big), rec.Code)
	}
	var n int
	if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM artifacts WHERE scenario_id = $1`, id).Scan(&n); err != nil || n != len(applied.Artifacts) {
		t.Errorf("%d artifacts, %v; want the %d that were applied", n, err, len(applied.Artifacts))
	}
}

// What adding a deception or an artifact answers, and the guides of a scenario
// with two deceptions, match the schemas of the specification.
func TestAdd_MatchesTheSpecification(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	schemas, err := apispec.ParseSchemas(api.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
	applied := f.apply(t, "remote-access", sshConfig)
	id := applied.Scenario.ID

	deception := f.serve(t, f.h.AddDeception, http.MethodPost, "/", id, directoryAndShares)
	artifactBody := `{"catalog_artifact": "ssh-config", "bindings": {"JumpHost": "` + applied.Honeytokens[0].ID + `"}}`
	for _, b := range []struct {
		schema string
		body   []byte
	}{
		{"AppliedDeception", deception.Body.Bytes()},
		{"AddedArtifact", f.serve(t, f.h.AddArtifact, http.MethodPost, "/", id, artifactBody).Body.Bytes()},
		{"ScenarioGuides", f.serve(t, f.h.Guide, http.MethodGet, "/", id, "").Body.Bytes()},
		{"Scenario", f.serve(t, f.h.Get, http.MethodGet, "/", id, "").Body.Bytes()},
		{"ScenarioPage", f.serve(t, f.h.List, http.MethodGet, "/api/v1/scenarios", "", "").Body.Bytes()},
	} {
		if deception.Code != http.StatusCreated {
			t.Fatalf("adding a deception = %d %s", deception.Code, deception.Body)
		}
		for _, p := range schemas.Check(b.schema, b.body) {
			t.Errorf("%s: %s", b.schema, p)
		}
	}
}
