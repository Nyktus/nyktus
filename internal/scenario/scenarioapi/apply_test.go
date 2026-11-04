// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenarioapi

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/platform/apispec"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/user"
)

func (f fixture) apply(t *testing.T, deception, body string) applyResponse {
	t.Helper()
	rec := f.serve(t, f.h.Apply, http.MethodPost, "/api/v1/catalog/deceptions/"+deception+"/apply", deception, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST apply %s: %d %s", deception, rec.Code, rec.Body)
	}
	return decode[applyResponse](t, rec)
}

func (f fixture) count(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM `+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Applying a deception answers with the scenario that holds its identifier and
// creates nothing else, unless the request asks for the resources.
func TestApply_ReturnsTheScenarioAndCreatesNoResourcesUnlessAsked(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	for _, body := range []string{`{"name": "Jump server"}`, `{"name": "Jump server", "create_resources": false}`} {
		got := f.apply(t, "remote-access", body)
		sc := got.Scenario
		if sc.Name != "Jump server" || len(sc.Deceptions) != 1 || sc.Deceptions[0].DeceptionID != "remote-access" ||
			!slices.Contains(sc.EngageActivities, "EAC0005") {
			t.Errorf("scenario = %+v", sc)
		}
		if got.Honeytokens == nil || len(got.Honeytokens) != 0 || got.Honeypots == nil || len(got.Honeypots) != 0 {
			t.Errorf("%s: honeytokens %v and honeypots %v, want empty lists", body, got.Honeytokens, got.Honeypots)
		}
	}
	if n, p := f.count(t, "honeytokens"), f.count(t, "honeypots"); n != 0 || p != 0 {
		t.Errorf("%d honeytokens and %d honeypots, want none", n, p)
	}
}

// With the resources, the response lists what was created in the scenario: the
// honeytokens with their names under every zone and the honeypots without
// their secret, which its own route returns.
func TestApply_CreatesTheResourcesWhenAsked(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	rec := f.serve(t, f.h.Apply, http.MethodPost, "/api/v1/catalog/deceptions/probe/apply", "probe",
		`{"name": "Jump server", "language": "de", "create_resources": true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	got := decode[applyResponse](t, rec)
	sc := got.Scenario
	if len(got.Honeytokens) != 2 || len(got.Honeypots) != 2 {
		t.Fatalf("created %d honeytokens and %d honeypots, want 2 and 2", len(got.Honeytokens), len(got.Honeypots))
	}
	for _, h := range got.Honeytokens {
		if h.ScenarioID == nil || *h.ScenarioID != sc.ID {
			t.Errorf("honeytoken = %+v, want one in the scenario", h)
		}
	}
	if h := got.Honeytokens[0]; h.Name != "Zugang" || len(h.TriggerNames) != 2 || h.TriggerNames[0] != h.TriggerValue+"."+dnsZone {
		t.Errorf("DNS honeytoken = %+v, want the name of the label and a name under each zone", h)
	}
	if p := got.Honeypots[0]; p.ScenarioID == nil || *p.ScenarioID != sc.ID || p.Name != "Sprungserver" || p.Service != "ssh" || !p.Enabled {
		t.Errorf("honeypot = %+v", p)
	}
	if strings.Contains(rec.Body.String(), "secret") || strings.Contains(rec.Body.String(), "sensor_config") {
		t.Errorf("the response mentions a secret: %s", rec.Body)
	}
	// Without a language, the names are English.
	en := f.apply(t, "probe", `{"name": "s", "create_resources": true}`)
	if en.Honeytokens[0].Name != "Gateway" || en.Honeypots[1].Name != "Database" {
		t.Errorf("names without a language = %q and %q, want English", en.Honeytokens[0].Name, en.Honeypots[1].Name)
	}
}

func TestApply_RejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	for _, body := range []string{
		`{}`,
		`{"name": ""}`,
		`{"name": " a"}`,
		`{"name": "` + strings.Repeat("x", 101) + `"}`,
		`{"name": "a", "notes": null}`,
		`{"name": "a", "notes": "\u0000"}`,
		`{"name": "a", "language": null}`,
		`{"name": "a", "language": "fr"}`,
		`{"name": "a", "language": "DE"}`,
		`{"name": "a", "create_resources": null}`,
		`{"name": "a", "create_resources": "yes"}`,
		// A member that the request does not have is rejected.
		`{"name": "a", "persona": {}}`,
		`{"name": "a", "artifacts": []}`,
		`{"name": "a"} {}`,
		`not json`,
	} {
		rec := f.serve(t, f.h.Apply, http.MethodPost, "/api/v1/catalog/deceptions/remote-access/apply", "remote-access", body)
		if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
			t.Errorf("POST %s = %d %s, want 400 invalid_request", body, rec.Code, rec.Body)
		}
	}
	for _, id := range []string{"nothing", "not a deception"} {
		if rec := f.serve(t, f.h.Apply, http.MethodPost, "/", id, `{"name": "a"}`); rec.Code != http.StatusNotFound {
			t.Errorf("POST apply %s = %d, want 404", id, rec.Code)
		}
	}
	if n := f.count(t, "scenarios"); n != 0 {
		t.Errorf("%d scenarios, want none", n)
	}
}

// A DNS honeytoken needs the zones of the DNS role when it is to be created,
// not before: the deception joins a scenario without them.
func TestApply_DNSHoneytokenNeedsZonesWhenTheResourcesAreCreated(t *testing.T) {
	t.Parallel()
	f := newFixtureWith(t, nil, user.RoleUser)

	rec := f.serve(t, f.h.Apply, http.MethodPost, "/", "probe", `{"name": "a", "create_resources": true}`)
	if rec.Code != http.StatusUnprocessableEntity || errorCode(t, rec) != "dns_not_configured" {
		t.Errorf("POST apply with the resources = %d %s, want 422 dns_not_configured", rec.Code, rec.Body)
	}
	if n := f.count(t, "scenarios"); n != 0 {
		t.Errorf("%d scenarios, want none", n)
	}
	if got := f.apply(t, "probe", `{"name": "a"}`); len(got.Scenario.Deceptions) != 1 {
		t.Errorf("scenario without the resources = %+v, want the deception", got.Scenario)
	}
	// A deception without a DNS honeytoken needs no zone for its resources.
	if got := f.apply(t, "word-image", `{"name": "w", "create_resources": true}`); len(got.Honeytokens) != 1 {
		t.Errorf("honeytokens of word-image = %+v, want one", got.Honeytokens)
	}
}

// Creating the resources of a deception needs the permissions of both
// resources, whatever the deception asks for. The request is refused before
// anything is loaded, so that it reveals nothing, and the denial is recorded.
func TestApply_CreatingTheResourcesNeedsThePermissionsOfBoth(t *testing.T) {
	t.Parallel()
	f := newFixtureWith(t, []string{dnsZone}, user.RoleViewer)

	for _, deception := range []string{"word-image", "remote-access", "nothing"} {
		rec := f.serve(t, f.h.Apply, http.MethodPost, "/", deception, `{"name": "a", "create_resources": true}`)
		if rec.Code != http.StatusForbidden || errorCode(t, rec) != "forbidden" {
			t.Errorf("apply %s as a viewer = %d %s, want 403", deception, rec.Code, rec.Body)
		}
	}
	rec := f.serve(t, f.h.AddDeception, http.MethodPost, "/", "00000000-0000-4000-8000-000000000000",
		`{"deception_id": "nothing", "create_resources": true}`)
	if rec.Code != http.StatusForbidden {
		t.Errorf("add as a viewer to an unknown scenario with an unknown deception = %d %s, want 403", rec.Code, rec.Body)
	}
	for _, table := range []string{"scenarios", "honeytokens", "honeypots"} {
		if n := f.count(t, table); n != 0 {
			t.Errorf("%d rows in %s, want none", n, table)
		}
	}
	if n := f.count(t, `audit_entries WHERE action = 'honeytokens.write' AND outcome = 'denied'`); n == 0 {
		t.Error("no denied creation is recorded in the audit log")
	}
	// The request without the resources is the business of the route, which
	// the authorizer decides before the handler runs: the handler accepts it.
	if rec := f.serve(t, f.h.Apply, http.MethodPost, "/", "remote-access", `{"name": "a"}`); rec.Code != http.StatusCreated {
		t.Errorf("apply without the resources = %d %s, want 201", rec.Code, rec.Body)
	}
}

func (f fixture) addDeception(t *testing.T, scenarioID, body string) applyResponse {
	t.Helper()
	rec := f.serve(t, f.h.AddDeception, http.MethodPost, "/", scenarioID, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST %s: %d %s", body, rec.Code, rec.Body)
	}
	return decode[applyResponse](t, rec)
}

func TestAddDeception_ReturnsTheScenarioAfterTheChange(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	sc := f.create(t, `{"name": "s", "engage_activities": ["EAC0012"]}`)

	got := f.addDeception(t, sc.ID, `{"deception_id": "probe", "create_resources": true}`)
	if len(got.Scenario.Deceptions) != 1 || got.Scenario.Deceptions[0].DeceptionID != "probe" ||
		!slices.Equal(got.Scenario.EngageActivities, []string{"EAC0012", "EAC0005", "EAC0011"}) {
		t.Errorf("scenario = %+v", got.Scenario)
	}
	if len(got.Honeytokens) != 2 || len(got.Honeypots) != 2 {
		t.Errorf("created %d honeytokens and %d honeypots, want 2 and 2", len(got.Honeytokens), len(got.Honeypots))
	}
	if again := f.addDeception(t, sc.ID, `{"deception_id": "remote-access"}`); len(again.Scenario.Deceptions) != 2 || len(again.Honeytokens) != 0 {
		t.Errorf("adding without the resources = %+v", again)
	}
}

func TestAddDeception_RejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	sc := f.create(t, `{"name": "s"}`)

	for _, body := range []string{
		`{}`,
		`{"deception_id": ""}`,
		`{"deception_id": "nothing"}`,
		`{"deception_id": "Probe"}`,
		`{"deception_id": null}`,
		`{"deception_id": "probe", "language": "fr"}`,
		`{"deception_id": "probe", "language": null}`,
		`{"deception_id": "probe", "create_resources": null}`,
		`{"deception_id": "probe", "create_resources": 1}`,
		`{"deception_id": "probe", "persona": {}}`,
		`{"deception_id": "probe", "artifacts": []}`,
		`{"catalog_artifact": "probe"}`,
	} {
		rec := f.serve(t, f.h.AddDeception, http.MethodPost, "/", sc.ID, body)
		if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
			t.Errorf("POST %s = %d %s, want 400 invalid_request", body, rec.Code, rec.Body)
		}
	}
	if n := f.count(t, "scenario_deceptions"); n != 0 {
		t.Errorf("%d deceptions, want none", n)
	}
}

func TestAddDeception_AnswersTheConditionsOfTheScenarioAndTheInstallation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	sc := f.create(t, `{"name": "s"}`)
	f.addDeception(t, sc.ID, `{"deception_id": "probe", "create_resources": true}`)

	rec := f.serve(t, f.h.AddDeception, http.MethodPost, "/", sc.ID, `{"deception_id": "probe", "create_resources": true}`)
	if rec.Code != http.StatusConflict || errorCode(t, rec) != "deception_already_added" {
		t.Errorf("a repeat = %d %s, want 409 deception_already_added", rec.Code, rec.Body)
	}
	if n := f.count(t, "honeytokens"); n != 2 {
		t.Errorf("%d honeytokens after a repeat, want the 2 of the first", n)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if rec := f.serve(t, f.h.AddDeception, http.MethodPost, "/", id, `{"deception_id": "probe"}`); rec.Code != http.StatusNotFound {
			t.Errorf("POST to %s = %d %s, want 404", id, rec.Code, rec.Body)
		}
	}
	// Without zones, a DNS honeytoken cannot be created.
	g := newFixtureWith(t, nil, user.RoleUser)
	other := g.create(t, `{"name": "o"}`)
	rec = g.serve(t, g.h.AddDeception, http.MethodPost, "/", other.ID, `{"deception_id": "probe", "create_resources": true}`)
	if rec.Code != http.StatusUnprocessableEntity || errorCode(t, rec) != "dns_not_configured" {
		t.Errorf("POST without zones = %d %s, want 422 dns_not_configured", rec.Code, rec.Body)
	}
}

func (f fixture) removeDeception(t *testing.T, scenarioID, deceptionID string) *httptest.ResponseRecorder {
	t.Helper()
	return f.serve(t, f.h.RemoveDeception, http.MethodDelete, "/", scenarioID, "", "deception_id", deceptionID)
}

func TestRemoveDeception_EndsTheAssignmentOnly(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	sc := f.create(t, `{"name": "s"}`)
	f.addDeception(t, sc.ID, `{"deception_id": "probe", "create_resources": true}`)
	f.addDeception(t, sc.ID, `{"deception_id": "remote-access"}`)

	rec := f.removeDeception(t, sc.ID, "probe")
	got := decode[response](t, rec)
	if rec.Code != http.StatusOK || len(got.Deceptions) != 1 || got.Deceptions[0].DeceptionID != "remote-access" {
		t.Errorf("DELETE = %d %s, want the scenario with remote-access only", rec.Code, rec.Body)
	}
	if n, p := f.count(t, "honeytokens"), f.count(t, "honeypots"); n != 2 || p != 2 {
		t.Errorf("%d honeytokens and %d honeypots, want the 4 that were created to stay", n, p)
	}
	for name, tt := range map[string]struct{ scenario, deception string }{
		"deception that is not part": {sc.ID, "probe"},
		"deception of the catalog":   {sc.ID, "word-image"},
		"unknown deception":          {sc.ID, "nothing"},
		"unknown scenario":           {"00000000-0000-4000-8000-000000000000", "remote-access"},
		"malformed scenario":         {"not-a-uuid", "remote-access"},
	} {
		if rec := f.removeDeception(t, tt.scenario, tt.deception); rec.Code != http.StatusNotFound {
			t.Errorf("%s: DELETE = %d %s, want 404", name, rec.Code, rec.Body)
		}
	}
}

// Every kind of answer matches the schema of the specification.
func TestApplyAndAdd_MatchTheSpecification(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	schemas, err := apispec.ParseSchemas(api.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
	sc := f.create(t, `{"name": "s"}`)

	for _, b := range []struct {
		name   string
		schema string
		rec    func() *httptest.ResponseRecorder
	}{
		{"apply", "AppliedDeception", func() *httptest.ResponseRecorder {
			return f.serve(t, f.h.Apply, http.MethodPost, "/", "remote-access", `{"name": "a"}`)
		}},
		{"apply with the resources", "AppliedDeception", func() *httptest.ResponseRecorder {
			return f.serve(t, f.h.Apply, http.MethodPost, "/", "probe", `{"name": "b", "create_resources": true}`)
		}},
		{"add", "AppliedDeception", func() *httptest.ResponseRecorder {
			return f.serve(t, f.h.AddDeception, http.MethodPost, "/", sc.ID, `{"deception_id": "probe", "create_resources": true}`)
		}},
		{"remove", "Scenario", func() *httptest.ResponseRecorder { return f.removeDeception(t, sc.ID, "probe") }},
	} {
		rec := b.rec()
		if rec.Code >= 300 {
			t.Fatalf("%s: status %d %s", b.name, rec.Code, rec.Body)
		}
		for _, p := range schemas.Check(b.schema, rec.Body.Bytes()) {
			t.Errorf("%s: %s", b.name, p)
		}
	}
}

// The handler needs the keys that seal the secrets of the honeypots it creates.
func TestNewHandler_PanicsWithoutWhatItNeeds(t *testing.T) {
	t.Parallel()
	_, consoleURL := schematest.Console(t)
	db := schematest.Open(t, consoleURL)
	c := testCatalog(t)

	defer func() {
		if recover() == nil {
			t.Error("NewHandler without keys did not panic")
		}
	}()
	NewHandler(slog.New(slog.DiscardHandler), db, c, triggerURL, nil, nil)
}
