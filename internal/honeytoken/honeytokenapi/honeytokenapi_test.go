// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeytokenapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/platform/apispec"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/user"
)

const triggerURL = "https://t.example.com"

var dnsZones = []string{"d.example.com", "e.example.org"}

type fixture struct {
	h         *Handler
	owner     *pgxpool.Pool
	principal access.Principal
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	return newFixtureWithZones(t, dnsZones)
}

func newFixtureWithZones(t *testing.T, zones []string) fixture {
	t.Helper()
	ownerURL, consoleURL := schematest.Console(t)
	owner := schematest.Open(t, ownerURL)
	var id string
	err := owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, password_hash)
VALUES ('user@example.com', 'Test User', 'user', 'active', '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA')
RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{
		h:         NewHandler(slog.New(slog.DiscardHandler), schematest.Open(t, consoleURL), triggerURL, zones),
		owner:     owner,
		principal: access.Principal{UserID: id, Role: user.RoleUser, Method: audit.AuthSession, SessionID: "s1"},
	}
}

// serve calls handler as the router would, with the principal and the path
// value of the route.
func (f fixture) serve(t *testing.T, handler http.HandlerFunc, method, target, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(access.WithPrincipal(t.Context(), f.principal), method, target, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if id != "" {
		req.SetPathValue("id", id)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %s: %v", rec.Body, err)
	}
	return v
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	return decode[struct {
		Error struct{ Code string } `json:"error"`
	}](t, rec).Error.Code
}

func (f fixture) create(t *testing.T, body string) response {
	t.Helper()
	rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeytokens", "", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST %s: %d %s", body, rec.Code, rec.Body)
	}
	return decode[response](t, rec)
}

func TestCreate_ReturnsTheHoneytokenWithItsTriggerURL(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	got := f.create(t, `{"type": "web_url", "name": "Wiki link", "notes": "page Finance",
		"redirect_url": "https://wiki.example.com/finance", "techniques": ["T1213"]}`)
	if got.Type != "web_url" || got.Name != "Wiki link" || got.Notes != "page Finance" || !got.Enabled ||
		got.RedirectURL == nil || *got.RedirectURL != "https://wiki.example.com/finance" || !slices.Equal(got.Techniques, []string{"T1213"}) {
		t.Errorf("POST = %+v", got)
	}
	if got.TriggerURL == nil || *got.TriggerURL != triggerURL+"/"+got.TriggerValue || len(got.TriggerValue) != 26 {
		t.Errorf("trigger_url = %v, trigger_value = %q; want the address of the trigger and the value", got.TriggerURL, got.TriggerValue)
	}
	if got.TriggerNames == nil || len(got.TriggerNames) != 0 {
		t.Errorf("trigger_names = %#v, want an empty list for a URL", got.TriggerNames)
	}

	// Without the optional members, a honeytoken is enabled and has no notes,
	// redirect or techniques; the lists are empty, never null.
	rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeytokens", "", `{"type": "web_image", "name": "Pixel"}`)
	raw := decode[map[string]any](t, rec)
	if rec.Code != http.StatusCreated || raw["enabled"] != true || raw["notes"] != "" || raw["redirect_url"] != nil ||
		raw["techniques"] == nil || len(raw["techniques"].([]any)) != 0 || raw["severity"] != "low" {
		t.Errorf("POST minimal = %d %s", rec.Code, rec.Body)
	}
	if want := triggerURL + "/" + raw["trigger_value"].(string) + ".gif"; raw["trigger_url"] != want {
		t.Errorf("trigger_url of an image = %v, want %q", raw["trigger_url"], want)
	}
	if got := f.create(t, `{"type": "web_url", "name": "Off", "enabled": false}`); got.Enabled || got.Severity != "medium" {
		t.Errorf("POST with enabled false = %+v, want a disabled honeytoken with the default severity medium", got)
	}
	if got := f.create(t, `{"type": "web_image", "name": "Severe", "severity": "critical"}`); got.Severity != "critical" {
		t.Errorf("POST with severity critical = %+v", got)
	}
}

func TestCreate_RejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	for _, body := range []string{
		`{"name": "a"}`,
		`{"type": "dns", "name": "a", "redirect_url": "https://example.com"}`,
		`{"type": "qr_code", "name": "a"}`,
		`{"type": "web_url"}`,
		`{"type": "web_url", "name": null}`,
		`{"type": "web_url", "name": " a"}`,
		`{"type": "web_url", "name": "a", "notes": "\u0000"}`,
		`{"type": "web_url", "name": "a", "redirect_url": ""}`,
		`{"type": "web_url", "name": "a", "redirect_url": "https://192.168.0.1/"}`,
		`{"type": "web_image", "name": "a", "redirect_url": "https://example.com"}`,
		`{"type": "web_url", "name": "a", "techniques": ["T9999"]}`,
		`{"type": "web_url", "name": "a", "techniques": ["T1078", "T1078"]}`,
		`{"type": "web_url", "name": "a", "trigger_value": "aaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
		`{"type": "web_url", "name": "a", "enabled": "yes"}`,
		`{"type": "web_url", "name": "a", "enabled": null}`,
		`{"type": "web_url", "name": "a", "notes": null}`,
		`{"type": "web_url", "name": "a", "redirect_url": null}`,
		`{"type": "web_url", "name": "a", "techniques": null}`,
		`{"type": "web_url", "name": "a", "severity": null}`,
	} {
		rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeytokens", "", body)
		if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
			t.Errorf("POST %s: %d %s, want 400 invalid_request", body, rec.Code, rec.Body)
		}
	}
	// An empty severity is not the default of the type, and info is only an
	// analyst's judgment of an incident.
	for _, body := range []string{
		`{"type": "web_url", "name": "a", "severity": ""}`,
		`{"type": "web_url", "name": "a", "severity": "info"}`,
		`{"type": "web_url", "name": "a", "severity": "urgent"}`,
	} {
		rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeytokens", "", body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "severity must be") {
			t.Errorf("POST %s: %d %s, want 400 naming the rule of the severity", body, rec.Code, rec.Body)
		}
	}
	var n int
	if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM honeytokens`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d honeytokens, %v; want none", n, err)
	}
}

func TestGet(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	created := f.create(t, `{"type": "web_url", "name": "a"}`)

	rec := f.serve(t, f.h.Get, http.MethodGet, "/api/v1/honeytokens/"+created.ID, created.ID, "")
	if got := decode[response](t, rec); rec.Code != http.StatusOK || got.ID != created.ID || *got.TriggerURL != *created.TriggerURL {
		t.Errorf("GET = %d %s", rec.Code, rec.Body)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if rec := f.serve(t, f.h.Get, http.MethodGet, "/api/v1/honeytokens/"+id, id, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", id, rec.Code)
		}
	}
}

func TestList_PagesAndFilters(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	url := f.create(t, `{"type": "web_url", "name": "u"}`)
	image := f.create(t, `{"type": "web_image", "name": "i", "enabled": false}`)

	list := func(query string) (listResponse, int) {
		rec := f.serve(t, f.h.List, http.MethodGet, "/api/v1/honeytokens?"+query, "", "")
		if rec.Code != http.StatusOK {
			return listResponse{}, rec.Code
		}
		return decode[listResponse](t, rec), rec.Code
	}
	ids := func(l listResponse) []string {
		var ids []string
		for _, h := range l.Honeytokens {
			ids = append(ids, h.ID)
		}
		return ids
	}

	page, _ := list("limit=1")
	if !slices.Equal(ids(page), []string{image.ID}) || page.NextCursor == "" {
		t.Errorf("first page = %v, cursor %q", ids(page), page.NextCursor)
	}
	if next, _ := list("limit=1&cursor=" + page.NextCursor); !slices.Equal(ids(next), []string{url.ID}) || next.NextCursor != "" {
		t.Errorf("second page = %v, cursor %q", ids(next), next.NextCursor)
	}
	for query, want := range map[string][]string{
		"":                           {image.ID, url.ID},
		"type=web_url":               {url.ID},
		"type=web_image":             {image.ID},
		"enabled=true":               {url.ID},
		"enabled=false":              {image.ID},
		"type=web_url&enabled=false": nil,
	} {
		if got, code := list(query); code != http.StatusOK || !slices.Equal(ids(got), want) {
			t.Errorf("GET ?%s = %d %v, want %v", query, code, ids(got), want)
		}
	}
	if got, _ := list("type=web_image"); got.Honeytokens == nil {
		t.Error("an empty list is null, want []")
	}
	if got, code := list("type=dns"); code != http.StatusOK || len(got.Honeytokens) != 0 {
		t.Errorf("GET ?type=dns = %d %v, want an empty list", code, ids(got))
	}
	for _, query := range []string{"type=txt", "type=", "enabled=yes", "enabled=1", "type=web_url&type=web_image", "name=u", "limit=201"} {
		if _, code := list(query); code != http.StatusBadRequest {
			t.Errorf("GET ?%s = %d, want 400", query, code)
		}
	}
}

func TestUpdate(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h := f.create(t, `{"type": "web_url", "name": "a", "redirect_url": "https://example.com", "techniques": ["T1078"]}`)
	patch := func(body string) *httptest.ResponseRecorder {
		return f.serve(t, f.h.Update, http.MethodPatch, "/api/v1/honeytokens/"+h.ID, h.ID, body)
	}

	rec := patch(`{"name": "b", "notes": "n", "enabled": false, "techniques": []}`)
	got := decode[response](t, rec)
	if rec.Code != http.StatusOK || got.Name != "b" || got.Notes != "n" || got.Enabled || len(got.Techniques) != 0 ||
		got.RedirectURL == nil || got.TriggerValue != h.TriggerValue {
		t.Errorf("PATCH = %d %s", rec.Code, rec.Body)
	}
	// null removes the redirect.
	if rec := patch(`{"redirect_url": null}`); rec.Code != http.StatusOK || decode[response](t, rec).RedirectURL != nil {
		t.Errorf("PATCH redirect_url null = %d %s, want the redirect removed", rec.Code, rec.Body)
	}
	if rec := patch(`{"redirect_url": "https://other.example.com"}`); rec.Code != http.StatusOK {
		t.Errorf("PATCH redirect_url = %d %s", rec.Code, rec.Body)
	}
	if rec := patch(`{"severity": "high"}`); rec.Code != http.StatusOK || decode[response](t, rec).Severity != "high" {
		t.Errorf("PATCH severity = %d %s, want severity high", rec.Code, rec.Body)
	}
	for _, body := range []string{`{"severity": ""}`, `{"severity": "info"}`} {
		if rec := patch(body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "severity must be") {
			t.Errorf("PATCH %s = %d %s, want 400 naming the rule of the severity", body, rec.Code, rec.Body)
		}
	}

	for _, body := range []string{
		`{}`,
		`{"name": null}`,
		`{"enabled": null}`,
		`{"techniques": null}`,
		`{"notes": null}`,
		`{"severity": null}`,
		`{"redirect_url": ""}`,
		`{"redirect_url": "https://10.0.0.1"}`,
		`{"type": "web_image"}`,
		`{"trigger_value": "aaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
		`{"name": ""}`,
		`{"techniques": ["T1086"]}`,
	} {
		if rec := patch(body); rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
			t.Errorf("PATCH %s = %d %s, want 400 invalid_request", body, rec.Code, rec.Body)
		}
	}

	image := f.create(t, `{"type": "web_image", "name": "i"}`)
	rec = f.serve(t, f.h.Update, http.MethodPatch, "/", image.ID, `{"redirect_url": "https://example.com"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "web_url") {
		t.Errorf("PATCH redirect of an image = %d %s, want 400", rec.Code, rec.Body)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if rec := f.serve(t, f.h.Update, http.MethodPatch, "/", id, `{"name": "x"}`); rec.Code != http.StatusNotFound {
			t.Errorf("PATCH %s = %d, want 404", id, rec.Code)
		}
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h := f.create(t, `{"type": "web_url", "name": "a"}`)

	if rec := f.serve(t, f.h.Delete, http.MethodDelete, "/", h.ID, ""); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Errorf("DELETE = %d %s, want 204", rec.Code, rec.Body)
	}
	for _, id := range []string{h.ID, "not-a-uuid"} {
		if rec := f.serve(t, f.h.Delete, http.MethodDelete, "/", id, ""); rec.Code != http.StatusNotFound {
			t.Errorf("DELETE %s = %d, want 404", id, rec.Code)
		}
	}
}

// createScenario inserts a scenario as the owner.
func (f fixture) createScenario(t *testing.T) string {
	t.Helper()
	var id string
	if err := f.owner.QueryRow(t.Context(), `INSERT INTO scenarios (name) VALUES ('s') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// Every kind of response matches the schema of the specification: alone and
// in a scenario, of every type, in a list and after a change of its scenario.
func TestResponses_MatchTheSpecification(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	schemas, err := apispec.ParseSchemas(api.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
	sc := f.createScenario(t)

	var bodies []struct {
		schema string
		rec    *httptest.ResponseRecorder
	}
	add := func(schema string, rec *httptest.ResponseRecorder) {
		bodies = append(bodies, struct {
			schema string
			rec    *httptest.ResponseRecorder
		}{schema, rec})
	}
	for _, body := range []string{
		`{"type": "web_url", "name": "a", "redirect_url": "https://example.com", "techniques": ["T1078"]}`,
		`{"type": "web_image", "name": "b"}`,
		`{"type": "dns", "name": "c"}`,
	} {
		add("Honeytoken", f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeytokens", "", body))
	}
	h := f.create(t, `{"type": "web_url", "name": "d"}`)
	add("Honeytoken", f.serve(t, f.h.AssignScenario, http.MethodPut, "/", h.ID, `{"scenario_id": "`+sc+`"}`))
	add("Honeytoken", f.serve(t, f.h.Get, http.MethodGet, "/", h.ID, ""))
	add("HoneytokenPage", f.serve(t, f.h.List, http.MethodGet, "/api/v1/honeytokens?limit=2", "", ""))
	add("HoneytokenPage", f.serve(t, f.h.List, http.MethodGet, "/api/v1/honeytokens?scenario_id="+sc, "", ""))
	add("Honeytoken", f.serve(t, f.h.DetachScenario, http.MethodDelete, "/", h.ID, ""))

	for _, b := range bodies {
		if b.rec.Code >= 300 {
			t.Fatalf("%s: status %d %s", b.schema, b.rec.Code, b.rec.Body)
		}
		for _, p := range schemas.Check(b.schema, b.rec.Body.Bytes()) {
			t.Error(p)
		}
	}
}

// A honeytoken joins a scenario through its own operation, which answers with
// the honeytoken, and leaves it through another one; the list of a scenario
// holds its honeytokens.
func TestScenario_AssignAndDetach(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	sc, other := f.createScenario(t), f.createScenario(t)
	h := f.create(t, `{"type": "web_url", "name": "a"}`)
	f.create(t, `{"type": "web_url", "name": "alone"}`)
	if h.ScenarioID != nil {
		t.Fatalf("POST scenario_id = %v, want null", *h.ScenarioID)
	}

	rec := f.serve(t, f.h.AssignScenario, http.MethodPut, "/", h.ID, `{"scenario_id": "`+sc+`"}`)
	if got := decode[response](t, rec); rec.Code != http.StatusOK || got.ScenarioID == nil || *got.ScenarioID != sc {
		t.Fatalf("PUT = %d %s, want the honeytoken in the scenario", rec.Code, rec.Body)
	}
	if rec := f.serve(t, f.h.AssignScenario, http.MethodPut, "/", h.ID, `{"scenario_id": "`+sc+`"}`); rec.Code != http.StatusOK {
		t.Errorf("PUT again = %d %s, want 200", rec.Code, rec.Body)
	}
	page := decode[listResponse](t, f.serve(t, f.h.List, http.MethodGet, "/api/v1/honeytokens?scenario_id="+sc, "", ""))
	if len(page.Honeytokens) != 1 || page.Honeytokens[0].ID != h.ID {
		t.Errorf("GET ?scenario_id = %+v, want only the honeytoken of the scenario", page.Honeytokens)
	}

	rec = f.serve(t, f.h.AssignScenario, http.MethodPut, "/", h.ID, `{"scenario_id": "`+other+`"}`)
	if rec.Code != http.StatusConflict || errorCode(t, rec) != codeInScenario {
		t.Errorf("PUT other scenario = %d %s, want 409 %s", rec.Code, rec.Body, codeInScenario)
	}

	rec = f.serve(t, f.h.DetachScenario, http.MethodDelete, "/", h.ID, "")
	if got := decode[response](t, rec); rec.Code != http.StatusOK || got.ScenarioID != nil {
		t.Errorf("DELETE = %d %s, want the honeytoken alone", rec.Code, rec.Body)
	}
	if rec := f.serve(t, f.h.DetachScenario, http.MethodDelete, "/", h.ID, ""); rec.Code != http.StatusOK {
		t.Errorf("DELETE again = %d %s, want 200", rec.Code, rec.Body)
	}
	if rec := f.serve(t, f.h.AssignScenario, http.MethodPut, "/", h.ID, `{"scenario_id": "`+other+`"}`); rec.Code != http.StatusOK {
		t.Errorf("PUT other scenario after leaving = %d %s, want 200", rec.Code, rec.Body)
	}
}

func TestScenario_RejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	sc := f.createScenario(t)
	h := f.create(t, `{"type": "web_url", "name": "a"}`)
	const missing = "00000000-0000-4000-8000-000000000000"

	for _, tt := range []struct {
		name, id, body string
		status         int
		code           string
	}{
		{"unknown scenario", h.ID, `{"scenario_id": "` + missing + `"}`, http.StatusUnprocessableEntity, codeScenarioNotFound},
		{"scenario in upper case", h.ID, `{"scenario_id": "` + strings.ToUpper(sc) + `"}`, http.StatusBadRequest, "invalid_request"},
		{"no scenario", h.ID, `{}`, http.StatusBadRequest, "invalid_request"},
		{"null scenario", h.ID, `{"scenario_id": null}`, http.StatusBadRequest, "invalid_request"},
		{"unknown member", h.ID, `{"scenario_id": "` + sc + `", "name": "x"}`, http.StatusBadRequest, "invalid_request"},
		{"unknown honeytoken", missing, `{"scenario_id": "` + sc + `"}`, http.StatusNotFound, "not_found"},
		{"malformed honeytoken", "not-a-uuid", `{"scenario_id": "` + sc + `"}`, http.StatusNotFound, "not_found"},
	} {
		rec := f.serve(t, f.h.AssignScenario, http.MethodPut, "/", tt.id, tt.body)
		if rec.Code != tt.status || errorCode(t, rec) != tt.code {
			t.Errorf("%s: PUT = %d %s, want %d %s", tt.name, rec.Code, rec.Body, tt.status, tt.code)
		}
	}
	for _, id := range []string{missing, "not-a-uuid"} {
		if rec := f.serve(t, f.h.DetachScenario, http.MethodDelete, "/", id, ""); rec.Code != http.StatusNotFound {
			t.Errorf("DELETE %s = %d, want 404", id, rec.Code)
		}
	}
	if rec := f.serve(t, f.h.List, http.MethodGet, "/api/v1/honeytokens?scenario_id=x", "", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("GET ?scenario_id=x = %d, want 400", rec.Code)
	}
}

// A DNS honeytoken has a name under every zone of the DNS role instead of a
// URL, in the order of the zones.
func TestCreate_DNSHoneytokenHasANameUnderEveryZone(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeytokens", "", `{"type": "dns", "name": "Jump host"}`)
	raw := decode[map[string]any](t, rec)
	if rec.Code != http.StatusCreated || raw["type"] != "dns" {
		t.Fatalf("POST = %d %s", rec.Code, rec.Body)
	}
	if v, ok := raw["trigger_url"]; !ok || v != nil {
		t.Errorf("trigger_url = %v (present %v), want null", v, ok)
	}
	value := raw["trigger_value"].(string)
	want := []any{value + ".d.example.com", value + ".e.example.org"}
	if got, _ := raw["trigger_names"].([]any); !slices.Equal(got, want) {
		t.Errorf("trigger_names = %v, want %v", raw["trigger_names"], want)
	}

	// A DNS honeytoken never redirects.
	id := raw["id"].(string)
	rec = f.serve(t, f.h.Update, http.MethodPatch, "/", id, `{"redirect_url": "https://example.com"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "web_url") {
		t.Errorf("PATCH redirect of a DNS honeytoken = %d %s, want 400", rec.Code, rec.Body)
	}
}

// Without the zones of the DNS role, a DNS honeytoken would have no name to
// place, so the console refuses to create one; the other types still work.
func TestCreate_DNSHoneytokenNeedsZones(t *testing.T) {
	t.Parallel()
	f := newFixtureWithZones(t, nil)

	rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeytokens", "", `{"type": "dns", "name": "Jump host"}`)
	if rec.Code != http.StatusUnprocessableEntity || errorCode(t, rec) != codeDNSNotConfigured {
		t.Errorf("POST dns without zones = %d %s, want 422 %s", rec.Code, rec.Body, codeDNSNotConfigured)
	}
	var n int
	if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM honeytokens`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d honeytokens, %v; want none", n, err)
	}
	if got := f.create(t, `{"type": "web_url", "name": "a"}`); got.TriggerURL == nil {
		t.Error("a URL was not created without zones")
	}
}
