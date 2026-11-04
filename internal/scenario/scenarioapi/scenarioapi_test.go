// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenarioapi

import (
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/api"
	embedded "nyktus.org/nyktus/catalog"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/platform/apispec"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
	"nyktus.org/nyktus/internal/user"
)

const (
	triggerURL = "https://t.example.net"
	dnsZone    = "d.example.net"
)

// probe is a deception with a honeytoken of each kind and two honeypots, which
// the embedded catalog does not have, so that applying it with its resources
// can be tested through the handler.
const probe = `{
  "schema_version": 3,
  "id": "probe",
  "category": "network",
  "title": {"en": "Probe", "de": "Sonde"},
  "summary": {"en": "Probe.", "de": "Sonde."},
  "techniques": ["T1021.004"],
  "engage_activities": ["EAC0005", "EAC0011"],
  "honeytokens": [
    {"label": {"en": "Gateway", "de": "Zugang"}, "type": "dns", "techniques": ["T1021.004"], "severity": "high"},
    {"label": {"en": "Image", "de": "Bild"}, "type": "web_image", "techniques": []}
  ],
  "honeypots": [
    {"label": {"en": "Jump host", "de": "Sprungserver"}, "service": "ssh"},
    {"label": {"en": "Database", "de": "Datenbank"}, "service": "postgres"}
  ],
  "files": [],
  "guide": {"en": "guide.en.md", "de": "guide.de.md"}
}`

// testCatalog returns the embedded catalog and the deception probe.
func testCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	fsys := fstest.MapFS{}
	if err := fs.WalkDir(embedded.FS(), ".", func(name string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		b, err := fs.ReadFile(embedded.FS(), name)
		fsys[name] = &fstest.MapFile{Data: b}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	fsys["deceptions/probe/deception.json"] = &fstest.MapFile{Data: []byte(probe)}
	fsys["deceptions/probe/guide.en.md"] = &fstest.MapFile{Data: []byte("Guide.\n")}
	fsys["deceptions/probe/guide.de.md"] = &fstest.MapFile{Data: []byte("Anleitung.\n")}
	c, err := catalog.Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type fixture struct {
	h         *Handler
	owner     *pgxpool.Pool
	principal access.Principal
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	return newFixtureWith(t, []string{dnsZone, "d.example.org"}, user.RoleUser)
}

// newFixtureWith returns a fixture whose console knows the zones of the DNS
// role and whose caller has the role.
func newFixtureWith(t *testing.T, zones []string, role user.Role) fixture {
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
		h: NewHandler(slog.New(slog.DiscardHandler), schematest.Open(t, consoleURL), testCatalog(t), triggerURL, zones,
			secretboxtest.Keyring(t)),
		owner:     owner,
		principal: access.Principal{UserID: id, Role: role, Method: audit.AuthSession, SessionID: "s1"},
	}
}

// serve calls handler as the router would, with the principal and the path
// value of the route.
func (f fixture) serve(t *testing.T, handler http.HandlerFunc, method, target, id, body string, pathValues ...string) *httptest.ResponseRecorder {
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
	for i := 0; i+1 < len(pathValues); i += 2 {
		req.SetPathValue(pathValues[i], pathValues[i+1])
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
	rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/scenarios", "", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST %s: %d %s", body, rec.Code, rec.Body)
	}
	return decode[response](t, rec)
}

// createHoneytoken inserts a honeytoken in the scenario scenarioID as the
// owner.
func (f fixture) createHoneytoken(t *testing.T, scenarioID string) string {
	t.Helper()
	var id string
	err := f.owner.QueryRow(t.Context(), `
INSERT INTO honeytokens (type, name, severity, trigger_value, scenario_id)
VALUES ('web_url', 'h', 'medium', translate(substr(md5(random()::text), 1, 26), '0189', 'wxyz'), $1)
RETURNING id`, scenarioID).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// createHoneypot inserts a honeypot in the scenario scenarioID as the owner of
// the database and returns its identifier.
func (f fixture) createHoneypot(t *testing.T, scenarioID string) string {
	t.Helper()
	var id string
	err := f.owner.QueryRow(t.Context(), `
INSERT INTO honeypots (service, name, severity, secret_hash, secret_sealed, scenario_id)
VALUES ('ssh', 'p', 'medium', sha256(gen_random_uuid()::text::bytea), sha256('s'), $1)
RETURNING id`, scenarioID).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestCreateGetList(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	got := f.create(t, `{"name": "Finance share", "notes": "fs01", "engage_activities": ["EAC0005"]}`)
	if got.ID == "" || got.Name != "Finance share" || got.Notes != "fs01" ||
		!slices.Equal(got.EngageActivities, []string{"EAC0005"}) || len(got.Deceptions) != 0 {
		t.Errorf("POST = %+v", got)
	}
	minimal := f.create(t, `{"name": "m"}`)
	if minimal.Notes != "" || minimal.EngageActivities == nil || len(minimal.EngageActivities) != 0 {
		t.Errorf("POST minimal = %+v, want no notes and an empty list of activities", minimal)
	}

	if rec := f.serve(t, f.h.Get, http.MethodGet, "/", got.ID, ""); rec.Code != http.StatusOK || decode[response](t, rec).ID != got.ID {
		t.Errorf("GET = %d %s", rec.Code, rec.Body)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if rec := f.serve(t, f.h.Get, http.MethodGet, "/", id, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", id, rec.Code)
		}
	}

	page := decode[listResponse](t, f.serve(t, f.h.List, http.MethodGet, "/api/v1/scenarios?limit=1", "", ""))
	if len(page.Scenarios) != 1 || page.Scenarios[0].ID != minimal.ID || page.NextCursor == "" {
		t.Fatalf("GET ?limit=1 = %+v, want the newest and a cursor", page)
	}
	page = decode[listResponse](t, f.serve(t, f.h.List, http.MethodGet, "/api/v1/scenarios?limit=1&cursor="+page.NextCursor, "", ""))
	if len(page.Scenarios) != 1 || page.Scenarios[0].ID != got.ID || page.NextCursor != "" {
		t.Errorf("GET second page = %+v, want the oldest and no cursor", page)
	}
	for _, q := range []string{"limit=0", "limit=201", "name=x", "cursor=x"} {
		if rec := f.serve(t, f.h.List, http.MethodGet, "/api/v1/scenarios?"+q, "", ""); rec.Code != http.StatusBadRequest {
			t.Errorf("GET ?%s = %d, want 400", q, rec.Code)
		}
	}
}

func TestCreate_RejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	for _, body := range []string{
		`{}`,
		`{"name": ""}`,
		`{"name": " a"}`,
		`{"name": "` + strings.Repeat("x", 101) + `"}`,
		`{"name": "a", "notes": null}`,
		`{"name": "a", "notes": "\u0000"}`,
		`{"name": "a", "engage_activities": null}`,
		`{"name": "a", "engage_activities": ["EAC9999"]}`,
		`{"name": "a", "engage_activities": ["EAC0005", "EAC0005"]}`,
		`{"name": "a", "deception_id": "remote-access"}`,
		`{"name": "a", "honeytokens": []}`,
	} {
		rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/scenarios", "", body)
		if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
			t.Errorf("POST %s = %d %s, want 400 invalid_request", body, rec.Code, rec.Body)
		}
	}
	var n int
	if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM scenarios`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d scenarios, %v; want none", n, err)
	}
}

func TestUpdate(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	sc := f.create(t, `{"name": "a", "engage_activities": ["EAC0005"]}`)

	rec := f.serve(t, f.h.Update, http.MethodPatch, "/", sc.ID, `{"name": "b", "notes": "n", "engage_activities": []}`)
	got := decode[response](t, rec)
	if rec.Code != http.StatusOK || got.Name != "b" || got.Notes != "n" || got.EngageActivities == nil || len(got.EngageActivities) != 0 {
		t.Errorf("PATCH = %d %s", rec.Code, rec.Body)
	}
	for _, body := range []string{`{}`, `{"name": null}`, `{"name": ""}`, `{"engage_activities": ["X"]}`, `{"deception_id": "remote-access"}`} {
		if rec := f.serve(t, f.h.Update, http.MethodPatch, "/", sc.ID, body); rec.Code != http.StatusBadRequest {
			t.Errorf("PATCH %s = %d %s, want 400", body, rec.Code, rec.Body)
		}
	}
	if rec := f.serve(t, f.h.Update, http.MethodPatch, "/", "00000000-0000-4000-8000-000000000000", `{"name": "c"}`); rec.Code != http.StatusNotFound {
		t.Errorf("PATCH unknown = %d, want 404", rec.Code)
	}
}

// The deletion keeps the honeytokens of the scenario unless the request asks
// to delete them.
func TestDelete_KeepsOrDeletesTheHoneytokens(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	count := func() int {
		t.Helper()
		var n int
		if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM honeytokens`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, tt := range []struct {
		query string
		left  int
	}{
		{"", 1},
		{"?honeytokens=keep", 2},
		{"?honeytokens=delete", 2},
	} {
		sc := f.create(t, `{"name": "s"}`)
		f.createHoneytoken(t, sc.ID)
		rec := f.serve(t, f.h.Delete, http.MethodDelete, "/api/v1/scenarios/"+sc.ID+tt.query, sc.ID, "")
		if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
			t.Errorf("DELETE %s = %d %s, want 204", tt.query, rec.Code, rec.Body)
		}
		if got := count(); got != tt.left {
			t.Errorf("DELETE %s: %d honeytokens left, want %d", tt.query, got, tt.left)
		}
		if rec := f.serve(t, f.h.Get, http.MethodGet, "/", sc.ID, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET after DELETE %s = %d, want 404", tt.query, rec.Code)
		}
	}
	var alone int
	if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM honeytokens WHERE scenario_id IS NULL`).Scan(&alone); err != nil || alone != 2 {
		t.Errorf("%d honeytokens stand alone, %v; want the 2 that were kept", alone, err)
	}
}

// The deletion keeps the honeypots of the scenario unless the request asks to
// delete them, independently of its honeytokens.
func TestDelete_KeepsOrDeletesTheHoneypots(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	count := func(table string) int {
		t.Helper()
		var n int
		if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM `+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, tt := range []struct {
		query                  string
		honeypots, honeytokens int
	}{
		{"", 1, 1},
		{"?honeypots=keep", 2, 2},
		{"?honeypots=delete", 2, 3},
		{"?honeypots=delete&honeytokens=delete", 2, 3},
	} {
		sc := f.create(t, `{"name": "s"}`)
		f.createHoneytoken(t, sc.ID)
		f.createHoneypot(t, sc.ID)
		rec := f.serve(t, f.h.Delete, http.MethodDelete, "/api/v1/scenarios/"+sc.ID+tt.query, sc.ID, "")
		if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
			t.Errorf("DELETE %s = %d %s, want 204", tt.query, rec.Code, rec.Body)
		}
		if got := count("honeypots"); got != tt.honeypots {
			t.Errorf("DELETE %s: %d honeypots left, want %d", tt.query, got, tt.honeypots)
		}
		if got := count("honeytokens"); got != tt.honeytokens {
			t.Errorf("DELETE %s: %d honeytokens left, want %d", tt.query, got, tt.honeytokens)
		}
	}
	if n := count("honeypots WHERE scenario_id IS NULL"); n != 2 {
		t.Errorf("%d honeypots stand alone, want the 2 that were kept", n)
	}
}

func TestDelete_RejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	sc := f.create(t, `{"name": "s"}`)
	h := f.createHoneytoken(t, sc.ID)
	p := f.createHoneypot(t, sc.ID)

	for _, query := range []string{
		"?honeytokens=cascade", "?honeytokens=", "?honeytokens=keep&honeytokens=delete", "?honeypots=cascade",
		"?honeypots=delete&honeypots=delete", "?sensors=keep",
	} {
		rec := f.serve(t, f.h.Delete, http.MethodDelete, "/api/v1/scenarios/"+sc.ID+query, sc.ID, "")
		if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
			t.Errorf("DELETE %s = %d %s, want 400 invalid_request", query, rec.Code, rec.Body)
		}
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if rec := f.serve(t, f.h.Delete, http.MethodDelete, "/api/v1/scenarios/"+id, id, ""); rec.Code != http.StatusNotFound {
			t.Errorf("DELETE %s = %d, want 404", id, rec.Code)
		}
	}
	var scenarioID *string
	if err := f.owner.QueryRow(t.Context(), `SELECT scenario_id::text FROM honeytokens WHERE id = $1`, h).Scan(&scenarioID); err != nil ||
		scenarioID == nil || *scenarioID != sc.ID {
		t.Errorf("honeytoken in %v, %v; want it unchanged in the scenario", scenarioID, err)
	}
	if err := f.owner.QueryRow(t.Context(), `SELECT scenario_id::text FROM honeypots WHERE id = $1`, p).Scan(&scenarioID); err != nil ||
		scenarioID == nil || *scenarioID != sc.ID {
		t.Errorf("honeypot in %v, %v; want it unchanged in the scenario", scenarioID, err)
	}
}

// Every kind of response matches the schema of the specification.
func TestResponses_MatchTheSpecification(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	schemas, err := apispec.ParseSchemas(api.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}

	created := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/scenarios", "", `{"name": "a", "engage_activities": ["EAC0005"]}`)
	sc := decode[response](t, created)
	applied := f.apply(t, "probe", `{"name": "Jump server", "language": "de", "create_resources": true}`)
	for _, b := range []struct {
		schema string
		rec    *httptest.ResponseRecorder
	}{
		{"Scenario", created},
		{"Scenario", f.serve(t, f.h.Get, http.MethodGet, "/", applied.Scenario.ID, "")},
		{"Scenario", f.serve(t, f.h.Get, http.MethodGet, "/", sc.ID, "")},
		{"Scenario", f.serve(t, f.h.Update, http.MethodPatch, "/", sc.ID, `{"notes": "n"}`)},
		{"ScenarioPage", f.serve(t, f.h.List, http.MethodGet, "/api/v1/scenarios?limit=1", "", "")},
		{"ScenarioPage", f.serve(t, f.h.List, http.MethodGet, "/api/v1/scenarios", "", "")},
	} {
		if b.rec.Code >= 300 {
			t.Fatalf("%s: status %d %s", b.schema, b.rec.Code, b.rec.Body)
		}
		for _, p := range schemas.Check(b.schema, b.rec.Body.Bytes()) {
			t.Error(p)
		}
	}
}
