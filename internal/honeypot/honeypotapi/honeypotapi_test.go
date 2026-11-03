// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeypotapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/platform/apispec"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
	"nyktus.org/nyktus/internal/user"
)

// syncBuffer collects the log of a handler.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type fixture struct {
	h         *Handler
	owner     *pgxpool.Pool
	log       *syncBuffer
	principal access.Principal
}

func newFixture(t *testing.T) fixture {
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
	log := &syncBuffer{}
	return fixture{
		h:         NewHandler(slog.New(slog.NewJSONHandler(log, nil)), schematest.Open(t, consoleURL), secretboxtest.Keyring(t)),
		owner:     owner,
		log:       log,
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

// created is a response with a secret, decoded without the type of the
// handler, so that the test reads what a client receives.
type created struct {
	Response
	Secret       string `json:"secret"`
	SensorConfig string `json:"sensor_config"`
}

func (f fixture) create(t *testing.T, body string) created {
	t.Helper()
	rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeypots", "", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST %s: %d %s", body, rec.Code, rec.Body)
	}
	return decode[created](t, rec)
}

// owns reports whether secret finds the honeypot id through its stored hash,
// as the trigger will look a sensor up.
func (f fixture) owns(t *testing.T, id, secret string) bool {
	t.Helper()
	sum := sha256.Sum256([]byte(secret))
	var found string
	err := f.owner.QueryRow(t.Context(), `SELECT id FROM honeypots WHERE secret_hash = $1`, sum[:]).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return found == id
}

func TestCreate_ReturnsTheHoneypotWithItsSecret(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeypots", "",
		`{"service": "ssh", "name": "Jump host", "notes": "VLAN 20", "techniques": ["T1021.004"]}`)
	got := decode[created](t, rec)
	if rec.Code != http.StatusCreated || got.Service != "ssh" || got.Name != "Jump host" || got.Notes != "VLAN 20" ||
		!got.Enabled || !slices.Equal(got.Techniques, []string{"T1021.004"}) || got.Severity != "medium" ||
		got.Status != "never" || got.LastSeenAt != nil || got.SensorVersion != nil || got.ScenarioID != nil {
		t.Errorf("POST = %d %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("POST Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
	if len(got.Secret) != 43 || !f.owns(t, got.ID, got.Secret) {
		t.Errorf("POST secret = %q, want 43 characters that find the honeypot", got.Secret)
	}
	// The entry for the sensor names the honeypot, the service and the secret,
	// and nothing of the inventory.
	// The entry of an SSH honeypot also names the file of its host key, which
	// the operator creates.
	wantEntry := "- id: \"" + got.ID + "\"\n  service: \"ssh\"\n  # Address and port to listen on. Ports below 1024 need CAP_NET_BIND_SERVICE.\n  listen: \":22\"\n" +
		"  # The private key of the server. Create it once, without a passphrase, with\n  # ssh-keygen -t ed25519 -N '' -f and the path below, and keep it: a host key\n  # that changes would identify the honeypot, and one that two honeypots share\n  # would tie them together. The path is relative to this file.\n  host_key_file: \"ssh_host_key_" + got.ID + "\"\n" +
		"  secret: \"" + got.Secret + "\"\n"
	if got.SensorConfig != wantEntry {
		t.Errorf("sensor_config = %q, want %q", got.SensorConfig, wantEntry)
	}
	if strings.Contains(got.SensorConfig, "Jump host") || strings.Contains(got.SensorConfig, "VLAN 20") {
		t.Errorf("sensor_config = %q, holds the name or the notes", got.SensorConfig)
	}

	// Nothing but the read of the secret shows it again.
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"GET":   f.serve(t, f.h.Get, http.MethodGet, "/", got.ID, ""),
		"list":  f.serve(t, f.h.List, http.MethodGet, "/api/v1/honeypots", "", ""),
		"PATCH": f.serve(t, f.h.Update, http.MethodPatch, "/", got.ID, `{"name": "b"}`),
	} {
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), got.Secret) || strings.Contains(rec.Body.String(), `"secret"`) || strings.Contains(rec.Body.String(), "sensor_config") {
			t.Errorf("%s = %d %s, want no secret and no entry for the sensor", name, rec.Code, rec.Body)
		}
	}
	if strings.Contains(f.log.String(), got.Secret) || strings.Contains(f.log.String(), "Jump host") {
		t.Errorf("log %s holds the secret or the name", f.log.String())
	}

	// Without the optional members, a honeypot is enabled and has no notes or
	// techniques; the lists are empty, never null.
	rec = f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeypots", "", `{"service": "ldap", "name": "DC"}`)
	raw := decode[map[string]any](t, rec)
	if rec.Code != http.StatusCreated || raw["enabled"] != true || raw["notes"] != "" || raw["techniques"] == nil ||
		len(raw["techniques"].([]any)) != 0 || raw["severity"] != "medium" {
		t.Errorf("POST minimal = %d %s", rec.Code, rec.Body)
	}
	if got := f.create(t, `{"service": "telnet", "name": "Off", "enabled": false, "severity": "critical"}`); got.Enabled || got.Severity != "critical" {
		t.Errorf("POST disabled and critical = %+v", got.Response)
	}
}

func TestCreate_RejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	for _, body := range []string{
		`{"name": "a"}`,
		`{"service": "smtp", "name": "a"}`,
		`{"service": "SSH", "name": "a"}`,
		`{"service": "ssh"}`,
		`{"service": "ssh", "name": null}`,
		`{"service": "ssh", "name": " a"}`,
		`{"service": "ssh", "name": "a", "notes": "\u0000"}`,
		`{"service": "ssh", "name": "a", "techniques": ["T9999"]}`,
		`{"service": "ssh", "name": "a", "techniques": ["T1078", "T1078"]}`,
		`{"service": "ssh", "name": "a", "secret": "chosen-by-the-client"}`,
		`{"service": "ssh", "name": "a", "port": 22}`,
		`{"service": "ssh", "name": "a", "last_seen_at": "2026-10-19T12:00:00Z"}`,
		`{"service": "ssh", "name": "a", "enabled": null}`,
		`{"service": "ssh", "name": "a", "notes": null}`,
		`{"service": "ssh", "name": "a", "techniques": null}`,
		`{"service": "ssh", "name": "a", "severity": null}`,
		`{"service": "ssh", "name": "a", "scenario_id": null}`,
		`{"service": "ssh", "name": "a", "scenario_id": ""}`,
		`{"service": "ssh", "name": "a", "scenario_id": "not-a-uuid"}`,
		`{"service": "ssh", "name": "a", "scenario_id": 7}`,
	} {
		rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeypots", "", body)
		if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
			t.Errorf("POST %s: %d %s, want 400 invalid_request", body, rec.Code, rec.Body)
		}
	}
	for body, rule := range map[string]string{
		`{"service": "smtp", "name": "a"}`:                    "service must be one of ssh, telnet, postgres, ldap",
		`{"service": "ssh", "name": "a", "severity": ""}`:     "severity must be",
		`{"service": "ssh", "name": "a", "severity": "info"}`: "severity must be",
	} {
		rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeypots", "", body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), rule) {
			t.Errorf("POST %s: %d %s, want 400 naming %q", body, rec.Code, rec.Body, rule)
		}
	}
	var n int
	if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM honeypots`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d honeypots, %v; want none", n, err)
	}
}

func TestGet(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c := f.create(t, `{"service": "postgres", "name": "a"}`)

	rec := f.serve(t, f.h.Get, http.MethodGet, "/api/v1/honeypots/"+c.ID, c.ID, "")
	if got := decode[Response](t, rec); rec.Code != http.StatusOK || got.ID != c.ID || got.Service != "postgres" {
		t.Errorf("GET = %d %s", rec.Code, rec.Body)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if rec := f.serve(t, f.h.Get, http.MethodGet, "/api/v1/honeypots/"+id, id, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", id, rec.Code)
		}
	}
}

func TestList_PagesAndFilters(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ssh := f.create(t, `{"service": "ssh", "name": "s"}`)
	ldap := f.create(t, `{"service": "ldap", "name": "l", "enabled": false}`)

	list := func(query string) (listResponse, int) {
		rec := f.serve(t, f.h.List, http.MethodGet, "/api/v1/honeypots?"+query, "", "")
		if rec.Code != http.StatusOK {
			return listResponse{}, rec.Code
		}
		return decode[listResponse](t, rec), rec.Code
	}
	ids := func(l listResponse) []string {
		var ids []string
		for _, h := range l.Honeypots {
			ids = append(ids, h.ID)
		}
		return ids
	}

	page, _ := list("limit=1")
	if !slices.Equal(ids(page), []string{ldap.ID}) || page.NextCursor == "" {
		t.Errorf("first page = %v, cursor %q", ids(page), page.NextCursor)
	}
	if next, _ := list("limit=1&cursor=" + page.NextCursor); !slices.Equal(ids(next), []string{ssh.ID}) || next.NextCursor != "" {
		t.Errorf("second page = %v, cursor %q", ids(next), next.NextCursor)
	}
	for query, want := range map[string][]string{
		"":                          {ldap.ID, ssh.ID},
		"service=ssh":               {ssh.ID},
		"service=ldap":              {ldap.ID},
		"enabled=true":              {ssh.ID},
		"enabled=false":             {ldap.ID},
		"service=ssh&enabled=false": nil,
	} {
		if got, code := list(query); code != http.StatusOK || !slices.Equal(ids(got), want) {
			t.Errorf("GET ?%s = %d %v, want %v", query, code, ids(got), want)
		}
	}
	if got, _ := list("service=telnet"); got.Honeypots == nil {
		t.Error("an empty list is null, want []")
	}
	for _, query := range []string{"service=smtp", "service=", "enabled=yes", "service=ssh&service=ldap", "status=online", "limit=201", "scenario_id=x"} {
		if _, code := list(query); code != http.StatusBadRequest {
			t.Errorf("GET ?%s = %d, want 400", query, code)
		}
	}
}

func TestUpdate(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c := f.create(t, `{"service": "ssh", "name": "a", "techniques": ["T1078"]}`)
	patch := func(body string) *httptest.ResponseRecorder {
		return f.serve(t, f.h.Update, http.MethodPatch, "/api/v1/honeypots/"+c.ID, c.ID, body)
	}

	rec := patch(`{"name": "b", "notes": "n", "enabled": false, "techniques": [], "severity": "high"}`)
	got := decode[Response](t, rec)
	if rec.Code != http.StatusOK || got.Name != "b" || got.Notes != "n" || got.Enabled || len(got.Techniques) != 0 ||
		got.Severity != "high" || got.Service != "ssh" {
		t.Errorf("PATCH = %d %s", rec.Code, rec.Body)
	}
	if !f.owns(t, c.ID, c.Secret) {
		t.Error("a change replaced the secret")
	}
	for _, body := range []string{
		`{}`,
		`{"name": null}`,
		`{"enabled": null}`,
		`{"techniques": null}`,
		`{"notes": null}`,
		`{"severity": null}`,
		`{"severity": "info"}`,
		`{"service": "telnet"}`,
		`{"secret": "chosen-by-the-client"}`,
		`{"scenario_id": null}`,
		`{"last_seen_at": null}`,
		`{"name": ""}`,
		`{"techniques": ["T1086"]}`,
	} {
		if rec := patch(body); rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
			t.Errorf("PATCH %s = %d %s, want 400 invalid_request", body, rec.Code, rec.Body)
		}
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if rec := f.serve(t, f.h.Update, http.MethodPatch, "/", id, `{"name": "x"}`); rec.Code != http.StatusNotFound {
			t.Errorf("PATCH %s = %d, want 404", id, rec.Code)
		}
	}
}

// A new secret is shown once, works at once, and the old one stops working at
// once; what the last sensor reported is cleared.
func TestReplaceSecret_ReturnsANewSecretAndInvalidatesTheOld(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c := f.create(t, `{"service": "telnet", "name": "Switch console"}`)
	if _, err := f.owner.Exec(t.Context(), `
UPDATE honeypots SET created_at = created_at - interval '1 hour', last_seen_at = clock_timestamp(), sensor_version = '0.1.0'
WHERE id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}

	rec := f.serve(t, f.h.ReplaceSecret, http.MethodPost, "/api/v1/honeypots/"+c.ID+"/secret", c.ID, "")
	got := decode[created](t, rec)
	if rec.Code != http.StatusOK || got.ID != c.ID || got.Name != "Switch console" || got.Status != "never" ||
		got.LastSeenAt != nil || got.SensorVersion != nil {
		t.Errorf("POST secret = %d %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("POST secret Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
	if len(got.Secret) != 43 || got.Secret == c.Secret || !f.owns(t, c.ID, got.Secret) || f.owns(t, c.ID, c.Secret) {
		t.Errorf("POST secret = %q; want a new secret that works while the old one does not", got.Secret)
	}
	// The entry for the sensor carries the new secret, for the same honeypot.
	if !strings.Contains(got.SensorConfig, got.Secret) || strings.Contains(got.SensorConfig, c.Secret) || !strings.Contains(got.SensorConfig, `service: "telnet"`) ||
		!strings.Contains(got.SensorConfig, `id: "`+c.ID+`"`) {
		t.Errorf("sensor_config = %q, want the entry of the honeypot with the new secret", got.SensorConfig)
	}
	if rec := f.serve(t, f.h.Get, http.MethodGet, "/", c.ID, ""); strings.Contains(rec.Body.String(), got.Secret) {
		t.Errorf("GET after the replacement = %s, want no secret", rec.Body)
	}
	if strings.Contains(f.log.String(), got.Secret) || strings.Contains(f.log.String(), c.Secret) {
		t.Errorf("log %s holds a secret", f.log.String())
	}
	if rec := f.serve(t, f.h.ReplaceSecret, http.MethodPost, "/", "00000000-0000-4000-8000-000000000000", ""); rec.Code != http.StatusNotFound {
		t.Errorf("POST secret of an unknown honeypot = %d, want 404", rec.Code)
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c := f.create(t, `{"service": "ssh", "name": "a"}`)

	if rec := f.serve(t, f.h.Delete, http.MethodDelete, "/", c.ID, ""); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Errorf("DELETE = %d %s, want 204", rec.Code, rec.Body)
	}
	if f.owns(t, c.ID, c.Secret) {
		t.Error("the secret of a deleted honeypot still finds it")
	}
	for _, id := range []string{c.ID, "not-a-uuid"} {
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
// in a scenario, of every service, seen and never seen by a sensor, in a list,
// after a change of its scenario and with a new secret.
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
		`{"service": "ssh", "name": "a", "techniques": ["T1021.004"], "notes": "n"}`,
		`{"service": "telnet", "name": "b", "enabled": false}`,
		`{"service": "postgres", "name": "c", "severity": "high"}`,
		`{"service": "ldap", "name": "d"}`,
	} {
		add("CreatedHoneypot", f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeypots", "", body))
	}
	c := f.create(t, `{"service": "ssh", "name": "e"}`)
	if _, err := f.owner.Exec(t.Context(), `
UPDATE honeypots SET created_at = created_at - interval '1 hour', last_seen_at = clock_timestamp(), sensor_version = '0.1.0'
WHERE id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}
	add("Honeypot", f.serve(t, f.h.Get, http.MethodGet, "/", c.ID, ""))
	add("Honeypot", f.serve(t, f.h.AssignScenario, http.MethodPut, "/", c.ID, `{"scenario_id": "`+sc+`"}`))
	add("Honeypot", f.serve(t, f.h.Update, http.MethodPatch, "/", c.ID, `{"name": "f"}`))
	add("HoneypotPage", f.serve(t, f.h.List, http.MethodGet, "/api/v1/honeypots?limit=2", "", ""))
	add("HoneypotPage", f.serve(t, f.h.List, http.MethodGet, "/api/v1/honeypots?scenario_id="+sc, "", ""))
	add("HoneypotSecret", f.serve(t, f.h.ReadSecret, http.MethodGet, "/", c.ID, ""))
	add("CreatedHoneypot", f.serve(t, f.h.ReplaceSecret, http.MethodPost, "/", c.ID, ""))
	add("HoneypotSecret", f.serve(t, f.h.ReadSecret, http.MethodGet, "/", c.ID, ""))
	add("Honeypot", f.serve(t, f.h.DetachScenario, http.MethodDelete, "/", c.ID, ""))

	for _, b := range bodies {
		if b.rec.Code >= 300 {
			t.Fatalf("%s: status %d %s", b.schema, b.rec.Code, b.rec.Body)
		}
		for _, p := range schemas.Check(b.schema, b.rec.Body.Bytes()) {
			t.Error(p)
		}
	}
}

// A honeypot joins a scenario through its own operation, which answers with
// the honeypot, and leaves it through another one; the list of a scenario
// holds its honeypots.
func TestScenario_AssignAndDetach(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	sc, other := f.createScenario(t), f.createScenario(t)
	c := f.create(t, `{"service": "ssh", "name": "a"}`)
	f.create(t, `{"service": "ssh", "name": "alone"}`)

	rec := f.serve(t, f.h.AssignScenario, http.MethodPut, "/", c.ID, `{"scenario_id": "`+sc+`"}`)
	if got := decode[Response](t, rec); rec.Code != http.StatusOK || got.ScenarioID == nil || *got.ScenarioID != sc {
		t.Fatalf("PUT = %d %s, want the honeypot in the scenario", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), `"secret"`) {
		t.Errorf("PUT = %s, want no secret", rec.Body)
	}
	if rec := f.serve(t, f.h.AssignScenario, http.MethodPut, "/", c.ID, `{"scenario_id": "`+sc+`"}`); rec.Code != http.StatusOK {
		t.Errorf("PUT again = %d %s, want 200", rec.Code, rec.Body)
	}
	page := decode[listResponse](t, f.serve(t, f.h.List, http.MethodGet, "/api/v1/honeypots?scenario_id="+sc, "", ""))
	if len(page.Honeypots) != 1 || page.Honeypots[0].ID != c.ID {
		t.Errorf("GET ?scenario_id = %+v, want only the honeypot of the scenario", page.Honeypots)
	}

	rec = f.serve(t, f.h.AssignScenario, http.MethodPut, "/", c.ID, `{"scenario_id": "`+other+`"}`)
	if rec.Code != http.StatusConflict || errorCode(t, rec) != codeInScenario {
		t.Errorf("PUT other scenario = %d %s, want 409 %s", rec.Code, rec.Body, codeInScenario)
	}

	rec = f.serve(t, f.h.DetachScenario, http.MethodDelete, "/", c.ID, "")
	if got := decode[Response](t, rec); rec.Code != http.StatusOK || got.ScenarioID != nil {
		t.Errorf("DELETE = %d %s, want the honeypot alone", rec.Code, rec.Body)
	}
	if rec := f.serve(t, f.h.DetachScenario, http.MethodDelete, "/", c.ID, ""); rec.Code != http.StatusOK {
		t.Errorf("DELETE again = %d %s, want 200", rec.Code, rec.Body)
	}
	if rec := f.serve(t, f.h.AssignScenario, http.MethodPut, "/", c.ID, `{"scenario_id": "`+other+`"}`); rec.Code != http.StatusOK {
		t.Errorf("PUT other scenario after leaving = %d %s, want 200", rec.Code, rec.Body)
	}
}

func TestScenario_RejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	sc := f.createScenario(t)
	c := f.create(t, `{"service": "ssh", "name": "a"}`)
	const missing = "00000000-0000-4000-8000-000000000000"

	for _, tt := range []struct {
		name, id, body string
		status         int
		code           string
	}{
		{"unknown scenario", c.ID, `{"scenario_id": "` + missing + `"}`, http.StatusUnprocessableEntity, codeScenarioNotFound},
		{"scenario in upper case", c.ID, `{"scenario_id": "` + strings.ToUpper(sc) + `"}`, http.StatusBadRequest, "invalid_request"},
		{"no scenario", c.ID, `{}`, http.StatusBadRequest, "invalid_request"},
		{"null scenario", c.ID, `{"scenario_id": null}`, http.StatusBadRequest, "invalid_request"},
		{"unknown member", c.ID, `{"scenario_id": "` + sc + `", "name": "x"}`, http.StatusBadRequest, "invalid_request"},
		{"unknown honeypot", missing, `{"scenario_id": "` + sc + `"}`, http.StatusNotFound, "not_found"},
		{"malformed honeypot", "not-a-uuid", `{"scenario_id": "` + sc + `"}`, http.StatusNotFound, "not_found"},
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
}

// A honeypot can join a scenario when it is created; one that names a
// scenario that does not exist is not created, and the response still shows
// the secret once.
func TestCreate_JoinsAScenario(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	sc := f.createScenario(t)

	got := f.create(t, `{"service": "ssh", "name": "a", "scenario_id": "`+sc+`"}`)
	if got.ScenarioID == nil || *got.ScenarioID != sc || got.Secret == "" || got.SensorConfig == "" {
		t.Errorf("POST = %+v, want it in the scenario %s with its secret", got, sc)
	}
	page := decode[listResponse](t, f.serve(t, f.h.List, http.MethodGet, "/api/v1/honeypots?scenario_id="+sc, "", ""))
	if len(page.Honeypots) != 1 || page.Honeypots[0].ID != got.ID {
		t.Errorf("GET ?scenario_id = %+v, want the new honeypot", page.Honeypots)
	}

	const missing = "00000000-0000-4000-8000-000000000000"
	rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeypots", "", `{"service": "ssh", "name": "b", "scenario_id": "`+missing+`"}`)
	if rec.Code != http.StatusUnprocessableEntity || errorCode(t, rec) != codeScenarioNotFound {
		t.Errorf("POST unknown scenario = %d %s, want 422 %s", rec.Code, rec.Body, codeScenarioNotFound)
	}
	var n int
	if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM honeypots`).Scan(&n); err != nil || n != 1 {
		t.Errorf("honeypots = %d, %v; want only the first", n, err)
	}
}

// The secret is shown again as it was created, with the entry for the sensor,
// until it is replaced, never to the log, and the read is recorded for the
// honeypot without the secret.
func TestReadSecret_ShowsTheSecretAgain(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c := f.create(t, `{"service": "ssh", "name": "Jump host", "techniques": ["T1021.004"]}`)

	rec := f.serve(t, f.h.ReadSecret, http.MethodGet, "/api/v1/honeypots/"+c.ID+"/secret", c.ID, "")
	got := decode[created](t, rec)
	if rec.Code != http.StatusOK || got.ID != c.ID || got.Secret != c.Secret || got.SensorConfig != c.SensorConfig ||
		got.Name != "Jump host" || got.Status != "never" || !slices.Equal(got.Techniques, []string{"T1021.004"}) {
		t.Fatalf("GET secret = %d %s, want the secret and the entry of the creation", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("GET secret Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}

	// A honeypot that a sensor has reported for shows its real status.
	if _, err := f.owner.Exec(t.Context(), `UPDATE honeypots SET created_at = created_at - interval '1 hour', last_seen_at = clock_timestamp() WHERE id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}
	if seen := decode[created](t, f.serve(t, f.h.ReadSecret, http.MethodGet, "/", c.ID, "")); seen.Status != "online" || seen.Secret != c.Secret {
		t.Errorf("GET secret of a honeypot that reported = %+v, want status online and the secret", seen.Response)
	}

	replaced := decode[created](t, f.serve(t, f.h.ReplaceSecret, http.MethodPost, "/", c.ID, ""))
	again := decode[created](t, f.serve(t, f.h.ReadSecret, http.MethodGet, "/", c.ID, ""))
	if again.Secret != replaced.Secret || again.Secret == c.Secret || !f.owns(t, c.ID, again.Secret) || f.owns(t, c.ID, c.Secret) {
		t.Errorf("GET secret after the replacement = %q, want the new secret, which finds the honeypot", again.Secret)
	}

	if strings.Contains(f.log.String(), c.Secret) || strings.Contains(f.log.String(), replaced.Secret) {
		t.Errorf("log %s holds a secret", f.log.String())
	}
	var n int
	if err := f.owner.QueryRow(t.Context(), `
SELECT count(*) FROM audit_entries WHERE action = 'honeypot.secret_read' AND resource_type = 'honeypot' AND resource_id = $1`, c.ID).Scan(&n); err != nil || n != 3 {
		t.Errorf("audit entries of the read = %d, %v; want one for each of the three reads", n, err)
	}
}

func TestReadSecret_RejectsUnknownHoneypots(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		rec := f.serve(t, f.h.ReadSecret, http.MethodGet, "/", id, "")
		if rec.Code != http.StatusNotFound || errorCode(t, rec) != "not_found" {
			t.Errorf("GET secret of %q = %d %s, want 404 not_found", id, rec.Code, rec.Body)
		}
	}
	var n int
	if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM audit_entries WHERE action = 'honeypot.secret_read'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("audit entries of reads = %d, %v; want none", n, err)
	}
}

// A secret that does not open is answered like any failure of the server, with
// nothing of the secret and nothing of the reason; the log has the reason, not
// the secret.
func TestReadSecret_DoesNotSendASecretThatDoesNotOpen(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c := f.create(t, `{"service": "ssh", "name": "a"}`)
	if _, err := f.owner.Exec(t.Context(), `UPDATE honeypots SET secret_sealed = set_byte(secret_sealed, 20, get_byte(secret_sealed, 20) # 1) WHERE id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}

	rec := f.serve(t, f.h.ReadSecret, http.MethodGet, "/", c.ID, "")
	if rec.Code != http.StatusInternalServerError || errorCode(t, rec) != "internal_error" || strings.Contains(rec.Body.String(), c.Secret) ||
		strings.Contains(rec.Body.String(), "cannot be read") {
		t.Errorf("GET secret = %d %s, want a generic 500", rec.Code, rec.Body)
	}
	if !strings.Contains(f.log.String(), "honeypot: read secret") || strings.Contains(f.log.String(), c.Secret) {
		t.Errorf("log %s, want the failed read without the secret", f.log.String())
	}
	var n int
	if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM audit_entries WHERE action = 'honeypot.secret_read'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("audit entries of reads = %d, %v; want none for a read that sent nothing", n, err)
	}
}
