// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package incidentapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/platform/apispec"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/user"
)

type fixture struct {
	h         *Handler
	owner     *pgxpool.Pool
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
	return fixture{
		h:         NewHandler(slog.New(slog.DiscardHandler), schematest.Open(t, consoleURL)),
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

func (f fixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := f.owner.QueryRow(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// incident opens an incident of resource with status, opened at, and returns
// its identifier.
func (f fixture) incident(t *testing.T, resource, status string, openedAt time.Time) string {
	t.Helper()
	var id string
	err := f.owner.QueryRow(t.Context(), `
INSERT INTO incidents (resource_type, resource_id, status, severity, techniques, first_event_at, last_event_at,
	opened_at, acknowledged_at, closed_at)
VALUES ('honeytoken', $1, $2, 'medium', '{T1213}', $3, $3, $3,
	CASE WHEN $2 = 'acknowledged' THEN $3::timestamptz END, CASE WHEN $2 = 'closed' THEN $3::timestamptz END)
RETURNING id`, resource, status, openedAt).Scan(&id)
	if err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	return id
}

// event writes an event of resource over channel at occurredAt, assigned to
// incident unless it is empty, and returns its identifier.
func (f fixture) event(t *testing.T, resource, incident, channel string, occurredAt time.Time) string {
	t.Helper()
	var incidentID *string
	if incident != "" {
		incidentID = &incident
	}
	var id string
	var err error
	switch channel {
	case "http":
		err = f.owner.QueryRow(t.Context(), `
INSERT INTO events (resource_type, resource_id, honeytoken_type, techniques, occurred_at, recorded_at, channel, client_ip,
	method, user_agent, referer, accept_language, incident_id)
VALUES ('honeytoken', $1, 'web_url', '{T1213}', $2, $2, 'http', '192.0.2.7', 'GET', 'curl/8.0', 'https://a.example.com/', 'de', $3)
RETURNING id`, resource, occurredAt, incidentID).Scan(&id)
	default:
		err = f.owner.QueryRow(t.Context(), `
INSERT INTO events (resource_type, resource_id, honeytoken_type, occurred_at, recorded_at, channel, client_ip,
	dns_zone, dns_prefix, dns_qtype, dns_transport, incident_id)
VALUES ('honeytoken', $1, 'dns', $2, $2, 'dns', NULL, 'd.example.com', 'vpn', 'AAAA', 'udp', $3)
RETURNING id`, resource, occurredAt, incidentID).Scan(&id)
	}
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}
	return id
}

const (
	resourceA = "00000000-0000-4000-8000-00000000000a"
	resourceB = "00000000-0000-4000-8000-00000000000b"
)

func incidentIDs(l incidentListResponse) []string {
	var ids []string
	for _, i := range l.Incidents {
		ids = append(ids, i.ID)
	}
	return ids
}

func TestListIncidents_PagesAndFilters(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	start := time.Now().Add(-time.Hour)
	closed := f.incident(t, resourceA, "closed", start)
	acknowledged := f.incident(t, resourceA, "acknowledged", start.Add(time.Minute))
	open := f.incident(t, resourceB, "open", start.Add(2*time.Minute))

	list := func(query string) (incidentListResponse, int) {
		rec := f.serve(t, f.h.ListIncidents, http.MethodGet, "/api/v1/incidents?"+query, "", "")
		if rec.Code != http.StatusOK {
			return incidentListResponse{}, rec.Code
		}
		return decode[incidentListResponse](t, rec), rec.Code
	}

	page, _ := list("limit=2")
	if !slices.Equal(incidentIDs(page), []string{open, acknowledged}) || page.NextCursor == "" {
		t.Errorf("first page = %v, cursor %q", incidentIDs(page), page.NextCursor)
	}
	if next, _ := list("limit=2&cursor=" + page.NextCursor); !slices.Equal(incidentIDs(next), []string{closed}) || next.NextCursor != "" {
		t.Errorf("second page = %v, cursor %q", incidentIDs(next), next.NextCursor)
	}
	// The cursor continues with the filters of the resource.
	page, _ = list("limit=1&resource_id=" + resourceA)
	if next, _ := list("limit=1&resource_id=" + resourceA + "&cursor=" + page.NextCursor); !slices.Equal(incidentIDs(next), []string{closed}) {
		t.Errorf("second page of the resource = %v, want the closed incident", incidentIDs(next))
	}
	for query, want := range map[string][]string{
		"":                                       {open, acknowledged, closed},
		"status=open":                            {open},
		"status=open,acknowledged":               {open, acknowledged},
		"status=closed":                          {closed},
		"resource_id=" + resourceA:               {acknowledged, closed},
		"resource_id=" + resourceB:               {open},
		"status=closed&resource_id=" + resourceB: nil,
	} {
		if got, code := list(query); code != http.StatusOK || !slices.Equal(incidentIDs(got), want) {
			t.Errorf("GET ?%s = %d %v, want %v", query, code, incidentIDs(got), want)
		}
	}
	if got, _ := list("status=closed&resource_id=" + resourceB); got.Incidents == nil {
		t.Error("an empty list is null, want []")
	}
	for _, query := range []string{
		"status=resolved", "status=", "status=open,", "resource_id=a", "resource_id=" + strings.ToUpper(resourceA),
		"status=open&status=closed", "severity=low", "limit=201",
	} {
		if _, code := list(query); code != http.StatusBadRequest {
			t.Errorf("GET ?%s = %d, want 400", query, code)
		}
	}
}

func TestGetIncident(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	id := f.incident(t, resourceA, "open", time.Now())

	rec := f.serve(t, f.h.GetIncident, http.MethodGet, "/", id, "")
	got := decode[incidentResponse](t, rec)
	if rec.Code != http.StatusOK || got.ID != id || got.ResourceID != resourceA || got.Status != "open" || got.Severity != "medium" ||
		!slices.Equal(got.Techniques, []string{"T1213"}) || got.SeverityOverride != nil || got.TechniquesOverride != nil || got.EventCount != 1 {
		t.Errorf("GET = %d %s", rec.Code, rec.Body)
	}
	for _, unknown := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if rec := f.serve(t, f.h.GetIncident, http.MethodGet, "/", unknown, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", unknown, rec.Code)
		}
	}
}

func TestUpdateIncident_Triage(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	id := f.incident(t, resourceA, "open", time.Now().Add(-time.Hour))
	patch := func(body string) *httptest.ResponseRecorder {
		return f.serve(t, f.h.UpdateIncident, http.MethodPatch, "/", id, body)
	}

	rec := patch(`{"status": "acknowledged", "notes": "looking\ninto it", "severity_override": "critical", "techniques_override": ["T1078"]}`)
	got := decode[incidentResponse](t, rec)
	if rec.Code != http.StatusOK || got.Status != "acknowledged" || got.AcknowledgedAt == nil || got.Notes != "looking\ninto it" ||
		got.Severity != "critical" || got.EventSeverity != "medium" || !slices.Equal(got.Techniques, []string{"T1078"}) ||
		!slices.Equal(got.EventTechniques, []string{"T1213"}) {
		t.Fatalf("PATCH = %d %s", rec.Code, rec.Body)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'incident.update' AND resource_type = 'incident'
	AND resource_id = $1 AND changed_fields = '{status,notes,severity_override,techniques_override}' AND actor_user_id = $2`, id, f.principal.UserID); n != 1 {
		t.Errorf("%d audit entries with the changed fields, want 1", n)
	}

	// null removes an override, an empty list states that there is no
	// technique.
	rec = patch(`{"severity_override": null, "techniques_override": []}`)
	got = decode[incidentResponse](t, rec)
	if rec.Code != http.StatusOK || got.SeverityOverride != nil || got.Severity != "medium" || got.TechniquesOverride == nil ||
		len(got.Techniques) != 0 {
		t.Errorf("PATCH removing the severity override = %d %s", rec.Code, rec.Body)
	}
	if rec := patch(`{"techniques_override": null}`); rec.Code != http.StatusOK || decode[incidentResponse](t, rec).TechniquesOverride != nil {
		t.Errorf("PATCH removing the techniques override = %d %s", rec.Code, rec.Body)
	}

	// A change that changes nothing is not recorded.
	before := f.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'incident.update'`)
	if rec := patch(`{"status": "acknowledged", "notes": "looking\ninto it"}`); rec.Code != http.StatusOK {
		t.Errorf("PATCH without change = %d %s", rec.Code, rec.Body)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'incident.update'`); n != before {
		t.Errorf("a change without change was recorded")
	}

	// The status only moves forward; a closed incident stays closed, but its
	// notes can still be written.
	if rec := patch(`{"status": "open"}`); rec.Code != http.StatusConflict || errorCode(t, rec) != codeInvalidState {
		t.Errorf("PATCH back to open = %d %s, want 409 invalid_state", rec.Code, rec.Body)
	}
	if rec := patch(`{"status": "closed"}`); rec.Code != http.StatusOK || decode[incidentResponse](t, rec).ClosedAt == nil {
		t.Errorf("PATCH closed = %d %s", rec.Code, rec.Body)
	}
	for _, status := range []string{"open", "acknowledged"} {
		if rec := patch(`{"status": "` + status + `"}`); rec.Code != http.StatusConflict || errorCode(t, rec) != codeInvalidState {
			t.Errorf("PATCH closed back to %s = %d %s, want 409 invalid_state", status, rec.Code, rec.Body)
		}
	}
	if rec := patch(`{"notes": "false positive: backup job"}`); rec.Code != http.StatusOK {
		t.Errorf("PATCH notes of a closed incident = %d %s", rec.Code, rec.Body)
	}

	for _, body := range []string{
		`{}`,
		`{"status": null}`,
		`{"notes": null}`,
		`{"status": "resolved"}`,
		`{"severity_override": "urgent"}`,
		`{"severity_override": 3}`,
		`{"techniques_override": ["T9999"]}`,
		`{"techniques_override": ["T1078", "T1078"]}`,
		`{"notes": "` + strings.Repeat("a", 10001) + `"}`,
		`{"notes": "a\u0007"}`,
		`{"severity": "low"}`,
		`{"event_count": 1}`,
	} {
		if rec := patch(body); rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
			t.Errorf("PATCH %.60s = %d %s, want 400 invalid_request", body, rec.Code, rec.Body)
		}
	}
	for _, unknown := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if rec := f.serve(t, f.h.UpdateIncident, http.MethodPatch, "/", unknown, `{"notes": "x"}`); rec.Code != http.StatusNotFound {
			t.Errorf("PATCH %s = %d, want 404", unknown, rec.Code)
		}
	}
}

func eventIDs(l eventListResponse) []string {
	var ids []string
	for _, e := range l.Events {
		ids = append(ids, e.ID)
	}
	return ids
}

func TestListEvents_PagesFiltersAndRecordsTheRead(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	start := time.Now().Add(-time.Hour)
	incidentA := f.incident(t, resourceA, "open", start)
	first := f.event(t, resourceA, incidentA, "http", start)
	second := f.event(t, resourceA, incidentA, "dns", start.Add(time.Minute))
	unassigned := f.event(t, resourceB, "", "http", start.Add(2*time.Minute))
	// The DNS query arrived before the first request, but was recorded after
	// it: the list follows the time of recording.
	if _, err := f.owner.Exec(t.Context(), "UPDATE events SET occurred_at = recorded_at - interval '3 minutes' WHERE id = $1", second); err != nil {
		t.Fatal(err)
	}

	list := func(query string) (eventListResponse, int) {
		rec := f.serve(t, f.h.ListEvents, http.MethodGet, "/api/v1/events?"+query, "", "")
		if rec.Code != http.StatusOK {
			return eventListResponse{}, rec.Code
		}
		return decode[eventListResponse](t, rec), rec.Code
	}

	page, _ := list("limit=2")
	if !slices.Equal(eventIDs(page), []string{unassigned, second}) || page.NextCursor == "" {
		t.Errorf("first page = %v, cursor %q", eventIDs(page), page.NextCursor)
	}
	if next, _ := list("limit=2&cursor=" + page.NextCursor); !slices.Equal(eventIDs(next), []string{first}) || next.NextCursor != "" {
		t.Errorf("second page = %v, cursor %q", eventIDs(next), next.NextCursor)
	}
	page, _ = list("limit=1&incident_id=" + incidentA)
	if next, _ := list("limit=1&incident_id=" + incidentA + "&cursor=" + page.NextCursor); !slices.Equal(eventIDs(next), []string{first}) {
		t.Errorf("second page of the incident = %v, want the first event", eventIDs(next))
	}
	for query, want := range map[string][]string{
		"incident_id=" + incidentA:                         {second, first},
		"incident_id=00000000-0000-4000-8000-000000000000": nil,
	} {
		if got, code := list(query); code != http.StatusOK || !slices.Equal(eventIDs(got), want) {
			t.Errorf("GET ?%s = %d %v, want %v", query, code, eventIDs(got), want)
		}
	}
	for _, query := range []string{"incident_id=a", "incident_id=", "resource_id=" + resourceA, "channel=dns", "limit=0"} {
		if _, code := list(query); code != http.StatusBadRequest {
			t.Errorf("GET ?%s = %d, want 400", query, code)
		}
	}

	// Reads of events are recorded, at most once per user and minute.
	if n := f.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'events.read' AND outcome = 'success' AND actor_user_id = $1`,
		f.principal.UserID); n != 1 {
		t.Errorf("%d reads of events recorded, want 1", n)
	}
}

// Every channel has its own member, and the other one is null.
func TestGetEvent_ShowsTheRequestOrTheQuery(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	request := f.event(t, resourceA, "", "http", time.Now())
	query := f.event(t, resourceA, "", "dns", time.Now())

	rec := f.serve(t, f.h.GetEvent, http.MethodGet, "/", request, "")
	got := decode[eventResponse](t, rec)
	if rec.Code != http.StatusOK || got.Channel != "http" || got.DNS != nil || got.HTTP == nil || got.HTTP.Method != http.MethodGet ||
		got.HTTP.UserAgent != "curl/8.0" || got.ClientIP == nil || *got.ClientIP != "192.0.2.7" || got.IncidentID != nil ||
		got.HoneytokenType == nil || *got.HoneytokenType != "web_url" {
		t.Errorf("GET request = %d %s", rec.Code, rec.Body)
	}
	rec = f.serve(t, f.h.GetEvent, http.MethodGet, "/", query, "")
	got = decode[eventResponse](t, rec)
	if rec.Code != http.StatusOK || got.Channel != "dns" || got.HTTP != nil || got.DNS == nil || got.DNS.QType != "AAAA" ||
		got.DNS.Prefix != "vpn" || got.ClientIP != nil || got.Techniques == nil {
		t.Errorf("GET query = %d %s", rec.Code, rec.Body)
	}
	for _, unknown := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if rec := f.serve(t, f.h.GetEvent, http.MethodGet, "/", unknown, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", unknown, rec.Code)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'events.read'`); n != 1 {
		t.Errorf("%d reads of events recorded, want 1", n)
	}
}

// Without the entry in the audit log, the reader receives no events.
func TestEvents_AreNotReturnedWithoutTheAuditEntry(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	id := f.event(t, resourceA, "", "http", time.Now())
	if _, err := f.owner.Exec(t.Context(), "ALTER TABLE audit_entries ADD CONSTRAINT audit_entries_reject CHECK (false) NOT VALID"); err != nil {
		t.Fatal(err)
	}

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"list": f.serve(t, f.h.ListEvents, http.MethodGet, "/api/v1/events", "", ""),
		"get":  f.serve(t, f.h.GetEvent, http.MethodGet, "/", id, ""),
	} {
		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "192.0.2.7") {
			t.Errorf("%s = %d %s, want 500 without data", name, rec.Code, rec.Body)
		}
	}
}

// Every kind of response matches the schema of the specification: incidents
// of a honeytoken and of a scenario, events over HTTP and DNS, alone and in a
// scenario, one at a time and in lists.
func TestResponses_MatchTheSpecification(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	schemas, err := apispec.ParseSchemas(api.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
	incidentID := f.incident(t, resourceA, "open", time.Now())
	request := f.event(t, resourceA, incidentID, "http", time.Now())
	query := f.event(t, resourceA, incidentID, "dns", time.Now())
	var scenarioIncident, scenarioEvent string
	if err := f.owner.QueryRow(t.Context(), `
INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at)
VALUES ('scenario', $1, 'low', now(), now()) RETURNING id`, resourceB).Scan(&scenarioIncident); err != nil {
		t.Fatal(err)
	}
	if err := f.owner.QueryRow(t.Context(), `
INSERT INTO events (resource_type, resource_id, scenario_id, honeytoken_type, occurred_at, recorded_at, channel, method, incident_id)
VALUES ('honeytoken', $1, $2, 'web_image', now(), now(), 'http', 'HEAD', $3) RETURNING id`, resourceA, resourceB, scenarioIncident).Scan(&scenarioEvent); err != nil {
		t.Fatal(err)
	}

	for _, b := range []struct {
		schema string
		rec    *httptest.ResponseRecorder
	}{
		{"Incident", f.serve(t, f.h.GetIncident, http.MethodGet, "/", incidentID, "")},
		{"Incident", f.serve(t, f.h.GetIncident, http.MethodGet, "/", scenarioIncident, "")},
		{"IncidentPage", f.serve(t, f.h.ListIncidents, http.MethodGet, "/api/v1/incidents", "", "")},
		{"Event", f.serve(t, f.h.GetEvent, http.MethodGet, "/", request, "")},
		{"Event", f.serve(t, f.h.GetEvent, http.MethodGet, "/", query, "")},
		{"Event", f.serve(t, f.h.GetEvent, http.MethodGet, "/", scenarioEvent, "")},
		{"EventPage", f.serve(t, f.h.ListEvents, http.MethodGet, "/api/v1/events", "", "")},
	} {
		if b.rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d %s", b.schema, b.rec.Code, b.rec.Body)
		}
		for _, p := range schemas.Check(b.schema, b.rec.Body.Bytes()) {
			t.Error(p)
		}
	}

	got := decode[eventResponse](t, f.serve(t, f.h.GetEvent, http.MethodGet, "/", scenarioEvent, ""))
	if got.ScenarioID == nil || *got.ScenarioID != resourceB || got.ResourceID != resourceA {
		t.Errorf("event in a scenario = %+v, want the honeytoken %s in the scenario %s", got, resourceA, resourceB)
	}
	page := decode[incidentListResponse](t, f.serve(t, f.h.ListIncidents, http.MethodGet, "/api/v1/incidents?resource_id="+resourceB, "", ""))
	if ids := incidentIDs(page); !slices.Equal(ids, []string{scenarioIncident}) {
		t.Errorf("incidents of the scenario = %v, want %s", ids, scenarioIncident)
	}
}
