// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package alertingapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/alerting"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
	"nyktus.org/nyktus/internal/platform/ssrf"
	"nyktus.org/nyktus/internal/user"
)

const (
	password = "correct horse battery"
	hookURL  = "https://hooks.example.com/services/T0/B0/s3cr3t"
)

// fakeConfirmer confirms with password and runs the change in a transaction
// of the console's pool, as session.Service does after the password.
type fakeConfirmer struct {
	pool *pgxpool.Pool
	mu   sync.Mutex
	// actions are the actions of every confirmation, including failed ones.
	actions []audit.Action
}

func (c *fakeConfirmer) Confirm(ctx context.Context, _ access.Principal, pw string, action audit.Action,
	change func(ctx context.Context, tx pgx.Tx) error,
) error {
	c.mu.Lock()
	c.actions = append(c.actions, action)
	c.mu.Unlock()
	if pw != password {
		return session.ErrWrongPassword
	}
	return pgx.BeginFunc(ctx, c.pool, func(tx pgx.Tx) error { return change(ctx, tx) })
}

func (c *fakeConfirmer) confirmed() []audit.Action {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.actions)
}

// fakeChecker accepts URLs of public hosts and rejects others like the guard.
type fakeChecker struct{}

func (fakeChecker) CheckURL(_ context.Context, s string) (*url.URL, error) {
	u, err := url.Parse(s)
	switch {
	case err != nil || u.Scheme != "https":
		return nil, ssrf.ErrInvalidURL
	case strings.HasSuffix(u.Hostname(), ".internal"):
		return nil, ssrf.ErrBlocked
	}
	return u, nil
}

type fixture struct {
	h         *Handler
	owner     *pgxpool.Pool
	confirmer *fakeConfirmer
	principal access.Principal
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ownerURL, consoleURL := schematest.Console(t)
	owner := schematest.Open(t, ownerURL)
	console := schematest.Open(t, consoleURL)
	var id string
	err := owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, password_hash)
VALUES ('admin@example.com', 'Admin', 'admin', 'active', '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA')
RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	confirmer := &fakeConfirmer{pool: console}
	return fixture{
		h:         NewHandler(slog.New(slog.DiscardHandler), console, secretboxtest.Keyring(t), confirmer, fakeChecker{}),
		owner:     owner,
		confirmer: confirmer,
		principal: access.Principal{UserID: id, Role: user.RoleAdmin, Method: audit.AuthSession, SessionID: "s1"},
	}
}

func (f fixture) serve(t *testing.T, handler http.HandlerFunc, method, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(access.WithPrincipal(t.Context(), f.principal), method, "/api/v1/alert-channels", r)
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

func (f fixture) create(t *testing.T, body string) response {
	t.Helper()
	rec := f.serve(t, f.h.Create, http.MethodPost, "", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", rec.Code, rec.Body)
	}
	return decode[response](t, rec)
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
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error %s: %v", rec.Body, err)
	}
	return e.Error.Code
}

func webhookBody(name string) string {
	return `{"name":"` + name + `","type":"webhook","url":"` + hookURL + `",` +
		`"header":{"name":"Authorization","value":"Bearer t0k3n"},"password":"` + password + `"}`
}

func TestCreate_ConfirmsAndNeverReturnsTheSecrets(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	rec := f.serve(t, f.h.Create, http.MethodPost, "", webhookBody("SOAR"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	if body := rec.Body.String(); strings.Contains(body, "s3cr3t") || strings.Contains(body, "t0k3n") {
		t.Errorf("the response contains a secret: %s", body)
	}
	c := decode[response](t, rec)
	if c.Name != "SOAR" || c.Type != alerting.TypeWebhook || !c.Enabled || c.Target != "https://hooks.example.com" ||
		c.HeaderName == nil || *c.HeaderName != "Authorization" {
		t.Errorf("channel = %+v", c)
	}
	if got := f.confirmer.confirmed(); !slices.Equal(got, []audit.Action{audit.ActionAlertChannelCreate}) {
		t.Errorf("confirmations = %v", got)
	}

	for _, h := range []http.HandlerFunc{f.h.List, f.h.Get} {
		rec := f.serve(t, h, http.MethodGet, c.ID, "")
		if body := rec.Body.String(); rec.Code != http.StatusOK || strings.Contains(body, "s3cr3t") || strings.Contains(body, "t0k3n") {
			t.Errorf("read: status %d, body %s", rec.Code, body)
		}
	}
}

func TestCreate_Rejections(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.create(t, webhookBody("Taken"))

	tests := []struct {
		name   string
		body   string
		status int
		code   string
	}{
		{"wrong password", strings.Replace(webhookBody("A"), password, "wrong", 1), http.StatusForbidden, "wrong_password"},
		{"no password", `{"name":"A","type":"slack","url":"` + hookURL + `"}`, http.StatusForbidden, "wrong_password"},
		{"unknown type", `{"name":"A","type":"email","url":"` + hookURL + `","password":"` + password + `"}`, http.StatusBadRequest, "invalid_request"},
		{"invalid name", `{"name":" A","type":"slack","url":"` + hookURL + `","password":"` + password + `"}`, http.StatusBadRequest, "invalid_request"},
		{"plain http", `{"name":"A","type":"slack","url":"http://hooks.example.com/x","password":"` + password + `"}`, http.StatusBadRequest, "invalid_request"},
		{"internal target", `{"name":"A","type":"slack","url":"https://soar.internal/x","password":"` + password + `"}`, http.StatusUnprocessableEntity, "target_not_allowed"},
		{"header for slack", `{"name":"A","type":"slack","url":"` + hookURL + `","header":{"name":"X","value":"y"},"password":"` + password + `"}`, http.StatusUnprocessableEntity, "header_not_allowed"},
		{"reserved header", `{"name":"A","type":"webhook","url":"` + hookURL + `","header":{"name":"Host","value":"y"},"password":"` + password + `"}`, http.StatusBadRequest, "invalid_request"},
		{"header with line break", `{"name":"A","type":"webhook","url":"` + hookURL + `","header":{"name":"X-T","value":"a\r\nB: c"},"password":"` + password + `"}`, http.StatusBadRequest, "invalid_request"},
		{"null header", `{"name":"A","type":"webhook","url":"` + hookURL + `","header":null,"password":"` + password + `"}`, http.StatusBadRequest, "invalid_request"},
		{"unknown member", `{"name":"A","type":"slack","url":"` + hookURL + `","secret":"x","password":"` + password + `"}`, http.StatusBadRequest, "invalid_request"},
		{"taken name", strings.Replace(webhookBody("Taken"), "SOAR", "Taken", 1), http.StatusConflict, "name_taken"},
	}
	for _, tt := range tests {
		rec := f.serve(t, f.h.Create, http.MethodPost, "", tt.body)
		if rec.Code != tt.status || errorCode(t, rec) != tt.code {
			t.Errorf("%s: status %d, body %s; want %d %s", tt.name, rec.Code, rec.Body, tt.status, tt.code)
		}
	}
	// Requests rejected for their fields or their target never reach the
	// confirmation, which counts wrong passwords.
	if got := f.confirmer.confirmed(); len(got) != 4 {
		t.Errorf("confirmations = %d, want 4 (the first channel, both passwords and the taken name)", len(got))
	}
	var n int
	if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM alert_channels`).Scan(&n); err != nil || n != 1 {
		t.Errorf("channels = %d, %v; want 1", n, err)
	}
}

func TestUpdate_ConfirmsChangesThatRedirectOrStopAlerts(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c := f.create(t, webhookBody("SOAR"))
	before := len(f.confirmer.confirmed())

	// Only renaming needs no password.
	if rec := f.serve(t, f.h.Update, http.MethodPatch, c.ID, `{"name":"Renamed"}`); rec.Code != http.StatusOK {
		t.Errorf("rename: status %d, body %s", rec.Code, rec.Body)
	}
	if got := len(f.confirmer.confirmed()); got != before {
		t.Errorf("a rename asked for confirmation")
	}

	for _, body := range []string{
		`{"enabled":false}`,
		`{"enabled":true}`,
		`{"url":"https://other.example.com/x"}`,
		`{"header":{"name":"X-API-Key","value":"k"}}`,
		`{"header":null}`,
		`{"name":"Again","url":"https://other.example.com/x"}`,
	} {
		// A missing password is a wrong one: the confirmation decides.
		rec := f.serve(t, f.h.Update, http.MethodPatch, c.ID, body)
		if rec.Code != http.StatusForbidden || errorCode(t, rec) != "wrong_password" {
			t.Errorf("%s without password: status %d, body %s; want 403 wrong_password", body, rec.Code, rec.Body)
		}
		rec = f.serve(t, f.h.Update, http.MethodPatch, c.ID, strings.TrimSuffix(body, "}")+`,"password":"wrong"}`)
		if rec.Code != http.StatusForbidden || errorCode(t, rec) != "wrong_password" {
			t.Errorf("%s with a wrong password: status %d, body %s; want 403 wrong_password", body, rec.Code, rec.Body)
		}
	}
	got := decode[response](t, f.serve(t, f.h.Get, http.MethodGet, c.ID, ""))
	if got.Name != "Renamed" || !got.Enabled || got.Target != "https://hooks.example.com" || got.HeaderName == nil {
		t.Errorf("unconfirmed changes took effect: %+v", got)
	}

	rec := f.serve(t, f.h.Update, http.MethodPatch, c.ID,
		`{"enabled":false,"url":"https://other.example.com:8443/x","header":null,"password":"`+password+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed change: status %d, body %s", rec.Code, rec.Body)
	}
	got = decode[response](t, rec)
	if got.Enabled || got.Target != "https://other.example.com:8443" || got.HeaderName != nil {
		t.Errorf("confirmed change = %+v", got)
	}
	if actions := f.confirmer.confirmed(); actions[len(actions)-1] != audit.ActionAlertChannelUpdate {
		t.Errorf("last confirmation = %s, want %s", actions[len(actions)-1], audit.ActionAlertChannelUpdate)
	}

	for _, tt := range []struct{ body, code string }{
		{`{}`, "invalid_request"},
		{`{"type":"slack"}`, "invalid_request"},
		{`{"url":"https://soar.internal/x","password":"` + password + `"}`, "target_not_allowed"},
	} {
		if rec := f.serve(t, f.h.Update, http.MethodPatch, c.ID, tt.body); errorCode(t, rec) != tt.code {
			t.Errorf("%s: status %d, body %s; want %s", tt.body, rec.Code, rec.Body, tt.code)
		}
	}
	if rec := f.serve(t, f.h.Update, http.MethodPatch, "00000000-0000-4000-8000-000000000000", `{"name":"x"}`); rec.Code != http.StatusNotFound {
		t.Errorf("unknown channel: status %d", rec.Code)
	}
}

func TestDelete_OnlyDisabledChannels(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c := f.create(t, webhookBody("SOAR"))

	rec := f.serve(t, f.h.Delete, http.MethodDelete, c.ID, "")
	if rec.Code != http.StatusConflict || errorCode(t, rec) != "alert_channel_enabled" {
		t.Errorf("enabled: status %d, body %s", rec.Code, rec.Body)
	}
	f.serve(t, f.h.Update, http.MethodPatch, c.ID, `{"enabled":false,"password":"`+password+`"}`)
	if rec := f.serve(t, f.h.Delete, http.MethodDelete, c.ID, ""); rec.Code != http.StatusNoContent {
		t.Errorf("disabled: status %d, body %s", rec.Code, rec.Body)
	}
	if rec := f.serve(t, f.h.Delete, http.MethodDelete, c.ID, ""); rec.Code != http.StatusNotFound {
		t.Errorf("deleted: status %d", rec.Code)
	}
}

// The routes admit sessions only; a handler that is reached without one was
// wired without the restriction and answers 500 instead of acting.
func TestCreateAndUpdate_WithoutSession_Fail(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.principal = access.Principal{APIKeyID: "k1", Method: audit.AuthAPIKey, Scopes: nil}
	for _, h := range []http.HandlerFunc{f.h.Create, f.h.Update} {
		if rec := f.serve(t, h, http.MethodPost, "x", webhookBody("A")); rec.Code != http.StatusInternalServerError {
			t.Errorf("status %d, want 500", rec.Code)
		}
	}
	if got := f.confirmer.confirmed(); len(got) != 0 {
		t.Errorf("confirmations = %v", got)
	}
}

func TestResponse_HasTheDocumentedMembers(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c := f.create(t, webhookBody("SOAR"))

	var members map[string]any
	if err := json.Unmarshal(f.serve(t, f.h.Get, http.MethodGet, c.ID, "").Body.Bytes(), &members); err != nil {
		t.Fatal(err)
	}
	want := specSchemas(t)["AlertChannel"].Required
	if got := slices.Collect(maps.Keys(members)); !sameSet(got, want) {
		t.Errorf("members = %v, want %v", got, want)
	}
}

func TestTest_RequestsATestOnceAtATime(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c := f.create(t, webhookBody("SOAR"))

	rec := f.serve(t, f.h.Test, http.MethodPost, c.ID, "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	d := decode[deliveryResponse](t, rec)
	if d.IncidentID != nil || d.ChannelID != c.ID || d.Status != alerting.StatusPending || d.NextAttemptAt == nil {
		t.Errorf("delivery = %+v", d)
	}
	if rec := f.serve(t, f.h.Test, http.MethodPost, c.ID, ""); rec.Code != http.StatusConflict || errorCode(t, rec) != "test_pending" {
		t.Errorf("second test: status %d, body %s", rec.Code, rec.Body)
	}
	if rec := f.serve(t, f.h.Test, http.MethodPost, "00000000-0000-4000-8000-000000000000", ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown channel: status %d", rec.Code)
	}
	got := decode[deliveryResponse](t, f.serve(t, f.h.GetDelivery, http.MethodGet, d.ID, ""))
	if got.ID != d.ID {
		t.Errorf("GetDelivery = %+v", got)
	}
	if rec := f.serve(t, f.h.GetDelivery, http.MethodGet, "not-a-uuid", ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown delivery: status %d", rec.Code)
	}
	var n int
	if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM audit_entries WHERE action = 'alert_channel.test' AND resource_id = $1`, c.ID).Scan(&n); err != nil || n != 1 {
		t.Errorf("audit entries of the test = %d, %v; want 1", n, err)
	}
}

func TestDeliveries_ListAndRetry(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c := f.create(t, webhookBody("SOAR"))
	var incidentID, deliveryID string
	err := f.owner.QueryRow(t.Context(), `
WITH i AS (
	INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at)
	VALUES ('honeytoken', gen_random_uuid(), 'low', clock_timestamp(), clock_timestamp()) RETURNING id
), a AS (
	INSERT INTO alerts (incident_id, severity) SELECT id, 'low' FROM i RETURNING incident_id
)
INSERT INTO alert_deliveries (alert_id, channel_id, channel_type, channel_name, status, attempts, last_attempt_at, last_error)
SELECT incident_id, $1, 'webhook', 'SOAR', 'dead', 10, clock_timestamp(), 'http_status' FROM a
RETURNING alert_id, id`, c.ID).Scan(&incidentID, &deliveryID)
	if err != nil {
		t.Fatal(err)
	}

	list := decode[deliveryListResponse](t, f.serve(t, f.h.IncidentDeliveries, http.MethodGet, incidentID, ""))
	if len(list.Deliveries) != 1 || list.Deliveries[0].Status != alerting.StatusDead || list.Deliveries[0].NextAttemptAt != nil ||
		*list.Deliveries[0].LastError != alerting.FailureHTTPStatus || *list.Deliveries[0].IncidentID != incidentID {
		t.Errorf("deliveries = %+v", list)
	}
	if rec := f.serve(t, f.h.IncidentDeliveries, http.MethodGet, "00000000-0000-4000-8000-000000000000", ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown incident: status %d", rec.Code)
	}

	rec := f.serve(t, f.h.RetryDelivery, http.MethodPost, deliveryID, "")
	if got := decode[deliveryResponse](t, rec); rec.Code != http.StatusOK || got.Status != alerting.StatusPending || got.Attempts != 0 {
		t.Errorf("retry: status %d, %+v", rec.Code, got)
	}
	if rec := f.serve(t, f.h.RetryDelivery, http.MethodPost, deliveryID, ""); rec.Code != http.StatusConflict || errorCode(t, rec) != "delivery_not_dead" {
		t.Errorf("retry a pending delivery: status %d, body %s", rec.Code, rec.Body)
	}
	if rec := f.serve(t, f.h.RetryDelivery, http.MethodPost, "00000000-0000-4000-8000-000000000000", ""); rec.Code != http.StatusNotFound {
		t.Errorf("retry an unknown delivery: status %d", rec.Code)
	}
	var n int
	if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM audit_entries WHERE action = 'alert_delivery.retry' AND resource_type = 'alert_delivery' AND resource_id = $1`, deliveryID).Scan(&n); err != nil || n != 1 {
		t.Errorf("audit entries of the retry = %d, %v; want 1", n, err)
	}

	var members map[string]any
	if err := json.Unmarshal(f.serve(t, f.h.GetDelivery, http.MethodGet, deliveryID, "").Body.Bytes(), &members); err != nil {
		t.Fatal(err)
	}
	if got, want := slices.Collect(maps.Keys(members)), specSchemas(t)["AlertDelivery"].Required; !sameSet(got, want) {
		t.Errorf("members = %v, want %v", got, want)
	}
}

func TestTestAndRetry_WithoutSession_Fail(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.principal = access.Principal{APIKeyID: "k1", Method: audit.AuthAPIKey}
	for _, h := range []http.HandlerFunc{f.h.Test, f.h.RetryDelivery} {
		if rec := f.serve(t, h, http.MethodPost, "00000000-0000-4000-8000-000000000000", ""); rec.Code != http.StatusInternalServerError {
			t.Errorf("status %d, want 500", rec.Code)
		}
	}
}
