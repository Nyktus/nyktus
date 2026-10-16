// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package account_test

import (
	"bytes"
	"context"
	"crypto/sha256"
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

	embedded "nyktus.org/nyktus/catalog"
	"nyktus.org/nyktus/internal/auth/password"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/auth/setup"
	"nyktus.org/nyktus/internal/console"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
)

const (
	consoleURL   = "https://nyktus.example.com"
	testPassword = "correct horse battery"
	unknownID    = "00000000-0000-4000-8000-000000000000"
)

var hasher = password.NewHasher()

type env struct {
	srv   *httptest.Server
	owner *pgxpool.Pool
	// console is a pool of the console's database role.
	console *pgxpool.Pool
}

func newEnv(t *testing.T) env {
	t.Helper()
	ownerURL, consoleDBURL := schematest.Console(t)
	pool := schematest.Open(t, consoleDBURL)
	h, err := console.New(t.Context(), console.Options{
		Catalog:    embedded.Deceptions(),
		Logger:     slog.New(slog.DiscardHandler),
		DB:         pool,
		Setup:      setup.NewService(pool),
		Hasher:     hasher,
		Sessions:   session.Config{IdleTimeout: time.Hour, MaxAge: 12 * time.Hour},
		Keys:       secretboxtest.Keyring(t),
		ConsoleURL: consoleURL,
		TriggerURL: "https://t.example.net",
	})
	if err != nil {
		t.Fatalf("console.New() error = %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return env{srv: srv, owner: schematest.Open(t, ownerURL), console: pool}
}

// signIn creates an active account with role and returns its ID and the cookie
// of a new session.
func (e env) signIn(t *testing.T, email, role string) (id, cookie string) {
	t.Helper()
	hash, err := hasher.Hash(t.Context(), testPassword)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if err := e.owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, password_hash) VALUES ($1, 'Test User', $2, 'active', $3)
RETURNING id`, email, role, hash).Scan(&id); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return id, e.startSession(t, email, testPassword)
}

// startSession signs in and returns the session cookie, or "" if the sign-in
// fails.
func (e env) startSession(t *testing.T, email, pw string) string {
	t.Helper()
	r := e.do(t, http.MethodPost, "/api/v1/session", "", map[string]string{"email": email, "password": pw})
	for _, c := range r.cookies {
		if c.Name == session.CookieName {
			return session.CookieName + "=" + c.Value
		}
	}
	return ""
}

type response struct {
	status  int
	header  http.Header
	raw     []byte
	body    map[string]any
	cookies []*http.Cookie
}

func (r response) code() string {
	errBody, _ := r.body["error"].(map[string]any)
	code, _ := errBody["code"].(string)
	return code
}

// do sends a request with an optional cookie and a JSON body. A body of type
// string is sent as it is.
func (e env) do(t *testing.T, method, path, cookie string, body any) response {
	t.Helper()
	var reader io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		reader = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, e.srv.URL+path, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	r := response{status: resp.StatusCode, header: resp.Header, raw: raw, cookies: resp.Cookies()}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &r.body); err != nil {
			t.Fatalf("%s %s: decode %q: %v", method, path, raw, err)
		}
	}
	return r
}

// create creates a viewer through the API and returns its ID and the token of
// its activation link.
func (e env) create(t *testing.T, cookie, email string) (id, tok string) {
	t.Helper()
	r := e.do(t, http.MethodPost, "/api/v1/users", cookie, map[string]string{"email": email, "display_name": "New User", "role": "viewer"})
	if r.status != http.StatusCreated {
		t.Fatalf("create %s: status %d, body %s", email, r.status, r.raw)
	}
	u := r.body["user"].(map[string]any)
	activation := r.body["activation"].(map[string]any)
	return u["id"].(string), tokenOf(t, activation["url"].(string))
}

func tokenOf(t *testing.T, link string) string {
	t.Helper()
	tok, ok := strings.CutPrefix(link, consoleURL+"/activate#token=")
	if !ok || len(tok) != 43 {
		t.Fatalf("activation link %q does not have the form %s/activate#token=<43 characters>", link, consoleURL)
	}
	return tok
}

func (e env) activate(t *testing.T, tok, pw string) response {
	t.Helper()
	return e.do(t, http.MethodPost, "/api/v1/activation", "", map[string]string{"token": tok, "password": pw})
}

func (e env) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.owner.QueryRow(t.Context(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

type auditRow struct {
	Action, Outcome, Kind, Method string
	ActorID, ResourceID           *string
	ChangedFields                 []string
}

func (e env) auditEntries(t *testing.T, action string) []auditRow {
	t.Helper()
	rows, err := e.owner.Query(t.Context(), `
SELECT action, outcome, actor_kind, auth_method, actor_user_id::text, resource_id::text, changed_fields
FROM audit_entries WHERE action = $1 ORDER BY occurred_at`, action)
	if err != nil {
		t.Fatalf("read audit entries: %v", err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.Action, &r.Outcome, &r.Kind, &r.Method, &r.ActorID, &r.ResourceID, &r.ChangedFields); err != nil {
			t.Fatalf("scan audit entry: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read audit entries: %v", err)
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Viewers and users are denied every operation on accounts before the
// account is looked up: an existing and an unknown ID receive the same answer.
func TestUsers_DeniedRequestsAreRejectedBeforeTheLookup(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	existing, _ := e.signIn(t, "ada@example.com", "admin")
	for _, role := range []string{"viewer", "user"} {
		_, cookie := e.signIn(t, role+"@example.com", role)
		for _, id := range []string{existing, unknownID} {
			for _, op := range []struct {
				method, path string
				body         any
			}{
				{http.MethodGet, "/api/v1/users", nil},
				{http.MethodPost, "/api/v1/users", map[string]string{"email": "x@example.com", "display_name": "X", "role": "admin"}},
				{http.MethodGet, "/api/v1/users/" + id, nil},
				{http.MethodPatch, "/api/v1/users/" + id, map[string]string{"role": "admin"}},
				{http.MethodDelete, "/api/v1/users/" + id, nil},
				{http.MethodPost, "/api/v1/users/" + id + "/activation-link", nil},
				{http.MethodPost, "/api/v1/users/" + id + "/password-reset-link", nil},
			} {
				r := e.do(t, op.method, op.path, cookie, op.body)
				if r.status != http.StatusForbidden || r.code() != "forbidden" {
					t.Errorf("%s: %s %s: status %d, body %s; want 403", role, op.method, op.path, r.status, r.raw)
				}
			}
		}
	}
	if n := e.count(t, `SELECT count(*) FROM users WHERE email = 'x@example.com'`); n != 0 {
		t.Error("a denied request created an account")
	}
	if n := e.count(t, `SELECT count(*) FROM users WHERE id = $1 AND role = 'admin' AND status = 'active' AND updated_at = created_at`, existing); n != 1 {
		t.Error("a denied request changed or deleted the existing account")
	}
	if n := e.count(t, `SELECT count(*) FROM account_links`); n != 0 {
		t.Error("a denied request issued a link")
	}
	if n := e.count(t, `SELECT count(*) FROM audit_entries WHERE outcome = 'denied' AND action IN ('users.read', 'users.write')`); n != 4 {
		t.Errorf("denied entries = %d, want one per role and permission", n)
	}
	for _, op := range []string{"/api/v1/users", "/api/v1/users/" + existing} {
		if r := e.do(t, http.MethodGet, op, "", nil); r.status != http.StatusUnauthorized {
			t.Errorf("GET %s without a session: status %d, want 401", op, r.status)
		}
	}
}

// The activation link is returned once, at creation, and is stored only as a
// hash. The account is pending and has no password.
func TestCreateUser_ReturnsTheActivationLinkOnce(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	adminID, cookie := e.signIn(t, "ada@example.com", "admin")
	r := e.do(t, http.MethodPost, "/api/v1/users", cookie, map[string]string{"email": "Jane@Example.com", "display_name": "Jane Doe", "role": "user"})
	if r.status != http.StatusCreated {
		t.Fatalf("status %d, body %s; want 201", r.status, r.raw)
	}
	u := r.body["user"].(map[string]any)
	if u["email"] != "jane@example.com" || u["display_name"] != "Jane Doe" || u["role"] != "user" || u["status"] != "pending" {
		t.Errorf("user = %v, want a pending user with the address in lower case", u)
	}
	activation := r.body["activation"].(map[string]any)
	tok := tokenOf(t, activation["url"].(string))
	expires, err := time.Parse(time.RFC3339Nano, activation["expires_at"].(string))
	if err != nil || expires.Before(time.Now().Add(71*time.Hour)) || expires.After(time.Now().Add(73*time.Hour)) {
		t.Errorf("expires_at = %v, %v; want in 72 hours", activation["expires_at"], err)
	}

	id := u["id"].(string)
	sum := sha256.Sum256([]byte(tok))
	if n := e.count(t, `SELECT count(*) FROM account_links WHERE user_id = $1 AND token_hash = $2`, id, sum[:]); n != 1 {
		t.Errorf("stored hashes of the token = %d, want 1", n)
	}
	if n := e.count(t, `SELECT count(*) FROM users WHERE id = $1 AND password_hash IS NULL`, id); n != 1 {
		t.Error("the new account has a password")
	}
	for _, path := range []string{"/api/v1/users", "/api/v1/users/" + id} {
		if g := e.do(t, http.MethodGet, path, cookie, nil); g.status != http.StatusOK || bytes.Contains(g.raw, []byte(tok)) || bytes.Contains(g.raw, []byte("activate")) {
			t.Errorf("GET %s: status %d, body %s; want 200 without the link", path, g.status, g.raw)
		}
	}

	creates := e.auditEntries(t, "user.create")
	links := e.auditEntries(t, "activation_link.create")
	for _, entries := range [][]auditRow{creates, links} {
		if len(entries) != 1 || entries[0].Kind != "user" || entries[0].Method != "session" ||
			deref(entries[0].ActorID) != adminID || deref(entries[0].ResourceID) != id {
			t.Errorf("audit entries = %+v, want one by the administrator for the new account", entries)
		}
	}
}

func TestCreateUser_RejectsInvalidInput(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	for _, body := range []any{
		map[string]string{"email": "not an address", "display_name": "Jane", "role": "viewer"},
		map[string]string{"email": "Jane <jane@example.com>", "display_name": "Jane", "role": "viewer"},
		map[string]string{"email": "jane@example.com", "display_name": " Jane", "role": "viewer"},
		map[string]string{"email": "jane@example.com", "display_name": "Jane\u202eDoe", "role": "viewer"},
		map[string]string{"email": "jane@example.com", "display_name": "Jane", "role": "owner"},
		map[string]string{"email": "jane@example.com", "display_name": "Jane"},
		map[string]any{"email": "jane@example.com", "display_name": "Jane", "role": "viewer", "password": testPassword},
		`{"email": "jane@example.com", "display_name": "Jane", "role": "viewer"} {}`,
	} {
		if r := e.do(t, http.MethodPost, "/api/v1/users", cookie, body); r.status != http.StatusBadRequest || r.code() != "invalid_request" {
			t.Errorf("body %v: status %d, body %s; want 400", body, r.status, r.raw)
		}
	}
	if n := e.count(t, `SELECT count(*) FROM users`); n != 1 {
		t.Errorf("accounts = %d, want only the administrator", n)
	}

	e.create(t, cookie, "jane@example.com")
	r := e.do(t, http.MethodPost, "/api/v1/users", cookie, map[string]string{"email": "JANE@example.com", "display_name": "Jane", "role": "viewer"})
	if r.status != http.StatusConflict || r.code() != "email_taken" {
		t.Errorf("taken address: status %d, body %s; want 409 email_taken", r.status, r.raw)
	}
}

func TestActivate_SetsThePasswordOnce(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	id, tok := e.create(t, cookie, "jane@example.com")
	if e.startSession(t, "jane@example.com", "new password for jane") != "" {
		t.Fatal("a pending account could sign in")
	}

	r := e.activate(t, tok, "new password for jane")
	if r.status != http.StatusOK || r.body["id"] != id || r.body["status"] != "active" {
		t.Fatalf("activate: status %d, body %s; want 200 with the active account", r.status, r.raw)
	}
	if len(r.cookies) != 0 {
		t.Error("the activation set a cookie; it must not sign in")
	}
	if e.startSession(t, "jane@example.com", "new password for jane") == "" {
		t.Error("the activated account cannot sign in with its new password")
	}
	if again := e.activate(t, tok, "another password for jane"); again.status != http.StatusNotFound {
		t.Errorf("second use: status %d, want 404", again.status)
	}
	if n := e.count(t, `SELECT count(*) FROM account_links`); n != 0 {
		t.Errorf("account links = %d, want the used one removed", n)
	}

	entries := e.auditEntries(t, "user.activate")
	if len(entries) != 1 || entries[0].Kind != "user" || entries[0].Method != "activation_token" ||
		deref(entries[0].ActorID) != id || deref(entries[0].ResourceID) != id {
		t.Errorf("audit entries = %+v, want one by the account through its token", entries)
	}
}

// Unknown, expired and used tokens, and tokens issued for another purpose,
// receive the same response as a route that does not exist. The password is not validated without a valid token, and
// nothing is recorded in the audit log.
func TestActivate_InvalidTokensAnswerLikeAnUnknownRoute(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	_, expired := e.create(t, cookie, "expired@example.com")
	if _, err := e.owner.Exec(t.Context(), `UPDATE account_links SET expires_at = clock_timestamp() - interval '1 second'`); err != nil {
		t.Fatalf("expire token: %v", err)
	}
	_, used := e.create(t, cookie, "used@example.com")
	if r := e.activate(t, used, testPassword); r.status != http.StatusOK {
		t.Fatalf("activate: status %d", r.status)
	}
	otherID, other := e.create(t, cookie, "other@example.com")
	if _, err := e.owner.Exec(t.Context(), `UPDATE account_links SET purpose = 'password_reset' WHERE user_id = $1`, otherID); err != nil {
		t.Fatalf("change purpose: %v", err)
	}
	entriesBefore := e.count(t, `SELECT count(*) FROM audit_entries`)

	unknownRoute := e.do(t, http.MethodPost, "/api/v1/no-such-route", "", map[string]string{"token": "x", "password": testPassword})
	for name, tok := range map[string]string{"unknown": strings.Repeat("A", 43), "expired": expired, "used": used, "other purpose": other, "empty": ""} {
		for _, pw := range []string{testPassword, "short"} {
			r := e.activate(t, tok, pw)
			if r.status != unknownRoute.status || !sameError(r.body, unknownRoute.body) || !headersEqual(r.header, unknownRoute.header) {
				t.Errorf("%s token, password %q: %d %v %s; want the response of an unknown route: %d %v %s",
					name, pw, r.status, r.header, r.raw, unknownRoute.status, unknownRoute.header, unknownRoute.raw)
			}
		}
	}
	if n := e.count(t, `SELECT count(*) FROM audit_entries`); n != entriesBefore {
		t.Errorf("audit entries grew from %d to %d, want no entries for invalid tokens", entriesBefore, n)
	}
}

// sameError compares two error bodies apart from their request IDs, which differ
// between any two responses.
func sameError(a, b map[string]any) bool {
	strip := func(m map[string]any) map[string]any {
		e, _ := m["error"].(map[string]any)
		out := map[string]any{}
		for k, v := range e {
			if k != "request_id" {
				out[k] = v
			}
		}
		return out
	}
	x, y := strip(a), strip(b)
	if len(x) == 0 || len(a) != 1 || len(b) != 1 || len(x) != len(y) {
		return false
	}
	for k, v := range x {
		if y[k] != v {
			return false
		}
	}
	return true
}

func headersEqual(a, b http.Header) bool {
	for _, h := range []http.Header{a, b} {
		// The request ID and the date differ between any two responses.
		h.Del("X-Request-Id")
		h.Del("Date")
	}
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !slices.Equal(v, b[k]) {
			return false
		}
	}
	return true
}

// With a valid token, the password rules apply, and the token stays valid
// after a rejected password.
func TestActivate_ValidTokenRequiresAValidPassword(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	_, tok := e.create(t, cookie, "jane@example.com")
	for _, pw := range []string{"short", strings.Repeat("a", 129)} {
		if r := e.activate(t, tok, pw); r.status != http.StatusBadRequest || r.code() != "invalid_request" {
			t.Errorf("password %q: status %d, body %s; want 400", pw, r.status, r.raw)
		}
	}
	if r := e.do(t, http.MethodPost, "/api/v1/activation", "", map[string]any{"token": tok, "password": testPassword, "email": "x@example.com"}); r.status != http.StatusBadRequest {
		t.Errorf("unknown field: status %d, want 400", r.status)
	}
	if r := e.activate(t, tok, testPassword); r.status != http.StatusOK {
		t.Errorf("valid password after rejected ones: status %d, body %s; want 200", r.status, r.raw)
	}
}

func TestIssueLink_ReplacesThePreviousLink(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	adminID, cookie := e.signIn(t, "ada@example.com", "admin")
	id, old := e.create(t, cookie, "jane@example.com")

	r := e.do(t, http.MethodPost, "/api/v1/users/"+id+"/activation-link", cookie, nil)
	if r.status != http.StatusCreated {
		t.Fatalf("status %d, body %s; want 201", r.status, r.raw)
	}
	tok := tokenOf(t, r.body["url"].(string))
	if a := e.activate(t, old, testPassword); a.status != http.StatusNotFound {
		t.Errorf("previous link: status %d, want 404", a.status)
	}
	if a := e.activate(t, tok, testPassword); a.status != http.StatusOK {
		t.Errorf("new link: status %d, want 200", a.status)
	}
	if n := len(e.auditEntries(t, "activation_link.create")); n != 2 {
		t.Errorf("activation_link.create entries = %d, want 2", n)
	}

	for _, target := range []string{id, adminID} {
		if r := e.do(t, http.MethodPost, "/api/v1/users/"+target+"/activation-link", cookie, nil); r.status != http.StatusConflict || r.code() != "invalid_state" {
			t.Errorf("active account: status %d, body %s; want 409 invalid_state", r.status, r.raw)
		}
	}
	if r := e.do(t, http.MethodPost, "/api/v1/users/"+unknownID+"/activation-link", cookie, nil); r.status != http.StatusNotFound {
		t.Errorf("unknown account: status %d, want 404", r.status)
	}
}

func TestUpdateUser_ChangesFieldsAndRecordsTheirNames(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	adminID, cookie := e.signIn(t, "ada@example.com", "admin")
	id, _ := e.signIn(t, "jane@example.com", "viewer")

	r := e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, map[string]string{"display_name": "Jane Roe", "role": "user"})
	if r.status != http.StatusOK || r.body["display_name"] != "Jane Roe" || r.body["role"] != "user" {
		t.Fatalf("status %d, body %s; want 200 with the changes", r.status, r.raw)
	}
	if r := e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, map[string]string{"display_name": "Jane Roe"}); r.status != http.StatusOK {
		t.Errorf("change without a difference: status %d, want 200", r.status)
	}
	// An administrator may rename their own account.
	if r := e.do(t, http.MethodPatch, "/api/v1/users/"+adminID, cookie, map[string]string{"display_name": "Ada L."}); r.status != http.StatusOK {
		t.Errorf("rename own account: status %d, body %s; want 200", r.status, r.raw)
	}

	entries := e.auditEntries(t, "user.update")
	if len(entries) != 2 || !slices.Equal(entries[0].ChangedFields, []string{"display_name", "role"}) ||
		deref(entries[0].ResourceID) != id || deref(entries[0].ActorID) != adminID ||
		!slices.Equal(entries[1].ChangedFields, []string{"display_name"}) {
		t.Errorf("audit entries = %+v, want the changed field names of the two real changes", entries)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_entries WHERE 'Jane Roe' = ANY (changed_fields)`); n != 0 {
		t.Error("the audit log contains a new value")
	}
}

func TestUpdateUser_RejectsInvalidRequests(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	id, _ := e.signIn(t, "jane@example.com", "viewer")
	for _, body := range []string{
		`{}`,
		`{"role": null}`,
		`{"display_name": null}`,
		`{"status": "pending"}`,
		`{"status": "locked"}`,
		`{"role": "owner"}`,
		`{"role": 1}`,
		`{"display_name": ""}`,
		`{"email": "jane.roe@example.com"}`,
		`{"password_hash": "x"}`,
		`{"display_name": "Jane"} {}`,
	} {
		if r := e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, body); r.status != http.StatusBadRequest || r.code() != "invalid_request" {
			t.Errorf("body %s: status %d, body %s; want 400", body, r.status, r.raw)
		}
	}
	if r := e.do(t, http.MethodPatch, "/api/v1/users/"+unknownID, cookie, map[string]string{"role": "user"}); r.status != http.StatusNotFound {
		t.Errorf("unknown account: status %d, want 404", r.status)
	}
	if r := e.do(t, http.MethodPatch, "/api/v1/users/not-a-uuid", cookie, map[string]string{"role": "user"}); r.status != http.StatusNotFound {
		t.Errorf("invalid ID: status %d, want 404", r.status)
	}
	if n := len(e.auditEntries(t, "user.update")); n != 0 {
		t.Errorf("user.update entries = %d, want none", n)
	}
}

// A change of role or status ends the sessions of the account, so the change
// takes effect immediately and a reactivated account must sign in again.
func TestUpdateUser_RoleAndStatusChangesEndSessions(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	for name, body := range map[string]map[string]string{
		"role":   {"role": "user"},
		"status": {"status": "deactivated"},
	} {
		id, userCookie := e.signIn(t, name+"@example.com", "viewer")
		if r := e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, map[string]string{"display_name": "Jane Roe"}); r.status != http.StatusOK {
			t.Fatalf("rename: status %d", r.status)
		}
		if n := e.count(t, `SELECT count(*) FROM sessions WHERE user_id = $1`, id); n != 1 {
			t.Fatalf("sessions after a rename = %d, want the session kept", n)
		}
		if r := e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, body); r.status != http.StatusOK {
			t.Fatalf("change %s: status %d, body %s", name, r.status, r.raw)
		}
		if n := e.count(t, `SELECT count(*) FROM sessions WHERE user_id = $1`, id); n != 0 {
			t.Errorf("sessions after a change of %s = %d, want none", name, n)
		}
		if r := e.do(t, http.MethodGet, "/api/v1/session", userCookie, nil); r.status != http.StatusUnauthorized {
			t.Errorf("session after a change of %s: status %d, want 401", name, r.status)
		}
	}
}

func TestUpdateUser_DeactivationRemovesTheActivationLink(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	id, tok := e.create(t, cookie, "jane@example.com")
	if r := e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, map[string]string{"status": "deactivated"}); r.status != http.StatusOK {
		t.Fatalf("deactivate: status %d, body %s", r.status, r.raw)
	}
	r := e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, map[string]string{"status": "active"})
	if r.status != http.StatusOK || r.body["status"] != "pending" {
		t.Fatalf("reactivate: status %d, body %s; want 200 and pending", r.status, r.raw)
	}
	if a := e.activate(t, tok, testPassword); a.status != http.StatusNotFound {
		t.Errorf("link from before the deactivation: status %d, want 404", a.status)
	}
	if r := e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, map[string]string{"status": "active"}); r.status != http.StatusConflict || r.code() != "invalid_state" {
		t.Errorf("activate a pending account: status %d, body %s; want 409 invalid_state", r.status, r.raw)
	}
}

// Administrators cannot remove their own access, even while other
// administrators exist.
func TestUsers_AdministratorsCannotDemoteDeactivateOrDeleteThemselves(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	id, cookie := e.signIn(t, "ada@example.com", "admin")
	e.signIn(t, "grace@example.com", "admin")
	for _, op := range []struct {
		method string
		body   any
	}{
		{http.MethodPatch, map[string]string{"role": "user"}},
		{http.MethodPatch, map[string]string{"status": "deactivated"}},
		{http.MethodPatch, map[string]string{"display_name": "Ada", "role": "viewer"}},
		{http.MethodDelete, nil},
	} {
		if r := e.do(t, op.method, "/api/v1/users/"+id, cookie, op.body); r.status != http.StatusConflict || r.code() != "own_account" {
			t.Errorf("%s %v: status %d, body %s; want 409 own_account", op.method, op.body, r.status, r.raw)
		}
	}
	if n := e.count(t, `SELECT count(*) FROM users WHERE id = $1 AND role = 'admin' AND status = 'active' AND display_name = 'Test User'`, id); n != 1 {
		t.Error("the administrator's account changed")
	}
}

func TestDeleteUser(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	adminID, cookie := e.signIn(t, "ada@example.com", "admin")
	id, _ := e.signIn(t, "jane@example.com", "viewer")
	pendingID, tok := e.create(t, cookie, "pending@example.com")

	for _, target := range []string{id, pendingID} {
		if r := e.do(t, http.MethodDelete, "/api/v1/users/"+target, cookie, nil); r.status != http.StatusNoContent || len(r.raw) != 0 {
			t.Fatalf("delete: status %d, body %s; want 204", r.status, r.raw)
		}
	}
	if n := e.count(t, `SELECT count(*) FROM sessions WHERE user_id = $1`, id); n != 0 {
		t.Errorf("sessions of the deleted account = %d, want none", n)
	}
	if a := e.activate(t, tok, testPassword); a.status != http.StatusNotFound {
		t.Errorf("link of the deleted account: status %d, want 404", a.status)
	}
	if r := e.do(t, http.MethodDelete, "/api/v1/users/"+id, cookie, nil); r.status != http.StatusNotFound {
		t.Errorf("delete again: status %d, want 404", r.status)
	}
	entries := e.auditEntries(t, "user.delete")
	if len(entries) != 2 || deref(entries[0].ResourceID) != id || deref(entries[0].ActorID) != adminID {
		t.Errorf("audit entries = %+v, want one per deleted account", entries)
	}
}

// Reads return personal data and are recorded, at most once per minute.
func TestUsers_ReadsAreRecordedOncePerWindow(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	adminID, cookie := e.signIn(t, "ada@example.com", "admin")
	for range 3 {
		for _, path := range []string{"/api/v1/users", "/api/v1/users/" + adminID} {
			if r := e.do(t, http.MethodGet, path, cookie, nil); r.status != http.StatusOK {
				t.Fatalf("GET %s: status %d", path, r.status)
			}
		}
	}
	entries := e.auditEntries(t, "users.read")
	if len(entries) != 1 || entries[0].Outcome != "success" || deref(entries[0].ActorID) != adminID {
		t.Errorf("users.read entries = %+v, want one by the administrator", entries)
	}
	// A failed lookup returns no personal data and records nothing more.
	if r := e.do(t, http.MethodGet, "/api/v1/users/"+unknownID, cookie, nil); r.status != http.StatusNotFound {
		t.Errorf("unknown account: status %d, want 404", r.status)
	}
}

func TestListUsers_PagesWithCursor(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	for _, email := range []string{"a@example.com", "b@example.com"} {
		e.create(t, cookie, email)
	}
	var emails []string
	query := "?limit=1"
	for range 3 {
		r := e.do(t, http.MethodGet, "/api/v1/users"+query, cookie, nil)
		if r.status != http.StatusOK {
			t.Fatalf("GET %s: status %d, body %s", query, r.status, r.raw)
		}
		for _, u := range r.body["users"].([]any) {
			emails = append(emails, u.(map[string]any)["email"].(string))
		}
		next, _ := r.body["next_cursor"].(string)
		query = "?limit=1&cursor=" + next
	}
	if want := []string{"b@example.com", "a@example.com", "ada@example.com"}; !slices.Equal(emails, want) {
		t.Errorf("pages = %v, want %v", emails, want)
	}
	if r := e.do(t, http.MethodGet, "/api/v1/users?limit=201", cookie, nil); r.status != http.StatusBadRequest {
		t.Errorf("limit above the maximum: status %d, want 400", r.status)
	}
}

// waitForLockWaiter returns once a session of the test database waits for a
// lock, or fails the test if done receives first.
func waitForLockWaiter(t *testing.T, owner *pgxpool.Pool, done <-chan response) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		var waiting bool
		err := owner.QueryRow(ctx, `
SELECT EXISTS (SELECT FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting)
		if err != nil {
			t.Fatalf("query waiting sessions: %v", err)
		}
		if waiting {
			return
		}
		select {
		case r := <-done:
			t.Fatalf("the request completed without waiting for the account: status %d", r.status)
		default:
		}
	}
}

// The activation locks the account before its link, as a deactivation does,
// so the two wait for each other instead of deadlocking. While the activation
// waits for the account, the link must still be free.
func TestActivate_LocksTheAccountBeforeTheLink(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	id, tok := e.create(t, cookie, "jane@example.com")

	holder, err := e.owner.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = holder.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := holder.Exec(t.Context(), `SELECT FROM users WHERE id = $1 FOR UPDATE`, id); err != nil {
		t.Fatalf("lock account: %v", err)
	}

	done := make(chan response, 1)
	go func() { done <- e.activate(t, tok, testPassword) }()
	waitForLockWaiter(t, e.owner, done)

	_, err = e.owner.Exec(t.Context(), `SELECT FROM account_links WHERE user_id = $1 FOR UPDATE NOWAIT`, id)
	if err != nil {
		t.Errorf("lock the link while the activation waits for the account: error = %v, want the link unlocked", err)
	}
	if err := holder.Commit(t.Context()); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if r := <-done; r.status != http.StatusOK {
		t.Errorf("activation: status %d, body %s; want 200", r.status, r.raw)
	}
}
