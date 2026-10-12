// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/auth/oidc"
	"nyktus.org/nyktus/internal/auth/password"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/auth/setup"
	"nyktus.org/nyktus/internal/console"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
)

const consoleURL = "https://nyktus.example.com"

var hasher = password.NewHasher()

var groups = oidc.Groups{
	GroupsClaim: "groups",
	Admin:       []string{"nyktus-admins"},
	User:        []string{"nyktus-users"},
	Viewer:      []string{"nyktus-viewers", "auditors"},
}

type env struct {
	srv      *httptest.Server
	idp      *idp
	provider *oidc.Provider
	owner    *pgxpool.Pool
	// errors counts the records of the console at level error.
	errors *atomic.Int32
}

// errorCounter counts the records at level error and discards the rest.
type errorCounter struct {
	slog.Handler
	n *atomic.Int32
}

func (h errorCounter) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelError }

func (h errorCounter) Handle(context.Context, slog.Record) error {
	h.n.Add(1)
	return nil
}

// newEnv starts a console whose identity provider is discovered, with a local
// administrator, so that the setup is complete.
func newEnv(t *testing.T) env {
	t.Helper()
	e := newUndiscoveredEnv(t)
	e.exec(t, `INSERT INTO users (email, display_name, role, status, password_hash) VALUES ('ada@example.com', 'Ada', 'admin', 'active', $1)`,
		mustHash(t))
	return e
}

// newUndiscoveredEnv starts a console without any account, whose provider has
// not been discovered yet. discover discovers it.
func newUndiscoveredEnv(t *testing.T) env {
	t.Helper()
	p := newIDP(t, consoleURL+oidc.CallbackPath)
	ownerURL, consoleDBURL := schematest.Console(t)
	pool := schematest.Open(t, consoleDBURL)
	provider := oidc.NewProvider(oidc.ProviderConfig{
		Issuer: p.issuer(), ClientID: clientID, ClientSecret: clientSecret, Scopes: []string{"email", "profile"},
		RedirectURL: consoleURL + oidc.CallbackPath, AllowHTTP: true,
	}, slog.New(slog.DiscardHandler))
	errs := new(atomic.Int32)
	h, err := console.New(t.Context(), console.Options{
		Logger:     slog.New(errorCounter{Handler: slog.DiscardHandler, n: errs}),
		DB:         pool,
		Setup:      setup.NewService(pool),
		Hasher:     hasher,
		Sessions:   session.Config{IdleTimeout: time.Hour, MaxAge: 12 * time.Hour},
		Keys:       secretboxtest.Keyring(t),
		ConsoleURL: consoleURL,
		TriggerURL: "https://t.example.net",
		OIDC:       provider,
		OIDCGroups: groups,
	})
	if err != nil {
		t.Fatalf("console.New() error = %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return env{srv: srv, idp: p, provider: provider, owner: schematest.Open(t, ownerURL), errors: errs}
}

func mustHash(t *testing.T) string {
	t.Helper()
	h, err := hasher.Hash(t.Context(), "correct horse battery")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	return h
}

// discover discovers the provider of e. It returns once discovery succeeded.
func (e env) discover(t *testing.T) {
	t.Helper()
	e.provider.Run(t.Context())
}

type response struct {
	status   int
	location string
	cookies  map[string]*http.Cookie
	body     []byte
}

// get sends a GET request without following redirects. Cookies are sent by
// hand, because a cookie jar does not send Secure cookies to the plain HTTP
// test server.
func (e env) get(t *testing.T, path string, cookies ...*http.Cookie) response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, e.srv.URL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for _, c := range cookies {
		if c != nil {
			req.Header.Add("Cookie", c.Name+"="+c.Value)
		}
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	r := response{status: resp.StatusCode, location: resp.Header.Get("Location"), cookies: map[string]*http.Cookie{}, body: body}
	for _, c := range resp.Cookies() {
		r.cookies[c.Name] = c
	}
	return r
}

// begin starts a sign-in and returns the response that sends the browser to
// the provider.
func (e env) begin(t *testing.T) response {
	t.Helper()
	r := e.get(t, "/api/v1/oidc/authorize")
	if r.status != http.StatusFound || r.cookies[oidc.CookieName] == nil {
		t.Fatalf("authorize: status %d, cookies %v, body %s; want 302 with the cookie", r.status, r.cookies, r.body)
	}
	return r
}

func callbackPath(state, code string) string {
	return oidc.CallbackPath + "?" + url.Values{"state": {state}, "code": {code}}.Encode()
}

// signIn signs the user sub in with groups and returns the response of the
// callback.
func (e env) signIn(t *testing.T, sub string, groups []string, opts ...option) response {
	t.Helper()
	start := e.begin(t)
	state, code := e.idp.authorize(start.location, sub, groups, opts...)
	return e.get(t, callbackPath(state, code), start.cookies[oidc.CookieName])
}

// mustSignIn signs the user sub in and returns the session cookie.
func (e env) mustSignIn(t *testing.T, sub string, groups []string, opts ...option) *http.Cookie {
	t.Helper()
	r := e.signIn(t, sub, groups, opts...)
	if r.status != http.StatusSeeOther || r.location != "/" || r.cookies[session.CookieName] == nil {
		t.Fatalf("callback: status %d, location %q, cookies %v; want 303 to / with a session cookie", r.status, r.location, r.cookies)
	}
	return r.cookies[session.CookieName]
}

// wantRejected checks that the callback sent the browser to the sign-in page
// without a session.
func wantRejected(t *testing.T, r response) {
	t.Helper()
	if r.status != http.StatusSeeOther || r.location != "/sign-in#error=oidc" || r.cookies[session.CookieName] != nil {
		t.Errorf("callback: status %d, location %q, session cookie %v; want 303 to /sign-in#error=oidc without a session",
			r.status, r.location, r.cookies[session.CookieName])
	}
	if c := r.cookies[oidc.CookieName]; c == nil || c.MaxAge >= 0 {
		t.Errorf("callback: cookie %v, want the sign-in cookie cleared", c)
	}
}

func (e env) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := e.owner.Exec(t.Context(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (e env) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.owner.QueryRow(t.Context(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

type account struct {
	ID, Email, DisplayName, Role, Status string
}

func (e env) account(t *testing.T, sub string) account {
	t.Helper()
	var a account
	err := e.owner.QueryRow(t.Context(), `
SELECT id, email, display_name, role, status FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2`, e.idp.issuer(), sub).
		Scan(&a.ID, &a.Email, &a.DisplayName, &a.Role, &a.Status)
	if err != nil {
		t.Fatalf("read account of %s: %v", sub, err)
	}
	return a
}

type auditRow struct {
	Action, Outcome, Kind, Method string
	ActorID                       string
	ChangedFields                 []string
}

// audit returns the entries of the audit log other than the reads, oldest
// first.
func (e env) audit(t *testing.T) []auditRow {
	t.Helper()
	rows, err := e.owner.Query(t.Context(), `
SELECT action, outcome, actor_kind, auth_method, coalesce(actor_user_id::text, ''), changed_fields
FROM audit_entries ORDER BY occurred_at`)
	if err != nil {
		t.Fatalf("read audit entries: %v", err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.Action, &r.Outcome, &r.Kind, &r.Method, &r.ActorID, &r.ChangedFields); err != nil {
			t.Fatalf("scan audit entry: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read audit entries: %v", err)
	}
	return out
}

// sessionOf returns the account of the session cookie, as the console sees it.
func (e env) sessionOf(t *testing.T, cookie *http.Cookie) (status int, u map[string]any) {
	t.Helper()
	r := e.get(t, "/api/v1/session", cookie)
	if r.status != http.StatusOK {
		return r.status, nil
	}
	var body struct {
		User map[string]any `json:"user"`
	}
	if err := json.Unmarshal(r.body, &body); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	return r.status, body.User
}

func TestAuthorize_SendsTheBrowserToTheProvider(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.discover(t)
	r := e.begin(t)

	u, err := url.Parse(r.location)
	if err != nil {
		t.Fatalf("location %q: %v", r.location, err)
	}
	q := u.Query()
	if got := q.Get("scope"); got != "openid email profile" {
		t.Errorf("scope = %q, want %q", got, "openid email profile")
	}
	for _, name := range []string{"state", "nonce", "code_challenge"} {
		if len(q.Get(name)) != 43 {
			t.Errorf("%s = %q, want 43 characters of 256 random bits", name, q.Get(name))
		}
	}
	if q.Get("state") == q.Get("nonce") {
		t.Error("state and nonce are equal, want independent values")
	}

	c := r.cookies[oidc.CookieName]
	if !strings.HasPrefix(c.Name, "__Host-") || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" ||
		c.Domain != "" || c.MaxAge != 600 || len(c.Value) != 43 {
		t.Errorf("cookie = %+v, want __Host-, Secure, HttpOnly, SameSite=Lax, Path=/, Max-Age=600 and a 43-character value", c)
	}
	// Neither the state, which travels through the provider, nor the token of
	// the browser can be read from the database.
	if n := e.count(t, `SELECT count(*) FROM oidc_logins WHERE state_hash = sha256(convert_to($1, 'UTF8')) AND browser_hash = sha256(convert_to($2, 'UTF8'))`,
		q.Get("state"), c.Value); n != 1 {
		t.Errorf("%d sign-ins stored under the hashes of state and cookie, want 1", n)
	}
}

// Until the provider has been discovered, a sign-in cannot start, and the
// answer says to retry.
func TestAuthorize_UnavailableUntilTheProviderIsDiscovered(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	r := e.get(t, "/api/v1/oidc/authorize")
	if r.status != http.StatusServiceUnavailable || r.cookies[oidc.CookieName] != nil {
		t.Errorf("authorize before discovery: status %d, cookies %v; want 503 without a cookie", r.status, r.cookies)
	}
	e.discover(t)
	e.begin(t)
}

// Without a provider, the routes answer like an unknown route.
func TestRoutes_NotFoundWithoutAProvider(t *testing.T) {
	t.Parallel()

	_, consoleDBURL := schematest.Console(t)
	pool := schematest.Open(t, consoleDBURL)
	h, err := console.New(t.Context(), console.Options{
		Logger: slog.New(slog.DiscardHandler), DB: pool, Setup: setup.NewService(pool), Hasher: hasher,
		Sessions: session.Config{IdleTimeout: time.Hour, MaxAge: 12 * time.Hour}, Keys: secretboxtest.Keyring(t), ConsoleURL: consoleURL, TriggerURL: "https://t.example.net",
	})
	if err != nil {
		t.Fatalf("console.New() error = %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	e := env{srv: srv}
	for _, path := range []string{"/api/v1/oidc/authorize", callbackPath("state", "code")} {
		if r := e.get(t, path); r.status != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", path, r.status)
		}
	}
}

func TestSignIn_CreatesTheAccountAtTheFirstSignIn(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.discover(t)
	cookie := e.mustSignIn(t, "jane", []string{"other", "auditors"})

	a := e.account(t, "jane")
	if a.Email != "jane@example.com" || a.DisplayName != "User jane" || a.Role != "viewer" || a.Status != "active" {
		t.Errorf("account = %+v, want jane@example.com, User jane, viewer, active", a)
	}
	status, u := e.sessionOf(t, cookie)
	if status != http.StatusOK || u["id"] != a.ID || u["sign_in_method"] != "oidc" {
		t.Errorf("session: status %d, user %v; want 200 with the new account and sign_in_method oidc", status, u)
	}
	want := []auditRow{
		{Action: "user.create", Outcome: "success", Kind: "user", Method: "oidc", ActorID: a.ID, ChangedFields: []string{}},
		{Action: "session.create", Outcome: "success", Kind: "user", Method: "oidc", ActorID: a.ID, ChangedFields: []string{}},
	}
	if got := e.audit(t); !slices.EqualFunc(got, want, equalRow) {
		t.Errorf("audit log = %+v, want %+v", got, want)
	}

	// The second sign-in finds the account by its identity.
	e.mustSignIn(t, "jane", []string{"auditors"}, withClaims(map[string]any{"email": "jane.doe@example.com"}))
	if n := e.count(t, `SELECT count(*) FROM users WHERE oidc_subject = 'jane'`); n != 1 {
		t.Errorf("%d accounts of the identity, want 1", n)
	}
	if a := e.account(t, "jane"); a.Email != "jane@example.com" {
		t.Errorf("email = %q after the provider reported another, want it unchanged", a.Email)
	}
}

func equalRow(a, b auditRow) bool {
	return a.Action == b.Action && a.Outcome == b.Outcome && a.Kind == b.Kind && a.Method == b.Method &&
		a.ActorID == b.ActorID && slices.Equal(a.ChangedFields, b.ChangedFields)
}

// The role follows the groups with every sign-in, the highest one wins, and a
// change of role ends the other sessions of the account.
func TestSignIn_RoleFollowsTheGroups(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.discover(t)
	first := e.mustSignIn(t, "jane", []string{"nyktus-viewers"})
	e.mustSignIn(t, "jane", []string{"nyktus-viewers"})
	if status, _ := e.sessionOf(t, first); status != http.StatusOK {
		t.Fatalf("first session after a sign-in without changes: status %d, want 200", status)
	}

	third := e.mustSignIn(t, "jane", []string{"nyktus-viewers", "nyktus-admins", "nyktus-users"},
		withClaims(map[string]any{"name": "Jane Doe"}))
	a := e.account(t, "jane")
	if a.Role != "admin" || a.DisplayName != "Jane Doe" {
		t.Errorf("account = %+v, want role admin and the new name", a)
	}
	if status, _ := e.sessionOf(t, first); status != http.StatusUnauthorized {
		t.Errorf("other session after a change of role: status %d, want 401", status)
	}
	if status, u := e.sessionOf(t, third); status != http.StatusOK || u["role"] != "admin" {
		t.Errorf("new session: status %d, user %v; want 200 as admin", status, u)
	}

	entries := e.audit(t)
	updates := slices.DeleteFunc(slices.Clone(entries), func(r auditRow) bool { return r.Action != "user.update" })
	want := []auditRow{{
		Action: "user.update", Outcome: "success", Kind: "user", Method: "oidc", ActorID: a.ID,
		ChangedFields: []string{"display_name", "role"},
	}}
	if !slices.EqualFunc(updates, want, equalRow) {
		t.Errorf("updates in the audit log = %+v, want %+v", updates, want)
	}

	// A new name alone leaves the sessions alone.
	e.mustSignIn(t, "jane", []string{"nyktus-admins"}, withClaims(map[string]any{"name": "Jane"}))
	if status, _ := e.sessionOf(t, third); status != http.StatusOK {
		t.Errorf("session after a change of name only: status %d, want 200", status)
	}
}

// A user in none of the groups cannot sign in, and the account is deactivated,
// so that adding the user to a group again by mistake does not let them in.
func TestSignIn_WithoutGroupDeactivatesTheAccount(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.discover(t)
	cookie := e.mustSignIn(t, "jane", []string{"nyktus-users"})
	a := e.account(t, "jane")

	wantRejected(t, e.signIn(t, "jane", []string{"other"}))
	if got := e.account(t, "jane"); got.Status != "deactivated" || got.Role != "user" {
		t.Errorf("account = %+v, want it deactivated with its role", got)
	}
	if status, _ := e.sessionOf(t, cookie); status != http.StatusUnauthorized {
		t.Errorf("session after the removal from the groups: status %d, want 401", status)
	}
	wantRejected(t, e.signIn(t, "jane", []string{"nyktus-users"}))

	entries := e.audit(t)
	want := []auditRow{
		{Action: "user.update", Outcome: "success", Kind: "user", Method: "oidc", ActorID: a.ID, ChangedFields: []string{"status"}},
		{Action: "session.create", Outcome: "failure", Kind: "user", Method: "oidc", ActorID: a.ID, ChangedFields: []string{}},
		{Action: "session.create", Outcome: "failure", Kind: "user", Method: "oidc", ActorID: a.ID, ChangedFields: []string{}},
	}
	if got := entries[len(entries)-3:]; !slices.EqualFunc(got, want, equalRow) {
		t.Errorf("audit log ends with %+v, want %+v", got, want)
	}
}

// The groups cannot demote or deactivate the last active administrator: the
// sign-in is rejected and the account stays as it is.
func TestSignIn_KeepsTheLastActiveAdministrator(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.discover(t)
	e.mustSignIn(t, "jane", []string{"nyktus-admins"})
	e.exec(t, `UPDATE users SET status = 'deactivated' WHERE email = 'ada@example.com'`)

	for name, groups := range map[string][]string{"demotion": {"nyktus-users"}, "no group": nil} {
		wantRejected(t, e.signIn(t, "jane", groups))
		if a := e.account(t, "jane"); a.Role != "admin" || a.Status != "active" {
			t.Errorf("%s: account = %+v, want it an active admin", name, a)
		}
	}
	e.mustSignIn(t, "jane", []string{"nyktus-admins"})
}

// Rejections of identities without an account are recorded without naming
// them: the subject and the address appear only in the application log.
func TestSignIn_RejectsIdentitiesThatMayNotHaveAnAccount(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.discover(t)
	e.exec(t, `INSERT INTO users (email, display_name, role, status) VALUES ('bob@example.com', 'Bob', 'viewer', 'pending')`)

	for name, opts := range map[string][]option{
		"address of another account": {withClaims(map[string]any{"email": "BOB@example.com"})},
		"no address":                 {withClaims(map[string]any{"email": nil})},
		"invalid address":            {withClaims(map[string]any{"email": "bob at example.com"})},
		"unverified address":         {withClaims(map[string]any{"email_verified": false})},
		"unverified address, string": {withClaims(map[string]any{"email_verified": "false"})},
		"address not said verified":  {withClaims(map[string]any{"email_verified": nil})},
	} {
		wantRejected(t, e.signIn(t, "mallory", []string{"nyktus-admins"}, opts...))
		if n := e.count(t, `SELECT count(*) FROM users WHERE oidc_subject = 'mallory'`); n != 0 {
			t.Errorf("%s: account created", name)
		}
	}
	wantRejected(t, e.signIn(t, "mallory", []string{"other"}))

	entries := e.audit(t)
	if len(entries) != 7 {
		t.Fatalf("%d audit entries, want one per rejection: %+v", len(entries), entries)
	}
	for _, r := range entries {
		if !equalRow(r, auditRow{Action: "session.create", Outcome: "failure", Kind: "anonymous", Method: "oidc", ChangedFields: []string{}}) {
			t.Errorf("audit entry = %+v, want an anonymous failure of session.create", r)
		}
	}
	// Some providers send the value as a string.
	e.mustSignIn(t, "mallory", []string{"nyktus-viewers"}, withClaims(map[string]any{"email_verified": "true"}))
}

// The first administrator is created with the setup token. The provider does
// not take its place, not even for its administrators.
func TestSignIn_WaitsForTheSetup(t *testing.T) {
	t.Parallel()

	e := newUndiscoveredEnv(t)
	e.discover(t)
	wantRejected(t, e.signIn(t, "jane", []string{"nyktus-admins"}))
	if n := e.count(t, `SELECT count(*) FROM users`); n != 0 {
		t.Errorf("%d accounts, want none before the setup", n)
	}
}

// A callback that does not prove an identity is rejected without a trace in
// the audit log, which records only users.
func TestCallback_RejectsSignInsThatProveNoIdentity(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.discover(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	groups := []string{"nyktus-admins"}

	tests := map[string]func(t *testing.T) response{
		"unknown state": func(t *testing.T) response {
			t.Helper()
			start := e.begin(t)
			_, code := e.idp.authorize(start.location, "jane", groups)
			return e.get(t, callbackPath("unknown", code), start.cookies[oidc.CookieName])
		},
		"cookie of another browser": func(t *testing.T) response {
			t.Helper()
			start, other := e.begin(t), e.begin(t)
			state, code := e.idp.authorize(start.location, "jane", groups)
			return e.get(t, callbackPath(state, code), other.cookies[oidc.CookieName])
		},
		"no cookie": func(t *testing.T) response {
			t.Helper()
			start := e.begin(t)
			state, code := e.idp.authorize(start.location, "jane", groups)
			return e.get(t, callbackPath(state, code))
		},
		"state used before": func(t *testing.T) response {
			t.Helper()
			start := e.begin(t)
			// The first use fails as well, so that no account exists.
			state, code := e.idp.authorize(start.location, "jane", groups, withClaims(map[string]any{"nonce": "x"}))
			e.get(t, callbackPath(state, code), start.cookies[oidc.CookieName])
			_, code = e.idp.authorize(start.location, "jane", groups)
			return e.get(t, callbackPath(state, code), start.cookies[oidc.CookieName])
		},
		"expired sign-in": func(t *testing.T) response {
			t.Helper()
			start := e.begin(t)
			state, code := e.idp.authorize(start.location, "jane", groups)
			e.exec(t, `UPDATE oidc_logins SET expires_at = clock_timestamp()`)
			return e.get(t, callbackPath(state, code), start.cookies[oidc.CookieName])
		},
		"error of the provider": func(t *testing.T) response {
			t.Helper()
			start := e.begin(t)
			state, _ := e.idp.authorize(start.location, "jane", groups)
			return e.get(t, oidc.CallbackPath+"?"+url.Values{"state": {state}, "error": {"access_denied"}}.Encode(), start.cookies[oidc.CookieName])
		},
		"unknown code":      e.callbackWithCode("not a code"),
		"another nonce":     e.callbackWith(groups, withClaims(map[string]any{"nonce": "another"})),
		"no nonce":          e.callbackWith(groups, withClaims(map[string]any{"nonce": nil})),
		"another issuer":    e.callbackWith(groups, withClaims(map[string]any{"iss": "https://idp.example.org"})),
		"another audience":  e.callbackWith(groups, withClaims(map[string]any{"aud": "another"})),
		"several audiences": e.callbackWith(groups, withClaims(map[string]any{"aud": []string{clientID, "another"}})),
		"issued to another": e.callbackWith(groups, withClaims(map[string]any{"aud": []string{clientID, "another"}, "azp": "another"})),
		"expired token":     e.callbackWith(groups, withClaims(map[string]any{"exp": time.Now().Add(-time.Minute).Unix()})),
		"signed by another": e.callbackWith(groups, signedBy(otherKey)),
		"empty subject":     e.callbackWith(groups, withClaims(map[string]any{"sub": ""})),
		"non-ASCII subject": e.callbackWith(groups, withClaims(map[string]any{"sub": "jäne"})),
		"wrong PKCE verifier": func(t *testing.T) response {
			t.Helper()
			start := e.begin(t)
			state, code := e.idp.authorize(start.location, "jane", groups)
			e.idp.mu.Lock()
			g := e.idp.grants[code]
			g.challenge = "another challenge"
			e.idp.grants[code] = g
			e.idp.mu.Unlock()
			return e.get(t, callbackPath(state, code), start.cookies[oidc.CookieName])
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			wantRejected(t, run(t))
		})
	}
	if n := e.count(t, `SELECT count(*) FROM users WHERE oidc_subject IS NOT NULL`); n != 0 {
		t.Errorf("%d accounts of the provider, want none", n)
	}
	if n := e.count(t, `SELECT count(*) FROM sessions`); n != 0 {
		t.Errorf("%d sessions, want none", n)
	}
	if entries := e.audit(t); len(entries) != 0 {
		t.Errorf("audit log = %+v, want it empty", entries)
	}
	// Each of them is an expected outcome, not a failure of the server.
	if n := e.errors.Load(); n != 0 {
		t.Errorf("%d records at level error, want none", n)
	}

	// A token for several audiences that names the console as the party it
	// was issued to is accepted.
	e.mustSignIn(t, "jane", groups, withClaims(map[string]any{"aud": []string{clientID, "another"}, "azp": clientID}))
}

func (e env) callbackWith(groups []string, opts ...option) func(t *testing.T) response {
	return func(t *testing.T) response {
		t.Helper()
		start := e.begin(t)
		state, code := e.idp.authorize(start.location, "jane", groups, opts...)
		return e.get(t, callbackPath(state, code), start.cookies[oidc.CookieName])
	}
}

func (e env) callbackWithCode(code string) func(t *testing.T) response {
	return func(t *testing.T) response {
		t.Helper()
		start := e.begin(t)
		state, _ := e.idp.authorize(start.location, "jane", nil)
		return e.get(t, callbackPath(state, code), start.cookies[oidc.CookieName])
	}
}

// A sign-in ends the session that the browser still holds, as the sign-in with
// a password does. The browser sends its session cookie, which is
// SameSite=Strict, when it starts the sign-in from a page of the console, but
// not when the provider sends it back from another site.
func TestSignIn_EndsThePreviousSessionOfTheBrowser(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.discover(t)
	previous := e.mustSignIn(t, "jane", []string{"nyktus-users"})

	start := e.get(t, "/api/v1/oidc/authorize", previous)
	state, code := e.idp.authorize(start.location, "john", []string{"nyktus-users"})
	r := e.get(t, callbackPath(state, code), start.cookies[oidc.CookieName])
	if r.cookies[session.CookieName] == nil {
		t.Fatalf("callback: status %d, location %q; want a new session", r.status, r.location)
	}
	if status, _ := e.sessionOf(t, previous); status != http.StatusUnauthorized {
		t.Errorf("previous session: status %d, want 401", status)
	}
	if a := e.account(t, "john"); a.Role != "user" {
		t.Errorf("account of the new session = %+v, want role user", a)
	}
}

// The sign-in locks the active administrators before it looks up the identity,
// in the order that every change of accounts takes. The lock keeps the last
// one when groups would demote it, and serializes concurrent first sign-ins of
// an identity, so that they create one account.
func TestSignIn_LocksTheAdministratorsFirst(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.discover(t)
	holder, err := e.owner.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = holder.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := holder.Exec(t.Context(), `SELECT FROM users WHERE role = 'admin' AND status = 'active' FOR UPDATE`); err != nil {
		t.Fatalf("lock administrators: %v", err)
	}

	start := e.begin(t)
	state, code := e.idp.authorize(start.location, "jane", []string{"nyktus-viewers"})
	done := make(chan response, 1)
	go func() { done <- e.get(t, callbackPath(state, code), start.cookies[oidc.CookieName]) }()
	waitForLockWaiter(t, e.owner, done)

	if err := holder.Commit(t.Context()); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if r := <-done; r.cookies[session.CookieName] == nil {
		t.Errorf("callback: status %d, location %q; want a session once the lock is free", r.status, r.location)
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
			t.Fatalf("the sign-in completed without waiting for the administrators: status %d, location %q", r.status, r.location)
		default:
		}
	}
}
