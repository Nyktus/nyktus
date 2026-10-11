// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc_test

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"nyktus.org/nyktus/internal/auth/oidc"
	"nyktus.org/nyktus/internal/auth/token"
)

// reauthenticate starts a reauthentication with the session cookie, which
// returns to /settings, and lets the provider confirm the user sub with groups.
func (e env) reauthenticate(t *testing.T, cookie *http.Cookie, sub string, groups []string, opts ...option) response {
	t.Helper()
	start := e.get(t, "/api/v1/oidc/reauthenticate?return_to=/settings", cookie)
	if start.status != http.StatusFound || start.cookies[oidc.CookieName] == nil {
		t.Fatalf("reauthenticate: status %d, body %s; want 302 with the cookie", start.status, start.body)
	}
	state, code := e.idp.authorize(start.location, sub, groups, opts...)
	return e.get(t, callbackPath(state, code), start.cookies[oidc.CookieName])
}

func (e env) reauthenticated(t *testing.T, cookie *http.Cookie) bool {
	t.Helper()
	return e.count(t, `SELECT count(*) FROM sessions WHERE token_hash = $1 AND reauthenticated_at IS NOT NULL`,
		token.Hash(cookie.Value)) == 1
}

func createKey(t *testing.T, e env, cookie *http.Cookie) int {
	t.Helper()
	body := `{"name": "k", "scopes": ["audit:read"], "expires_at": "` + time.Now().Add(time.Hour).Format(time.RFC3339) + `"}`
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, e.srv.URL+"/api/v1/api-keys", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookie.Name+"="+cookie.Value)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// The provider asks for the credentials again, and the session may then
// perform the actions that a password confirms.
func TestReauthenticate_ConfirmsTheSession(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.discover(t)
	cookie := e.mustSignIn(t, "jane", []string{"nyktus-admins"})
	if status := createKey(t, e, cookie); status != http.StatusForbidden {
		t.Fatalf("create key before the reauthentication: status %d, want 403", status)
	}

	start := e.get(t, "/api/v1/oidc/reauthenticate?return_to=%2Fsettings%2Fapi-keys%3Ftab%3D1", cookie)
	q := mustQuery(t, start.location)
	if q.Get("prompt") != "login" || q.Get("max_age") != "0" {
		t.Errorf("prompt = %q, max_age = %q; want login and 0", q.Get("prompt"), q.Get("max_age"))
	}
	state, code := e.idp.authorize(start.location, "jane", []string{"nyktus-admins"})
	r := e.get(t, callbackPath(state, code), start.cookies[oidc.CookieName])
	if r.status != http.StatusSeeOther || r.location != "/settings/api-keys?tab=1" || r.cookies["__Host-nyktus_session"] != nil {
		t.Errorf("callback: status %d, location %q, cookies %v; want 303 to the page without a new session", r.status, r.location, r.cookies)
	}
	if !e.reauthenticated(t, cookie) {
		t.Fatal("the session is not marked")
	}
	if status := createKey(t, e, cookie); status != http.StatusCreated {
		t.Errorf("create key after the reauthentication: status %d, want 201", status)
	}

	a := e.account(t, "jane")
	var found bool
	for _, row := range e.audit(t) {
		if row.Action == "session.reauthenticate" {
			found = equalRow(row, auditRow{
				Action: "session.reauthenticate", Outcome: "success", Kind: "user", Method: "oidc",
				ActorID: a.ID, ChangedFields: []string{},
			})
		}
	}
	if !found {
		t.Errorf("audit log = %+v, want a successful session.reauthenticate of the account", e.audit(t))
	}
}

func mustQuery(t *testing.T, location string) url.Values {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("location %q: %v", location, err)
	}
	return u.Query()
}

// A reauthentication that does not confirm the user of the session afresh,
// with the role of the account, leaves the session as it is.
func TestReauthenticate_RejectsWhatDoesNotConfirmTheUser(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.discover(t)
	cookie := e.mustSignIn(t, "jane", []string{"nyktus-admins"})
	e.mustSignIn(t, "john", []string{"nyktus-admins"})
	jane := e.account(t, "jane")
	admins := []string{"nyktus-admins"}

	for name, run := range map[string]func(t *testing.T) response{
		"another user": func(t *testing.T) response {
			t.Helper()
			return e.reauthenticate(t, cookie, "john", admins)
		},
		"no auth_time": func(t *testing.T) response {
			t.Helper()
			return e.reauthenticate(t, cookie, "jane", admins, withClaims(map[string]any{"auth_time": nil}))
		},
		"credentials not asked again": func(t *testing.T) response {
			t.Helper()
			old := time.Now().Add(-2 * time.Minute).Unix()
			return e.reauthenticate(t, cookie, "jane", admins, withClaims(map[string]any{"auth_time": old}))
		},
		"other groups": func(t *testing.T) response {
			t.Helper()
			return e.reauthenticate(t, cookie, "jane", []string{"nyktus-users"})
		},
		"no group": func(t *testing.T) response { t.Helper(); return e.reauthenticate(t, cookie, "jane", nil) },
	} {
		t.Run(name, func(t *testing.T) {
			r := run(t)
			if r.status != http.StatusSeeOther || r.location != "/settings#error=reauthentication" {
				t.Errorf("callback: status %d, location %q; want 303 to /settings#error=reauthentication", r.status, r.location)
			}
		})
	}
	if e.reauthenticated(t, cookie) {
		t.Error("the session is marked")
	}
	if a := e.account(t, "jane"); a.Role != "admin" || a.Status != "active" {
		t.Errorf("account = %+v, want it unchanged", a)
	}
	if status, _ := e.sessionOf(t, cookie); status != http.StatusOK {
		t.Errorf("session: status %d, want it to stay", status)
	}
	failures := slices.DeleteFunc(e.audit(t), func(r auditRow) bool { return r.Action != "session.reauthenticate" })
	if len(failures) != 5 {
		t.Fatalf("%d reauthentications recorded, want 5: %+v", len(failures), failures)
	}
	for _, r := range failures {
		if !equalRow(r, auditRow{
			Action: "session.reauthenticate", Outcome: "failure", Kind: "user", Method: "oidc", ActorID: jane.ID,
			ChangedFields: []string{},
		}) {
			t.Errorf("audit entry = %+v, want a failure of the account of the session", r)
		}
	}
	if n := e.errors.Load(); n != 0 {
		t.Errorf("%d records at level error, want none", n)
	}
}

// A reauthentication of a session that ended meanwhile confirms nothing and
// names nobody.
func TestReauthenticate_OfAnEndedSession(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.discover(t)
	cookie := e.mustSignIn(t, "jane", []string{"nyktus-admins"})
	start := e.get(t, "/api/v1/oidc/reauthenticate?return_to=/settings", cookie)
	state, code := e.idp.authorize(start.location, "jane", []string{"nyktus-admins"})
	e.exec(t, `DELETE FROM sessions`)

	r := e.get(t, callbackPath(state, code), start.cookies[oidc.CookieName])
	if r.status != http.StatusSeeOther || r.location != "/sign-in#error=oidc" {
		t.Errorf("callback: status %d, location %q; want 303 to the sign-in page", r.status, r.location)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'session.reauthenticate'`); n != 0 {
		t.Errorf("%d reauthentications recorded, want none", n)
	}
}

func TestReauthenticate_RejectsInvalidRequests(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.discover(t)
	cookie := e.mustSignIn(t, "jane", []string{"nyktus-admins"})

	for _, returnTo := range []string{
		"//evil.example.com", "https://evil.example.com", "/\\evil.example.com", "/a#b", "/a b", "settings",
		"/" + strings.Repeat("a", 512),
	} {
		if r := e.get(t, "/api/v1/oidc/reauthenticate?"+url.Values{"return_to": {returnTo}}.Encode(), cookie); r.status != http.StatusBadRequest {
			t.Errorf("return_to %q: status %d, want 400", returnTo, r.status)
		}
	}
	if r := e.get(t, "/api/v1/oidc/reauthenticate"); r.status != http.StatusUnauthorized {
		t.Errorf("without a session: status %d, want 401", r.status)
	}
	// The local administrator confirms with the password.
	if r := e.get(t, "/api/v1/oidc/reauthenticate", e.localSession(t)); r.status != http.StatusConflict ||
		!strings.Contains(string(r.body), "not_oidc_account") {
		t.Errorf("local account: status %d, body %s; want 409 not_oidc_account", r.status, r.body)
	}
	if n := e.count(t, `SELECT count(*) FROM oidc_logins WHERE purpose = 'reauthentication'`); n != 0 {
		t.Errorf("%d reauthentications started, want none", n)
	}

	// Without a return path, the browser returns to the start page.
	start := e.get(t, "/api/v1/oidc/reauthenticate", cookie)
	state, code := e.idp.authorize(start.location, "jane", []string{"nyktus-admins"})
	if r := e.get(t, callbackPath(state, code), start.cookies[oidc.CookieName]); r.location != "/" {
		t.Errorf("callback: location %q, want /", r.location)
	}
}

// localSession starts a session of the local administrator ada@example.com.
func (e env) localSession(t *testing.T) *http.Cookie {
	t.Helper()
	tok, err := token.New()
	if err != nil {
		t.Fatalf("token.New() error = %v", err)
	}
	e.exec(t, `INSERT INTO sessions (token_hash, user_id) SELECT $1, id FROM users WHERE email = 'ada@example.com'`, token.Hash(tok))
	return &http.Cookie{Name: "__Host-nyktus_session", Value: tok, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

func TestValidReturnTo(t *testing.T) {
	t.Parallel()

	for path, want := range map[string]bool{
		"/":                            true,
		"/settings/api-keys":           true,
		"/users?cursor=a%2Fb&x=1":      true,
		"":                             false,
		"settings":                     false,
		"//evil.example.com":           false,
		"/\\evil.example.com":          false,
		"https://evil.example.com":     false,
		"/a#b":                         false,
		"/a\\b":                        false,
		"/a b":                         false,
		"/a\tb":                        false,
		"/ä":                           false,
		"/" + strings.Repeat("a", 511): true,
		"/" + strings.Repeat("a", 512): false,
	} {
		if got := oidc.ValidReturnTo(path); got != want {
			t.Errorf("ValidReturnTo(%q) = %v, want %v", path, got, want)
		}
	}
}

// The schema keeps a reauthentication from returning to another site, and
// each purpose to its own columns, also if the console misses a case.
func TestSchema_RejectsInvalidSignIns(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.exec(t, `INSERT INTO sessions (token_hash, user_id) SELECT sha256('s'), id FROM users`)
	insert := func(purpose, previous, session, returnTo string) error {
		_, err := e.owner.Exec(t.Context(), `
INSERT INTO oidc_logins (state_hash, browser_hash, nonce, code_verifier, purpose, previous_session_hash, session_id, return_to)
SELECT sha256(gen_random_uuid()::text::bytea), sha256('b'), repeat('n', 43), repeat('v', 43), $1,
	CASE WHEN $2 = '' THEN NULL ELSE sha256($2::bytea) END,
	CASE WHEN $3 = '' THEN NULL ELSE (SELECT id FROM sessions) END,
	nullif($4, '')`, purpose, previous, session, returnTo)
		return err
	}
	for _, tc := range []struct {
		name, purpose, previous, session, returnTo, constraint string
	}{
		{"unknown purpose", "other", "", "", "", "oidc_logins_purpose_check"},
		{"sign-in with a session", "sign_in", "", "x", "", "oidc_logins_purpose_check"},
		{"sign-in with a return path", "sign_in", "", "", "/", "oidc_logins_purpose_check"},
		{"reauthentication without a session", "reauthentication", "", "", "/", "oidc_logins_purpose_check"},
		{"reauthentication without a return path", "reauthentication", "", "x", "", "oidc_logins_purpose_check"},
		{"reauthentication with a previous session", "reauthentication", "p", "x", "/", "oidc_logins_purpose_check"},
		{"protocol-relative", "reauthentication", "", "x", "//evil.example.com", "oidc_logins_return_to_check"},
		{"backslash", "reauthentication", "", "x", "/\\evil.example.com", "oidc_logins_return_to_check"},
		{"URL", "reauthentication", "", "x", "https://evil.example.com", "oidc_logins_return_to_check"},
		{"fragment", "reauthentication", "", "x", "/a#b", "oidc_logins_return_to_check"},
		{"space", "reauthentication", "", "x", "/a b", "oidc_logins_return_to_check"},
	} {
		err := insert(tc.purpose, tc.previous, tc.session, tc.returnTo)
		if err == nil || !strings.Contains(err.Error(), tc.constraint) {
			t.Errorf("%s: error = %v, want a violation of %s", tc.name, err, tc.constraint)
		}
	}
	for _, tc := range []struct{ purpose, previous, session, returnTo string }{
		{"sign_in", "", "", ""}, {"sign_in", "p", "", ""}, {"reauthentication", "", "x", "/"}, {"reauthentication", "", "x", "/users?x=1"},
	} {
		if err := insert(tc.purpose, tc.previous, tc.session, tc.returnTo); err != nil {
			t.Errorf("%+v: error = %v, want nil", tc, err)
		}
	}
}
