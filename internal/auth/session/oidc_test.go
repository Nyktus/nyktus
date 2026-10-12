// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/auth/setup"
	"nyktus.org/nyktus/internal/auth/token"
	"nyktus.org/nyktus/internal/console"
	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
)

// createOIDCUser inserts an active account of the identity provider, which
// has no password, and returns its ID.
func createOIDCUser(t *testing.T, d testDB, email, role string) string {
	t.Helper()
	var id string
	err := d.owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, oidc_issuer, oidc_subject)
VALUES ($1, 'Test User', $2, 'active', 'https://idp.example.com', $1)
RETURNING id`, email, role).Scan(&id)
	if err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	return id
}

// sessionOf starts a session of the account id, as the sign-in through the
// provider does, and returns its cookie.
func sessionOf(t *testing.T, d testDB, id string) *http.Cookie {
	t.Helper()
	tok, err := token.New()
	if err != nil {
		t.Fatalf("token.New() error = %v", err)
	}
	d.exec(t, `INSERT INTO sessions (token_hash, user_id) VALUES ($1, $2)`, token.Hash(tok), id)
	return clientCookie(tok)
}

// startConsoleWith starts the console with cfg.
func startConsoleWith(t *testing.T, d testDB, cfg session.Config) *httptest.Server {
	t.Helper()
	h, err := console.New(t.Context(), console.Options{
		Logger:         slog.New(slog.DiscardHandler),
		DB:             d.console,
		Setup:          setup.NewService(d.console),
		Hasher:         hasher,
		Sessions:       cfg,
		Keys:           secretboxtest.Keyring(t),
		ConsoleURL:     origin,
		TriggerURL:     "https://t.example.net",
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	})
	if err != nil {
		t.Fatalf("console.New() error = %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// While users sign in through the identity provider, only administrators sign
// in with a password by default, or nobody. Any other account is rejected like a wrong password,
// after the same work, so that the answer reveals neither the password nor the
// role, and a lock is revealed to nobody.
func TestSignIn_OnlyAdministratorsUsePasswordsWithAnIdentityProvider(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	cfg := testSessions
	cfg.LocalLogin = session.LocalLoginAdmins
	srv := startConsoleWith(t, d, cfg)
	createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	createUser(t, d, "uma@example.com", "user", "active", testPassword)
	createUser(t, d, "vic@example.com", "viewer", "active", testPassword)
	createUser(t, d, "locked@example.com", "user", "active", testPassword)
	d.exec(t, `UPDATE users SET locked_until = clock_timestamp() + interval '10 minutes' WHERE email = 'locked@example.com'`)
	// The viewer sets up the factor while every account signs in with a
	// password.
	plain := startConsole(t, d)
	enableTOTP(t, plain, d, signIn(t, plain, "vic@example.com", testPassword, nil).cookie)

	reference := signIn(t, srv, "nobody@example.com", testPassword, nil)
	for name, email := range map[string]string{
		"user, correct password":             "uma@example.com",
		"viewer with TOTP, correct password": "vic@example.com",
		"locked user, correct password":      "locked@example.com",
	} {
		t.Run(name, func(t *testing.T) {
			r := signIn(t, srv, email, testPassword, nil)
			if got, want := normalized(t, r), normalized(t, reference); got != want {
				t.Errorf("response = %s, want the response for an unknown account: %s", got, want)
			}
		})
	}
	if n := d.count(t, `SELECT count(*) FROM sign_in_challenges`); n != 0 {
		t.Errorf("%d challenges, want none for an account that may not sign in with a password", n)
	}
	if n := d.count(t, `
SELECT count(*) FROM audit_entries AS a JOIN users AS u ON u.id = a.actor_user_id
WHERE a.action = 'session.create' AND a.outcome = 'failure' AND u.email = 'uma@example.com'`); n != 1 {
		t.Errorf("%d recorded failures of the user, want 1", n)
	}
	if n := d.count(t, `SELECT failed_logins FROM users WHERE email = 'uma@example.com'`); n != 0 {
		t.Errorf("failed_logins = %d after the correct password, want 0", n)
	}
	if r := signIn(t, srv, "ada@example.com", testPassword, nil); r.status != http.StatusOK {
		t.Errorf("administrator: status %d, want 200", r.status)
	}

	cfg.LocalLogin = session.LocalLoginOff
	off := startConsoleWith(t, d, cfg)
	if got, want := normalized(t, signIn(t, off, "ada@example.com", testPassword, nil)), normalized(t, reference); got != want {
		t.Errorf("administrator without password sign-in: response = %s, want the response for an unknown account: %s", got, want)
	}
}

// An account of the identity provider has no password, so a sign-in with one
// is rejected like any wrong password, and every change that the password
// confirms is refused instead of failing.
func TestOIDCAccount_HasNoPassword(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	srv := startConsole(t, d)
	createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	jane := createOIDCUser(t, d, "jane@example.com", "admin")

	reference := signIn(t, srv, "nobody@example.com", testPassword, nil)
	if got, want := normalized(t, signIn(t, srv, "jane@example.com", testPassword, nil)), normalized(t, reference); got != want {
		t.Errorf("sign-in with a password = %s, want the response for an unknown account: %s", got, want)
	}

	cookie := sessionOf(t, d, jane)
	r := send(t, srv, http.MethodGet, "/api/v1/session", "", cookie, nil)
	if user, _ := r.body["user"].(map[string]any); r.status != http.StatusOK || user["sign_in_method"] != "oidc" {
		t.Errorf("session: %d %v, want 200 with sign_in_method oidc", r.status, r.body)
	}
	for name, req := range map[string]struct{ method, path, body string }{
		"change password": {
			http.MethodPut, "/api/v1/session/password",
			mustJSON(t, map[string]string{"current_password": testPassword, "new_password": "another horse battery"}),
		},
		"set up TOTP": {http.MethodPost, "/api/v1/session/totp", mustJSON(t, map[string]string{"password": testPassword})},
	} {
		r := send(t, srv, req.method, req.path, req.body, cookie, nil)
		if r.status != http.StatusConflict || errorCode(r) != "oidc_account" {
			t.Errorf("%s: %d %v, want 409 oidc_account", name, r.status, r.body)
		}
	}
	if n := d.count(t, `SELECT count(*) FROM users WHERE id = $1 AND password_hash IS NULL`, jane); n != 1 {
		t.Error("the account has a password, want none")
	}
}

// An administrator of the identity provider confirms the creation of a key by
// signing in there again, within the last five minutes, instead of with a
// password.
func TestAPIKey_AdministratorOfTheProviderConfirmsBySigningInAgain(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	srv := startConsole(t, d)
	jane := createOIDCUser(t, d, "jane@example.com", "admin")
	cookie := sessionOf(t, d, jane)
	// The sessions began before the times of the reauthentications below.
	backdate := func() { d.exec(t, `UPDATE sessions SET created_at = clock_timestamp() - interval '10 minutes'`) }
	backdate()
	body := mustJSON(t, map[string]any{
		"name": "k", "scopes": []string{"audit:read"}, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
	})

	for _, tc := range []struct{ name, at string }{
		{"never", "NULL"},
		{"six minutes ago", "clock_timestamp() - interval '6 minutes'"},
		{"in another session", ""},
	} {
		d.exec(t, `UPDATE sessions SET reauthenticated_at = NULL`)
		if tc.at == "" {
			other := sessionOf(t, d, jane)
			backdate()
			d.exec(t, `UPDATE sessions SET reauthenticated_at = clock_timestamp() WHERE token_hash = $1`, token.Hash(other.Value))
		} else {
			d.exec(t, `UPDATE sessions SET reauthenticated_at = `+tc.at)
		}
		r := send(t, srv, http.MethodPost, "/api/v1/api-keys", body, cookie, nil)
		if r.status != http.StatusForbidden || errorCode(r) != "reauthentication_required" {
			t.Errorf("%s: %d %v, want 403 reauthentication_required", tc.name, r.status, r.body)
		}
	}
	if n := d.count(t, `SELECT count(*) FROM api_keys`); n != 0 {
		t.Fatalf("%d keys created, want 0", n)
	}

	d.exec(t, `UPDATE sessions SET reauthenticated_at = clock_timestamp() - interval '4 minutes' WHERE token_hash = $1`,
		token.Hash(cookie.Value))
	for range 2 {
		if r := send(t, srv, http.MethodPost, "/api/v1/api-keys", body, cookie, nil); r.status != http.StatusCreated {
			t.Errorf("after signing in again: %d %v, want 201 for every key within the window", r.status, r.body)
		}
	}
	if n := d.count(t, `
SELECT count(*) FROM audit_entries WHERE action = 'api_key.create' AND outcome = 'success' AND actor_user_id = $1 AND auth_method = 'session'`,
		jane); n != 2 {
		t.Errorf("%d creations recorded, want 2", n)
	}
}
