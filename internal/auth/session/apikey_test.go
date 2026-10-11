// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nyktus.org/nyktus/internal/auth/apikey"
)

// createKey creates an API key of the team with the scope audit:read, as the
// administrator signed in with cookie, and returns its identifier and the key.
func createKey(t *testing.T, srv *httptest.Server, cookie *http.Cookie) (id, key string) {
	t.Helper()
	r := send(t, srv, http.MethodPost, "/api/v1/api-keys", keyBody("SIEM export", "audit:read", testPassword, 30*24*time.Hour), cookie, nil)
	id, _ = r.body["id"].(string)
	key, _ = r.body["key"].(string)
	if r.status != http.StatusCreated || id == "" || !strings.HasPrefix(key, apikey.Prefix) {
		t.Fatalf("create API key: %d %v", r.status, r.body)
	}
	return id, key
}

func keyBody(name, scope, pw string, lifetime time.Duration) string {
	b, err := json.Marshal(map[string]any{
		"name": name, "scopes": []string{scope}, "password": pw,
		"expires_at": time.Now().Add(lifetime).Format(time.RFC3339),
	})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func bearer(key string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + key}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return string(b)
}

// A key belongs to the team: it acts on its own, in the audit log too, and
// outlives the administrator who created it.
func TestAPIKey_IsShownOnceAndActsForTheTeam(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	ada := createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	createUser(t, d, "bob@example.com", "admin", "active", testPassword)
	srv := startConsole(t, d)
	c := mustSignIn(t, srv)
	id, key := createKey(t, srv, c)

	list := send(t, srv, http.MethodGet, "/api/v1/api-keys", "", c, nil)
	keys, _ := list.body["api_keys"].([]any)
	if list.status != http.StatusOK || len(keys) != 1 || strings.Contains(mustJSON(t, list.body), key) ||
		keys[0].(map[string]any)["created_by"] != ada {
		t.Fatalf("list: %d %v, want the key with its creator and without its secret", list.status, list.body)
	}

	if r := send(t, srv, http.MethodGet, "/api/v1/audit-entries", "", nil, bearer(key)); r.status != http.StatusOK {
		t.Fatalf("read the audit log with the key: %d %v", r.status, r.body)
	}
	if n := d.count(t, `SELECT count(*) FROM api_keys WHERE id = $1 AND last_used_at IS NOT NULL`, id); n != 1 {
		t.Error("the use of the key is not recorded")
	}
	if n := d.count(t, `
SELECT count(*) FROM audit_entries WHERE action = 'audit.read' AND outcome = 'success' AND actor_kind = 'api_key'
	AND auth_method = 'api_key' AND api_key_id = $1 AND actor_user_id IS NULL AND actor_display_name = 'SIEM export'`, id); n != 1 {
		t.Errorf("%d reads through the key recorded, want 1", n)
	}
	if n := d.count(t, `
SELECT count(*) FROM audit_entries WHERE action = 'api_key.create' AND outcome = 'success' AND actor_user_id = $1
	AND auth_method = 'session' AND resource_type = 'api_key' AND resource_id = $2`, ada, id); n != 1 {
		t.Errorf("%d creations recorded, want 1", n)
	}

	// Demoting, deactivating or deleting the creator leaves the key working.
	d.exec(t, `UPDATE users SET role = 'viewer' WHERE id = $1`, ada)
	d.exec(t, `UPDATE users SET status = 'deactivated' WHERE id = $1`, ada)
	d.exec(t, `DELETE FROM users WHERE id = $1`, ada)
	if r := send(t, srv, http.MethodGet, "/api/v1/audit-entries", "", nil, bearer(key)); r.status != http.StatusOK {
		t.Errorf("after deleting the creator: status %d, want 200", r.status)
	}
}

// A key holds its scopes and nothing else.
func TestAPIKey_HoldsOnlyItsScopes(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	srv := startConsole(t, d)
	id, key := createKey(t, srv, mustSignIn(t, srv))

	if r := send(t, srv, http.MethodGet, "/api/v1/users", "", nil, bearer(key)); r.status != http.StatusForbidden {
		t.Errorf("route beyond the scopes: status %d, want 403", r.status)
	}
	if n := d.count(t, `
SELECT count(*) FROM audit_entries WHERE action = 'users.read' AND outcome = 'denied' AND actor_kind = 'api_key' AND api_key_id = $1`, id); n != 1 {
		t.Errorf("%d denials recorded for the key, want 1", n)
	}
}

// Only administrators manage keys, and keys carry only scopes that keys may
// carry, for at most three years.
func TestAPIKey_ManagedByAdministratorsWithinTheLimits(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	createUser(t, d, "uma@example.com", "user", "active", testPassword)
	createUser(t, d, "vic@example.com", "viewer", "active", testPassword)
	srv := startConsole(t, d)
	admin := mustSignIn(t, srv)

	for _, email := range []string{"uma@example.com", "vic@example.com"} {
		c := signIn(t, srv, email, testPassword, nil).cookie
		for _, tt := range []struct{ method, path, body string }{
			{http.MethodGet, "/api/v1/api-keys", ""},
			{http.MethodPost, "/api/v1/api-keys", keyBody("k", "audit:read", testPassword, time.Hour)},
			{http.MethodDelete, "/api/v1/api-keys/00000000-0000-4000-8000-000000000000", ""},
		} {
			if r := send(t, srv, tt.method, tt.path, tt.body, c, nil); r.status != http.StatusForbidden {
				t.Errorf("%s: %s %s: status %d, want 403", email, tt.method, tt.path, r.status)
			}
		}
	}

	for _, tt := range []struct {
		name     string
		scope    string
		lifetime time.Duration
	}{
		{"users:write", "users:write", time.Hour},
		{"users:read", "users:read", time.Hour},
		{"api_keys:write", "api_keys:write", time.Hour},
		{"wildcard", "*:*", time.Hour},
		{"beyond three years", "audit:read", apikey.MaxLifetime + 24*time.Hour},
		{"in the past", "audit:read", -time.Hour},
	} {
		r := send(t, srv, http.MethodPost, "/api/v1/api-keys", keyBody("k", tt.scope, testPassword, tt.lifetime), admin, nil)
		if r.status != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", tt.name, r.status)
		}
	}
	if n := d.count(t, `SELECT count(*) FROM api_keys`); n != 0 {
		t.Errorf("%d keys created, want 0", n)
	}
	r := send(t, srv, http.MethodPost, "/api/v1/api-keys", keyBody("long-lived", "audit:read", testPassword, apikey.MaxLifetime-24*time.Hour), admin, nil)
	if r.status != http.StatusCreated {
		t.Errorf("key for almost three years: %d %v, want 201", r.status, r.body)
	}
}

// A key outlives the session, so creating one takes the password, and a wrong
// one counts as a failed sign-in.
func TestAPIKey_CreateRequiresThePassword(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	ada := createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	srv := startConsole(t, d)
	c := mustSignIn(t, srv)

	r := send(t, srv, http.MethodPost, "/api/v1/api-keys", keyBody("k", "audit:read", "wrong horse battery", time.Hour), c, nil)
	if r.status != http.StatusForbidden || errorCode(r) != "wrong_password" {
		t.Errorf("wrong password: %d %v, want 403 wrong_password", r.status, r.body)
	}
	if n := d.count(t, `SELECT failed_logins FROM users WHERE id = $1`, ada); n != 1 {
		t.Errorf("failed_logins = %d, want 1", n)
	}
	if n := d.count(t, `
SELECT count(*) FROM audit_entries WHERE action = 'api_key.create' AND outcome = 'failure' AND resource_id = $1`, ada); n != 1 {
		t.Errorf("%d failures recorded, want 1", n)
	}
	if n := d.count(t, `SELECT count(*) FROM api_keys`); n != 0 {
		t.Errorf("%d keys created, want 0", n)
	}
}

// An expired, revoked or malformed key is answered like a request without
// credentials and not recorded.
func TestAPIKey_InvalidKeysAreUnauthenticated(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	srv := startConsole(t, d)
	c := mustSignIn(t, srv)

	expiredID, expired := createKey(t, srv, c)
	revokedID, revoked := createKey(t, srv, c)
	for _, path := range []string{"/api/v1/api-keys/not-a-uuid", "/api/v1/api-keys/00000000-0000-4000-8000-000000000000"} {
		if r := send(t, srv, http.MethodDelete, path, "", c, nil); r.status != http.StatusNotFound {
			t.Errorf("DELETE %s: status %d, want 404", path, r.status)
		}
	}
	if r := send(t, srv, http.MethodDelete, "/api/v1/api-keys/"+revokedID, "", c, nil); r.status != http.StatusNoContent {
		t.Fatalf("revoke: status %d", r.status)
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'api_key.revoke' AND resource_id = $1`, revokedID); n != 1 {
		t.Errorf("%d revocations recorded, want 1", n)
	}
	// Creating a key deletes the expired keys, so the key expires after the
	// last one is created.
	d.exec(t, `UPDATE api_keys SET created_at = clock_timestamp() - interval '2 days', expires_at = clock_timestamp() WHERE id = $1`, expiredID)

	before := d.count(t, `SELECT count(*) FROM audit_entries`)
	for name, header := range map[string]map[string]string{
		"expired":   bearer(expired),
		"revoked":   bearer(revoked),
		"malformed": bearer("nyk_secret"),
	} {
		r := send(t, srv, http.MethodGet, "/api/v1/audit-entries", "", nil, header)
		if r.status != http.StatusUnauthorized || r.header.Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s: status %d, challenge %q; want 401 with Bearer", name, r.status, r.header.Get("WWW-Authenticate"))
		}
	}
	if after := d.count(t, `SELECT count(*) FROM audit_entries`); after != before {
		t.Errorf("%d entries recorded for invalid keys, want 0", after-before)
	}
}

// A request with an API key authenticates with it alone, also when it carries a
// valid session cookie. Other credentials leave the session in charge.
func TestAPIKey_TakesPrecedenceOverTheCookie(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	srv := startConsole(t, d)
	c := mustSignIn(t, srv)
	_, key := createKey(t, srv, c)

	if r := send(t, srv, http.MethodGet, "/api/v1/users", "", c, bearer("nyk_invalid")); r.status != http.StatusUnauthorized {
		t.Errorf("invalid key with a valid cookie: status %d, want 401", r.status)
	}
	if r := send(t, srv, http.MethodGet, "/api/v1/users", "", c, bearer(key)); r.status != http.StatusForbidden {
		t.Errorf("key without users:read with a valid cookie: status %d, want 403", r.status)
	}
	// Other credentials, such as those of a reverse proxy with basic
	// authentication or of an identity-aware proxy, leave the session in charge.
	for _, header := range []string{"Basic YWRhOnB3", "Bearer eyJhbGciOiJSUzI1NiJ9.e30.c2ln"} {
		if r := send(t, srv, http.MethodGet, "/api/v1/users", "", c, map[string]string{"Authorization": header}); r.status != http.StatusOK {
			t.Errorf("%s with a valid cookie: status %d, want 200", header, r.status)
		}
	}
	// RFC 6750 allows more than one space after the scheme.
	if r := send(t, srv, http.MethodGet, "/api/v1/audit-entries", "", nil, map[string]string{"Authorization": "Bearer   " + key}); r.status != http.StatusOK {
		t.Errorf("key after several spaces: status %d, want 200", r.status)
	}
}

// Routes that manage the session, how the account signs in and the keys reject
// API keys, so that a leaked key can neither take over an account nor issue
// itself a successor.
func TestAPIKey_RejectedWhereOnlySessionsAreAdmitted(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	bob := createUser(t, d, "bob@example.com", "admin", "active", testPassword)
	srv := startConsole(t, d)
	c := mustSignIn(t, srv)
	id, key := createKey(t, srv, c)

	pw := `{"password": "` + testPassword + `"}`
	for _, tt := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/session", ""},
		{http.MethodDelete, "/api/v1/session", ""},
		{http.MethodPut, "/api/v1/session/password", `{"current_password": "` + testPassword + `", "new_password": "a brand new horse battery"}`},
		{http.MethodPost, "/api/v1/session/totp", pw},
		{http.MethodDelete, "/api/v1/session/totp", `{"password": "` + testPassword + `", "code": "123456"}`},
		{http.MethodPost, "/api/v1/session/totp/confirmation", `{"code": "123456"}`},
		{http.MethodPost, "/api/v1/session/totp/recovery-codes", `{"password": "` + testPassword + `", "code": "123456"}`},
		{http.MethodGet, "/api/v1/api-keys", ""},
		{http.MethodPost, "/api/v1/api-keys", keyBody("successor", "audit:read", testPassword, time.Hour)},
		{http.MethodDelete, "/api/v1/api-keys/" + id, ""},
		{http.MethodPatch, "/api/v1/users/" + bob, `{"totp_enabled": false, "password": "` + testPassword + `"}`},
	} {
		r := send(t, srv, tt.method, tt.path, tt.body, nil, bearer(key))
		if r.status != http.StatusForbidden {
			t.Errorf("%s %s with an API key: status %d, want 403", tt.method, tt.path, r.status)
		}
		// The key lacks users:write for the account route; every other route
		// tells the client that it needs a session.
		e, _ := r.body["error"].(map[string]any)
		message, _ := e["message"].(string)
		needsSession := !strings.HasPrefix(tt.path, "/api/v1/users/")
		if strings.Contains(message, "session") != needsSession {
			t.Errorf("%s %s with an API key: message %q", tt.method, tt.path, message)
		}
	}
	// Nothing changed: the session, the password and the keys are as before.
	if r := send(t, srv, http.MethodGet, "/api/v1/session", "", c, nil); r.status != http.StatusOK {
		t.Errorf("the session ended: status %d", r.status)
	}
	if r := signIn(t, srv, "ada@example.com", testPassword, nil); r.status != http.StatusOK {
		t.Errorf("the password changed: status %d", r.status)
	}
	if n := d.count(t, `SELECT count(*) FROM api_keys`); n != 1 {
		t.Errorf("%d keys, want 1", n)
	}
	if n := d.count(t, `SELECT count(*) FROM totp_factors`); n != 0 {
		t.Errorf("%d TOTP factors, want 0", n)
	}
}

// The limit of keys is counted under the lock of the active administrators, who
// alone create keys, so that two administrators cannot exceed it together: a
// request of one waits for a transaction that holds the lock of another and
// sees the keys it added.
func TestAPIKey_CreateCountsKeysUnderTheLockOfTheAdministrators(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	ada := createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	createUser(t, d, "bob@example.com", "admin", "active", testPassword)
	srv := startConsole(t, d)
	bob := signIn(t, srv, "bob@example.com", testPassword, nil).cookie

	holder, err := d.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.WithoutCancel(t.Context())) }()
	// Only the row of the other administrator, so that the request waits for
	// the lock of the administrators and not for its own account.
	if _, err := holder.Exec(t.Context(), `SELECT FROM users WHERE id = $1 FOR UPDATE`, ada); err != nil {
		t.Fatal(err)
	}
	_, err = holder.Exec(t.Context(), `
INSERT INTO api_keys (name, secret_hash, scopes, expires_at)
SELECT 'k' || i, sha256(convert_to('k' || i, 'UTF8')), '{audit:read}', clock_timestamp() + interval '1 day'
FROM generate_series(1, $1) AS i`, apikey.MaxKeys)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan response, 1)
	go func() {
		done <- send(t, srv, http.MethodPost, "/api/v1/api-keys", keyBody("k", "audit:read", testPassword, time.Hour), bob, nil)
	}()
	waitForLockWaiter(t, d, done)
	if err := holder.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r := <-done; r.status != http.StatusConflict || errorCode(r) != "too_many_api_keys" {
		t.Errorf("create beyond the limit: %d %v, want 409", r.status, r.body)
	}
}
