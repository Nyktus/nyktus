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

// createKey creates an API key of the signed-in user of cookie with the scope
// audit:read and returns its identifier and the key.
func createKey(t *testing.T, srv *httptest.Server, cookie *http.Cookie) (id, key string) {
	t.Helper()
	r := send(t, srv, http.MethodPost, "/api/v1/session/api-keys", keyBody("SIEM export", "audit:read", testPassword), cookie, nil)
	id, _ = r.body["id"].(string)
	key, _ = r.body["key"].(string)
	if r.status != http.StatusCreated || id == "" || !strings.HasPrefix(key, apikey.Prefix) {
		t.Fatalf("create API key: %d %v", r.status, r.body)
	}
	return id, key
}

func keyBody(name, scope, pw string) string {
	b, err := json.Marshal(map[string]any{
		"name": name, "scopes": []string{scope}, "password": pw,
		"expires_at": time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func bearer(key string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + key}
}

func TestAPIKey_IsShownOnceAndActsForItsUser(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	ada := createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	srv := startConsole(t, d)
	c := mustSignIn(t, srv)
	id, key := createKey(t, srv, c)

	list := send(t, srv, http.MethodGet, "/api/v1/session/api-keys", "", c, nil)
	keys, _ := list.body["api_keys"].([]any)
	if list.status != http.StatusOK || len(keys) != 1 || strings.Contains(mustJSON(t, list.body), key) {
		t.Fatalf("list: %d %v, want the key without its secret", list.status, list.body)
	}

	if r := send(t, srv, http.MethodGet, "/api/v1/audit-entries", "", nil, bearer(key)); r.status != http.StatusOK {
		t.Fatalf("read the audit log with the key: %d %v", r.status, r.body)
	}
	if n := d.count(t, `SELECT count(*) FROM api_keys WHERE id = $1 AND last_used_at IS NOT NULL`, id); n != 1 {
		t.Error("the use of the key is not recorded")
	}
	// Every action names the key; creating it names the session.
	if n := d.count(t, `
SELECT count(*) FROM audit_entries WHERE action = 'audit.read' AND outcome = 'success'
	AND auth_method = 'api_key' AND api_key_id = $1 AND actor_user_id = $2`, id, ada); n != 1 {
		t.Errorf("%d reads through the key recorded, want 1", n)
	}
	if n := d.count(t, `
SELECT count(*) FROM audit_entries WHERE action = 'api_key.create' AND outcome = 'success'
	AND auth_method = 'session' AND resource_type = 'api_key' AND resource_id = $1`, id); n != 1 {
		t.Errorf("%d creations recorded, want 1", n)
	}

	// An administrator sees the keys of an account.
	r := send(t, srv, http.MethodGet, "/api/v1/users/"+ada+"/api-keys", "", c, nil)
	if keys, _ := r.body["api_keys"].([]any); r.status != http.StatusOK || len(keys) != 1 {
		t.Errorf("list the keys of the account: %d %v", r.status, r.body)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return string(b)
}

// A key holds the intersection of its scopes and the current role of its user,
// evaluated with every request.
func TestAPIKey_HoldsTheIntersectionOfScopesAndTheCurrentRole(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	ada := createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	// Another administrator remains when ada is demoted.
	createUser(t, d, "bob@example.com", "admin", "active", testPassword)
	srv := startConsole(t, d)
	id, key := createKey(t, srv, mustSignIn(t, srv))

	// The role grants users:read, the key does not carry it.
	if r := send(t, srv, http.MethodGet, "/api/v1/users", "", nil, bearer(key)); r.status != http.StatusForbidden {
		t.Errorf("route beyond the scopes: status %d, want 403", r.status)
	}
	if n := d.count(t, `
SELECT count(*) FROM audit_entries WHERE action = 'users.read' AND outcome = 'denied' AND api_key_id = $1`, id); n != 1 {
		t.Errorf("%d denials recorded with the key, want 1", n)
	}

	d.exec(t, `UPDATE users SET role = 'viewer' WHERE id = $1`, ada)
	if r := send(t, srv, http.MethodGet, "/api/v1/audit-entries", "", nil, bearer(key)); r.status != http.StatusForbidden {
		t.Errorf("after demotion: status %d, want 403", r.status)
	}
	d.exec(t, `UPDATE users SET role = 'admin' WHERE id = $1`, ada)
	if r := send(t, srv, http.MethodGet, "/api/v1/audit-entries", "", nil, bearer(key)); r.status != http.StatusOK {
		t.Errorf("after promotion: status %d, want 200", r.status)
	}
}

// Keys can carry only scopes that keys may carry and the role grants.
func TestAPIKey_CreateRejectsScopesBeyondKeysAndRole(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	createUser(t, d, "vic@example.com", "viewer", "active", testPassword)
	srv := startConsole(t, d)
	admin := mustSignIn(t, srv)
	viewer := signIn(t, srv, "vic@example.com", testPassword, nil).cookie

	for _, tt := range []struct {
		name   string
		cookie *http.Cookie
		scope  string
	}{
		{"users:write", admin, "users:write"},
		{"users:read", admin, "users:read"},
		{"scope beyond the role", viewer, "audit:read"},
		{"wildcard", admin, "*:*"},
	} {
		r := send(t, srv, http.MethodPost, "/api/v1/session/api-keys", keyBody("k", tt.scope, testPassword), tt.cookie, nil)
		if r.status != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", tt.name, r.status)
		}
	}
	if n := d.count(t, `SELECT count(*) FROM api_keys`); n != 0 {
		t.Errorf("%d keys created, want 0", n)
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

	r := send(t, srv, http.MethodPost, "/api/v1/session/api-keys", keyBody("k", "audit:read", "wrong horse battery"), c, nil)
	if code, _ := r.body["error"].(map[string]any)["code"].(string); r.status != http.StatusForbidden || code != "wrong_password" {
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

// An expired, revoked or malformed key, and a key of a deactivated account, is
// answered like a request without credentials and not recorded.
func TestAPIKey_InvalidKeysAreUnauthenticated(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	bob := createUser(t, d, "bob@example.com", "admin", "active", testPassword)
	srv := startConsole(t, d)
	c := mustSignIn(t, srv)
	bobCookie := signIn(t, srv, "bob@example.com", testPassword, nil).cookie

	expiredID, expired := createKey(t, srv, c)
	revokedID, revoked := createKey(t, srv, c)
	if r := send(t, srv, http.MethodDelete, "/api/v1/session/api-keys/"+revokedID, "", c, nil); r.status != http.StatusNoContent {
		t.Fatalf("revoke: status %d", r.status)
	}
	// Creating a key deletes the expired keys of the account, so the key
	// expires after the last one of ada is created.
	d.exec(t, `UPDATE api_keys SET created_at = clock_timestamp() - interval '2 days', expires_at = clock_timestamp() WHERE id = $1`, expiredID)
	leakedID, leaked := createKey(t, srv, bobCookie)
	if r := send(t, srv, http.MethodDelete, "/api/v1/users/"+bob+"/api-keys/"+leakedID, "", c, nil); r.status != http.StatusNoContent {
		t.Fatalf("revoke the key of another account: status %d", r.status)
	}
	_, deactivated := createKey(t, srv, bobCookie)
	if r := send(t, srv, http.MethodPatch, "/api/v1/users/"+bob, `{"status": "deactivated"}`, c, nil); r.status != http.StatusOK {
		t.Fatalf("deactivate: %d %v", r.status, r.body)
	}
	if n := d.count(t, `SELECT count(*) FROM api_keys WHERE user_id = $1`, bob); n != 0 {
		t.Errorf("%d keys of the deactivated account left, want 0", n)
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'api_key.revoke' AND resource_id IN ($1, $2)`, revokedID, leakedID); n != 2 {
		t.Errorf("%d revocations recorded, want 2", n)
	}

	before := d.count(t, `SELECT count(*) FROM audit_entries`)
	for name, header := range map[string]map[string]string{
		"expired":             bearer(expired),
		"revoked":             bearer(revoked),
		"revoked by an admin": bearer(leaked),
		"deactivated account": bearer(deactivated),
		"malformed":           bearer("nyk_secret"),
		"other scheme":        {"Authorization": "Basic " + expired},
		"empty":               {"Authorization": ""},
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

// A request with the Authorization header authenticates with it alone, also
// when it carries a valid session cookie.
func TestAPIKey_HeaderTakesPrecedenceOverTheCookie(t *testing.T) {
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
}

// Routes that manage the session, how the account signs in and its keys reject
// API keys, so that a leaked key can neither take over the account nor issue a
// successor. A key cannot remove the second factor of another account either.
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
		{http.MethodGet, "/api/v1/session/api-keys", ""},
		{http.MethodPost, "/api/v1/session/api-keys", keyBody("successor", "audit:read", testPassword)},
		{http.MethodDelete, "/api/v1/session/api-keys/" + id, ""},
		{http.MethodPatch, "/api/v1/users/" + bob, `{"totp_enabled": false, "password": "` + testPassword + `"}`},
	} {
		if r := send(t, srv, tt.method, tt.path, tt.body, nil, bearer(key)); r.status != http.StatusForbidden {
			t.Errorf("%s %s with an API key: status %d, want 403", tt.method, tt.path, r.status)
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

// The limit of keys is counted under the lock of the account, so that
// concurrent requests cannot exceed it: a request waits for a transaction that
// holds the lock and sees the keys it added.
func TestAPIKey_CreateCountsKeysUnderTheLockOfTheAccount(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	id := createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	srv := startConsole(t, d)
	c := mustSignIn(t, srv)

	holder, err := d.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := holder.Exec(t.Context(), `SELECT FROM users WHERE id = $1 FOR UPDATE`, id); err != nil {
		t.Fatal(err)
	}
	_, err = holder.Exec(t.Context(), `
INSERT INTO api_keys (user_id, name, secret_hash, scopes, expires_at)
SELECT $1, 'k' || i, sha256(convert_to('k' || i, 'UTF8')), '{audit:read}', clock_timestamp() + interval '1 day'
FROM generate_series(1, $2) AS i`, id, apikey.MaxPerUser)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan response, 1)
	go func() {
		done <- send(t, srv, http.MethodPost, "/api/v1/session/api-keys", keyBody("k", "audit:read", testPassword), c, nil)
	}()
	waitForLockWaiter(t, d, done)
	if err := holder.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r := <-done; r.status != http.StatusConflict {
		t.Errorf("create beyond the limit: %d %v, want 409", r.status, r.body)
	}
}
