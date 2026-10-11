// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"nyktus.org/nyktus/internal/auth/password"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/auth/token"
	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
	"nyktus.org/nyktus/internal/user"
)

// Login must not reveal whether an account exists or why it was rejected. Every
// rejection, except the correct password for a locked account, receives the same
// status, headers and body.
func TestSignIn_ReturnsIdenticalResponsesForUnknownAndRejectedAccounts(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	srv := startConsole(t, d)
	createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	createUser(t, d, "pending@example.com", "viewer", "pending", "")
	createUser(t, d, "gone@example.com", "viewer", "deactivated", testPassword)
	createUser(t, d, "locked@example.com", "viewer", "active", testPassword)
	d.exec(t, `UPDATE users SET locked_until = clock_timestamp() + interval '10 minutes' WHERE email = 'locked@example.com'`)

	reference := signIn(t, srv, "nobody@example.com", testPassword, nil)
	if reference.status != http.StatusUnauthorized || reference.header.Get("WWW-Authenticate") == "" || reference.cookie != nil {
		t.Fatalf("unknown account: %d %v %v, want 401 with a challenge and without a cookie", reference.status, reference.header, reference.body)
	}
	for name, attempt := range map[string]struct{ email, pw string }{
		"wrong password":                 {"ada@example.com", "wrong horse battery"},
		"address in other case":          {"ADA@example.com", "wrong horse battery"},
		"invalid address":                {"not an address", testPassword},
		"empty fields":                   {"", ""},
		"overlong password":              {"ada@example.com", strings.Repeat("x", 129)},
		"pending account":                {"pending@example.com", testPassword},
		"deactivated, correct password":  {"gone@example.com", testPassword},
		"locked account, wrong password": {"locked@example.com", "wrong horse battery"},
	} {
		t.Run(name, func(t *testing.T) {
			r := signIn(t, srv, attempt.email, attempt.pw, nil)
			if got, want := normalized(t, r), normalized(t, reference); got != want {
				t.Errorf("response = %s, want the response for an unknown account: %s", got, want)
			}
		})
	}
	if n := d.count(t, `SELECT count(*) FROM sessions`); n != 0 {
		t.Errorf("%d sessions after rejected sign-ins, want none", n)
	}
}

// countingHasher counts the passwords verified and the hashes used.
type countingHasher struct {
	*password.Hasher
	verified atomic.Int32
	encoded  atomic.Value
}

func (c *countingHasher) Verify(ctx context.Context, pw, encoded string) (bool, error) {
	c.verified.Add(1)
	c.encoded.Store(encoded)
	return c.Hasher.Verify(ctx, pw, encoded)
}

// A sign-in for an account that does not exist or has no password must take as
// long as one with a wrong password: it verifies against a hash with the same
// parameters.
func TestSignIn_VerifiesThePasswordInEveryCase(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	createUser(t, d, "pending@example.com", "viewer", "pending", "")
	counting := &countingHasher{Hasher: hasher}
	svc, err := session.NewService(t.Context(), d.console, counting, secretboxtest.Keyring(t), testSessions)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	for _, email := range []string{"nobody@example.com", "invalid", "pending@example.com", "ada@example.com"} {
		before := counting.verified.Load()
		_, err := svc.SignIn(t.Context(), email, "wrong horse battery", "")
		if err != session.ErrInvalidCredentials { //nolint:errorlint // The service returns the sentinel itself.
			t.Errorf("SignIn(%s) error = %v, want ErrInvalidCredentials", email, err)
		}
		if n := counting.verified.Load() - before; n != 1 {
			t.Errorf("SignIn(%s) verified %d passwords, want 1", email, n)
		}
		if encoded, _ := counting.encoded.Load().(string); hasher.NeedsRehash(encoded) {
			t.Errorf("SignIn(%s) verified against %q, want a hash with the current parameters", email, encoded)
		}
	}
}

func TestSignIn_StartsSessionWithSecureCookieAndAuditEntry(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	srv := startConsole(t, d)
	id := createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	d.exec(t, `UPDATE users SET failed_logins = 3 WHERE id = $1`, id)

	r := signIn(t, srv, "Ada@Example.com", testPassword, nil)
	if r.status != http.StatusOK {
		t.Fatalf("status = %d, body = %v", r.status, r.body)
	}
	c := r.cookie
	if c == nil || c.Path != "/" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode ||
		c.Domain != "" || c.MaxAge != int(testSessions.MaxAge.Seconds()) {
		t.Errorf("cookie = %+v, want __Host- attributes with the maximum age", c)
	}
	if raw, err := base64.RawURLEncoding.DecodeString(c.Value); err != nil || len(raw) != 32 {
		t.Errorf("cookie value %q does not encode 32 bytes", c.Value)
	}

	u, _ := r.body["user"].(map[string]any)
	if u["id"] != id || u["email"] != "ada@example.com" || u["role"] != "admin" || u["password_hash"] != nil {
		t.Errorf("user = %v, want the account without its hash", u)
	}
	idle, err1 := time.Parse(time.RFC3339Nano, fmt.Sprint(r.body["idle_expires_at"]))
	absolute, err2 := time.Parse(time.RFC3339Nano, fmt.Sprint(r.body["expires_at"]))
	if err1 != nil || err2 != nil || absolute.Sub(idle) != testSessions.MaxAge-testSessions.IdleTimeout {
		t.Errorf("expiries = %v, %v; want %v apart", r.body["idle_expires_at"], r.body["expires_at"], testSessions.MaxAge-testSessions.IdleTimeout)
	}

	var sessionID string
	if err := d.owner.QueryRow(t.Context(), `SELECT id FROM sessions WHERE token_hash = $1 AND user_id = $2`,
		token.Hash(c.Value), id).Scan(&sessionID); err != nil {
		t.Fatalf("the session is not stored under the hash of its token: %v", err)
	}
	var clientIP, requestID string
	err := d.owner.QueryRow(t.Context(), `
SELECT host(client_ip), request_id FROM audit_entries
WHERE action = 'session.create' AND outcome = 'success' AND actor_kind = 'user' AND auth_method = 'password'
	AND actor_user_id = $1 AND resource_type = 'session' AND resource_id = $2`, id, sessionID).Scan(&clientIP, &requestID)
	if err != nil {
		t.Fatalf("read audit entry: %v", err)
	}
	if clientIP != "203.0.113.9" || requestID != r.header.Get("X-Request-ID") {
		t.Errorf("audit entry client_ip = %s, request_id = %s; want 203.0.113.9 and the ID of the response", clientIP, requestID)
	}
	if n := d.count(t, `SELECT failed_logins FROM users WHERE id = $1`, id); n != 0 {
		t.Errorf("failed_logins = %d after a successful sign-in, want 0", n)
	}
}

// A failed sign-in for an unknown account is recorded without the submitted
// address, which is attacker input and sometimes a mistyped password.
func TestSignIn_RecordsFailuresWithoutTheSubmittedAddress(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	srv := startConsole(t, d)
	id := createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	signIn(t, srv, "Secret-Password-Typed-Here@example.com", testPassword, nil)
	signIn(t, srv, "ada@example.com", "wrong horse battery", nil)

	if n := d.count(t, `
SELECT count(*) FROM audit_entries WHERE action = 'session.create' AND outcome = 'failure'
	AND actor_kind = 'anonymous' AND auth_method = 'password' AND actor_email IS NULL AND resource_id IS NULL`); n != 1 {
		t.Errorf("%d anonymous failures recorded, want 1", n)
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE audit_entries::text ILIKE '%secret-password%'`); n != 0 {
		t.Error("the audit log contains the submitted address")
	}
	if n := d.count(t, `
SELECT count(*) FROM audit_entries WHERE action = 'session.create' AND outcome = 'failure'
	AND actor_kind = 'user' AND actor_user_id = $1`, id); n != 1 {
		t.Errorf("%d failures of the known account recorded, want 1", n)
	}
}

func TestSignIn_LockIsRevealedOnlyWithTheCorrectPassword(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	srv := startConsole(t, d)
	id := createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	reference := signIn(t, srv, "nobody@example.com", testPassword, nil)

	for i := range user.MaxFailedLogins {
		if r := signIn(t, srv, "ada@example.com", "wrong horse battery", nil); normalized(t, r) != normalized(t, reference) {
			t.Fatalf("failure %d: %d %v, want the generic response", i+1, r.status, r.body)
		}
	}

	r := signIn(t, srv, "ada@example.com", testPassword, nil)
	e, _ := r.body["error"].(map[string]any)
	retryAfter, err := strconv.Atoi(r.header.Get("Retry-After"))
	if r.status != http.StatusForbidden || e["code"] != "account_locked" || r.cookie != nil ||
		err != nil || retryAfter <= 14*60 || retryAfter > 15*60 {
		t.Errorf("correct password while locked: %d %v Retry-After %q, want 403 account_locked for about 15 minutes",
			r.status, r.body, r.header.Get("Retry-After"))
	}
	if r := signIn(t, srv, "ada@example.com", "wrong horse battery", nil); normalized(t, r) != normalized(t, reference) {
		t.Errorf("wrong password while locked: %d %v, want the generic response", r.status, r.body)
	}

	d.exec(t, `UPDATE users SET locked_until = clock_timestamp() - interval '1 second' WHERE id = $1`, id)
	if r := signIn(t, srv, "ada@example.com", testPassword, nil); r.status != http.StatusOK {
		t.Errorf("after the lock: %d %v, want 200", r.status, r.body)
	}
}

func TestSignIn_EndsThePreviousAndExpiredSessions(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	srv := startConsole(t, d)
	id := createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	first := mustSignIn(t, srv)
	d.exec(t, `INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at)
VALUES (sha256('expired'), $1, clock_timestamp() - interval '2 days', clock_timestamp() - interval '2 days')`, id)
	other := mustSignIn(t, srv)

	second := signIn(t, srv, "ada@example.com", testPassword, first)
	if second.status != http.StatusOK || second.cookie.Value == first.Value {
		t.Fatalf("second sign-in: %d, cookie %v; want a new token", second.status, second.cookie)
	}
	if r := send(t, srv, http.MethodGet, "/api/v1/session", "", first, nil); r.status != http.StatusUnauthorized {
		t.Errorf("previous session: status %d, want 401", r.status)
	}
	if r := send(t, srv, http.MethodGet, "/api/v1/session", "", other, nil); r.status != http.StatusOK {
		t.Errorf("session in another browser: status %d, want 200", r.status)
	}
	if n := d.count(t, `SELECT count(*) FROM sessions WHERE user_id = $1`, id); n != 2 {
		t.Errorf("%d sessions, want 2 without the previous and the expired one", n)
	}
}

// encodeHash builds an Argon2id hash with parameters other than the current ones.
func encodeHash(pw string, memory, iterations uint32) string {
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(pw), salt, iterations, memory, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=1$%s$%s", memory, iterations,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

func TestSignIn_RehashesAHashWithOutdatedParameters(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	srv := startConsole(t, d)
	id := createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	d.exec(t, `UPDATE users SET password_hash = $2 WHERE id = $1`, id, encodeHash(testPassword, 1024, 1))

	mustSignIn(t, srv)
	var stored string
	if err := d.owner.QueryRow(t.Context(), `SELECT password_hash FROM users WHERE id = $1`, id).Scan(&stored); err != nil {
		t.Fatalf("read hash: %v", err)
	}
	if hasher.NeedsRehash(stored) {
		t.Errorf("stored hash %q has outdated parameters after sign-in", stored)
	}
	if ok, err := hasher.Verify(t.Context(), testPassword, stored); err != nil || !ok {
		t.Errorf("new hash does not verify the password: %v, %v", ok, err)
	}
}

func TestSession_ReturnsTheCurrentSession(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	srv := startConsole(t, d)
	id := createUser(t, d, "ada@example.com", "user", "active", testPassword)
	c := mustSignIn(t, srv)

	r := send(t, srv, http.MethodGet, "/api/v1/session", "", c, nil)
	u, _ := r.body["user"].(map[string]any)
	if r.status != http.StatusOK || u["id"] != id || u["role"] != "user" || r.body["expires_at"] == nil {
		t.Errorf("GET /api/v1/session: %d %v", r.status, r.body)
	}
	for name, cookie := range map[string]*http.Cookie{
		"no cookie":     nil,
		"unknown token": clientCookie(strings.Repeat("A", 43)),
		"token hash":    clientCookie(base64.RawURLEncoding.EncodeToString(token.Hash(c.Value))),
	} {
		if r := send(t, srv, http.MethodGet, "/api/v1/session", "", cookie, nil); r.status != http.StatusUnauthorized ||
			r.header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: status %d, want 401 with a challenge", name, r.status)
		}
	}
}

func TestSession_EndsAfterIdleTimeoutMaximumAgeAndDeactivation(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"idle":        `UPDATE sessions SET last_seen_at = clock_timestamp() - interval '61 minutes', created_at = clock_timestamp() - interval '61 minutes'`,
		"maximum age": `UPDATE sessions SET created_at = clock_timestamp() - interval '12 hours 1 minute'`,
		"deactivated": `UPDATE users SET status = 'deactivated'`,
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			d := newTestDB(t)
			srv := startConsole(t, d)
			// Not an administrator: the last active one cannot be deactivated.
			createUser(t, d, "ada@example.com", "viewer", "active", testPassword)
			c := mustSignIn(t, srv)
			d.exec(t, change)
			if r := send(t, srv, http.MethodGet, "/api/v1/session", "", c, nil); r.status != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", r.status)
			}
		})
	}
}

// A request extends a session, but records its use at most once per minute, so
// that requests do not each cost a write.
func TestSession_RecordsUseAtMostOncePerMinute(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	srv := startConsole(t, d)
	createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	c := mustSignIn(t, srv)
	lastSeen := func() time.Time {
		t.Helper()
		var at time.Time
		if err := d.owner.QueryRow(t.Context(), `SELECT last_seen_at FROM sessions`).Scan(&at); err != nil {
			t.Fatalf("read last_seen_at: %v", err)
		}
		return at
	}

	before := lastSeen()
	send(t, srv, http.MethodGet, "/api/v1/session", "", c, nil)
	if after := lastSeen(); !after.Equal(before) {
		t.Errorf("last_seen_at changed from %v to %v within a minute", before, after)
	}

	d.exec(t, `UPDATE sessions SET created_at = created_at - interval '2 minutes', last_seen_at = last_seen_at - interval '2 minutes'`)
	before = lastSeen()
	r := send(t, srv, http.MethodGet, "/api/v1/session", "", c, nil)
	after := lastSeen()
	if !after.After(before.Add(time.Minute)) {
		t.Errorf("last_seen_at = %v after a request, want it moved from %v to now", after, before)
	}
	idle, err := time.Parse(time.RFC3339Nano, fmt.Sprint(r.body["idle_expires_at"]))
	if err != nil || !idle.Equal(after.Add(testSessions.IdleTimeout)) {
		t.Errorf("idle_expires_at = %v, want %v", r.body["idle_expires_at"], after.Add(testSessions.IdleTimeout))
	}
}

func TestSignOut_EndsTheSession(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	srv := startConsole(t, d)
	id := createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	c := mustSignIn(t, srv)

	r := send(t, srv, http.MethodDelete, "/api/v1/session", "", c, map[string]string{"Origin": origin})
	if r.status != http.StatusNoContent || r.cookie == nil || r.cookie.MaxAge >= 0 || r.cookie.Value != "" {
		t.Fatalf("DELETE /api/v1/session: %d, cookie %+v; want 204 and a cleared cookie", r.status, r.cookie)
	}
	if r := send(t, srv, http.MethodGet, "/api/v1/session", "", c, nil); r.status != http.StatusUnauthorized {
		t.Errorf("after sign-out: status %d, want 401", r.status)
	}
	if n := d.count(t, `SELECT count(*) FROM sessions`); n != 0 {
		t.Errorf("%d sessions after sign-out, want none", n)
	}
	if n := d.count(t, `
SELECT count(*) FROM audit_entries WHERE action = 'session.delete' AND outcome = 'success'
	AND actor_kind = 'user' AND auth_method = 'session' AND actor_user_id = $1 AND resource_type = 'session'`, id); n != 1 {
		t.Errorf("%d sign-outs recorded, want 1", n)
	}
	if r := send(t, srv, http.MethodDelete, "/api/v1/session", "", nil, nil); r.status != http.StatusUnauthorized {
		t.Errorf("sign-out without a session: status %d, want 401", r.status)
	}
}

// Session cookies are SameSite=Strict, but pages on other subdomains count as
// the same site. Requests that change state must come from the console.
func TestSession_RejectsRequestsFromOtherOrigins(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	srv := startConsole(t, d)
	createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	c := mustSignIn(t, srv)
	evil := map[string]string{"Origin": "https://wiki.example.com"}

	if r := send(t, srv, http.MethodPost, "/api/v1/session", signInBody("ada@example.com", testPassword), nil, evil); r.status != http.StatusForbidden || r.cookie != nil {
		t.Errorf("cross-origin sign-in: %d, cookie %v; want 403 without a session", r.status, r.cookie)
	}
	if r := send(t, srv, http.MethodDelete, "/api/v1/session", "", c, evil); r.status != http.StatusForbidden {
		t.Errorf("cross-origin sign-out: status %d, want 403", r.status)
	}
	if r := send(t, srv, http.MethodGet, "/api/v1/session", "", c, nil); r.status != http.StatusOK {
		t.Errorf("session after the rejected sign-out: status %d, want 200", r.status)
	}
	if r := send(t, srv, http.MethodPost, "/api/v1/session", signInBody("ada@example.com", testPassword), nil, map[string]string{"Origin": origin}); r.status != http.StatusOK {
		t.Errorf("same-origin sign-in: status %d, want 200", r.status)
	}
}
