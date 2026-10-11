// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"nyktus.org/nyktus/internal/user"
)

const newPassword = "a brand new horse battery"

func changeBody(current, next string) string {
	b, err := json.Marshal(map[string]string{"current_password": current, "new_password": next})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// A change of password ends every session of the account. The session that made
// the change is replaced by a new one, so the user stays signed in while its old
// token stops working.
func TestChangePassword_ReplacesTheSessionAndEndsTheOthers(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	srv := startConsole(t, d)
	id := createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	current := mustSignIn(t, srv)
	other := mustSignIn(t, srv)

	r := send(t, srv, http.MethodPut, "/api/v1/session/password", changeBody(testPassword, newPassword), current, map[string]string{"Origin": origin})
	if r.status != http.StatusNoContent || r.cookie == nil {
		t.Fatalf("PUT /api/v1/session/password: %d %v, cookie %v; want 204 with a new session cookie", r.status, r.body, r.cookie)
	}
	if !r.cookie.Secure || !r.cookie.HttpOnly || r.cookie.SameSite != http.SameSiteStrictMode || r.cookie.Path != "/" ||
		r.cookie.Value == current.Value || r.cookie.Value == other.Value {
		t.Errorf("new cookie %+v, want a new Secure, HttpOnly, SameSite=Strict cookie for /", r.cookie)
	}
	if got := r.header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	for name, c := range map[string]*http.Cookie{"changing": current, "other": other} {
		if r := send(t, srv, http.MethodGet, "/api/v1/session", "", c, nil); r.status != http.StatusUnauthorized {
			t.Errorf("%s session after the change: status %d, want 401", name, r.status)
		}
	}
	if r := send(t, srv, http.MethodGet, "/api/v1/session", "", r.cookie, nil); r.status != http.StatusOK {
		t.Errorf("new session: status %d, want 200", r.status)
	}
	if n := d.count(t, `SELECT count(*) FROM sessions`); n != 1 {
		t.Errorf("%d sessions, want only the new one", n)
	}
	if r := signIn(t, srv, "ada@example.com", testPassword, nil); r.status != http.StatusUnauthorized {
		t.Errorf("sign-in with the old password: status %d, want 401", r.status)
	}
	if r := signIn(t, srv, "ada@example.com", newPassword, nil); r.status != http.StatusOK {
		t.Errorf("sign-in with the new password: status %d, want 200", r.status)
	}
	if n := d.count(t, `
SELECT count(*) FROM audit_entries WHERE action = 'user.password_change' AND outcome = 'success'
	AND actor_kind = 'user' AND auth_method = 'session' AND actor_user_id = $1
	AND resource_type = 'user' AND resource_id = $1`, id); n != 1 {
		t.Errorf("%d changes recorded, want 1", n)
	}
}

// A taken-over session must not guess the password more often than the sign-in
// can: a wrong current password counts as a failed sign-in, and the lock is
// revealed only with the correct one.
func TestChangePassword_WrongCurrentPasswordCountsAsFailedSignIn(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	srv := startConsole(t, d)
	id := createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	c := mustSignIn(t, srv)
	change := func(current string) response {
		return send(t, srv, http.MethodPut, "/api/v1/session/password", changeBody(current, newPassword), c, nil)
	}

	for i := range user.MaxFailedLogins {
		r := change("wrong horse battery")
		if e, _ := r.body["error"].(map[string]any); r.status != http.StatusForbidden || e["code"] != "wrong_password" || r.cookie != nil {
			t.Fatalf("failure %d: %d %v, want 403 wrong_password", i+1, r.status, r.body)
		}
	}
	if n := d.count(t, `SELECT count(*) FROM users WHERE id = $1 AND locked_until > clock_timestamp()`, id); n != 1 {
		t.Fatal("the account is not locked after the failures")
	}

	r := change(testPassword)
	e, _ := r.body["error"].(map[string]any)
	retryAfter, err := strconv.Atoi(r.header.Get("Retry-After"))
	if r.status != http.StatusForbidden || e["code"] != "account_locked" || r.cookie != nil || err != nil || retryAfter <= 0 {
		t.Errorf("correct password while locked: %d %v Retry-After %q, want 403 account_locked", r.status, r.body, r.header.Get("Retry-After"))
	}
	if r := change("wrong horse battery"); r.status != http.StatusForbidden || r.body["error"].(map[string]any)["code"] != "wrong_password" {
		t.Errorf("wrong password while locked: %d %v, want 403 wrong_password", r.status, r.body)
	}
	// A lock blocks the sign-in, not existing sessions: anyone who knows the
	// address can lock an account.
	if r := send(t, srv, http.MethodGet, "/api/v1/session", "", c, nil); r.status != http.StatusOK {
		t.Errorf("session while locked: status %d, want 200", r.status)
	}
	if r := signIn(t, srv, "ada@example.com", newPassword, nil); r.status != http.StatusUnauthorized {
		t.Error("the password changed while the account was locked")
	}
	if n := d.count(t, `
SELECT count(*) FROM audit_entries WHERE action = 'user.password_change' AND outcome = 'failure'
	AND actor_user_id = $1 AND auth_method = 'session'`, id); n != user.MaxFailedLogins+2 {
		t.Errorf("%d failures recorded, want %d", n, user.MaxFailedLogins+2)
	}

	d.exec(t, `UPDATE users SET locked_until = clock_timestamp() - interval '1 second' WHERE id = $1`, id)
	if r := change(testPassword); r.status != http.StatusNoContent {
		t.Errorf("after the lock: %d %v, want 204", r.status, r.body)
	}
}

// The new password is checked before the current one, because the check costs
// no hash. A request that fails it neither counts as a failed sign-in nor is
// recorded.
func TestChangePassword_RejectsAnInvalidNewPasswordFirst(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	srv := startConsole(t, d)
	id := createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	c := mustSignIn(t, srv)

	for _, body := range []string{
		changeBody("wrong horse battery", "short"),
		changeBody(testPassword, "short"),
		`{"current_password": "correct horse battery"}`,
		`{"current_password": "x", "new_password": "a brand new horse battery", "extra": 1}`,
	} {
		r := send(t, srv, http.MethodPut, "/api/v1/session/password", body, c, nil)
		if e, _ := r.body["error"].(map[string]any); r.status != http.StatusBadRequest || e["code"] != "invalid_request" {
			t.Errorf("%s: %d %v, want 400 invalid_request", body, r.status, r.body)
		}
	}
	if n := d.count(t, `SELECT failed_logins FROM users WHERE id = $1`, id); n != 0 {
		t.Errorf("failed_logins = %d, want 0", n)
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'user.password_change'`); n != 0 {
		t.Errorf("%d changes recorded, want none", n)
	}
	if r := send(t, srv, http.MethodPut, "/api/v1/session/password", changeBody(testPassword, newPassword), nil, nil); r.status != http.StatusUnauthorized {
		t.Errorf("without a session: status %d, want 401", r.status)
	}
	if r := send(t, srv, http.MethodPut, "/api/v1/session/password", changeBody(testPassword, newPassword), c,
		map[string]string{"Origin": "https://wiki.example.com"}); r.status != http.StatusForbidden {
		t.Errorf("from another origin: status %d, want 403", r.status)
	}
	if r := signIn(t, srv, "ada@example.com", testPassword, nil); r.status != http.StatusOK {
		t.Error("a rejected request changed the password")
	}
}
