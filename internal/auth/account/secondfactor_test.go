// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package account_test

import (
	"context"
	"net/http"
	"testing"
)

// addFactor gives the account id a confirmed TOTP factor with one recovery code
// and an open sign-in challenge. Removing a factor never decrypts it, so the
// secret only has to satisfy the schema.
func (e env) addFactor(t *testing.T, id string) {
	t.Helper()
	for _, statement := range []string{
		`INSERT INTO totp_factors (user_id, secret, confirmed_at, last_used_step)
VALUES ($1, decode(repeat('01', 49), 'hex'), clock_timestamp(), 0)`,
		`INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, sha256('\x00'::bytea))`,
		`INSERT INTO sign_in_challenges (token_hash, user_id) VALUES (sha256(uuid_send($1::uuid)), $1)`,
	} {
		if _, err := e.owner.Exec(t.Context(), statement, id); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

// An administrator removes the second factor of a user who lost the
// authenticator and the recovery codes. The sessions of the account end, and
// so does a sign-in that waits for the factor.
func TestUpdateUser_RemovesTheSecondFactor(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	id, userCookie := e.signIn(t, "jane@example.com", "viewer")
	e.addFactor(t, id)

	r := e.do(t, http.MethodGet, "/api/v1/users/"+id, cookie, nil)
	if r.body["totp_enabled"] != true {
		t.Fatalf("totp_enabled = %v, want true", r.body["totp_enabled"])
	}
	r = e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, map[string]any{"totp_enabled": false, "password": testPassword})
	if r.status != http.StatusOK || r.body["totp_enabled"] != false {
		t.Fatalf("remove factor: status %d, body %s; want 200 with totp_enabled false", r.status, r.raw)
	}
	for table, want := range map[string]int{"totp_factors": 0, "recovery_codes": 0, "sign_in_challenges": 0, "sessions": 0} {
		if n := e.count(t, `SELECT count(*) FROM `+table+` WHERE user_id = $1`, id); n != want {
			t.Errorf("%s of the account: %d, want %d", table, n, want)
		}
	}
	if r := e.do(t, http.MethodGet, "/api/v1/session", userCookie, nil); r.status != http.StatusUnauthorized {
		t.Errorf("session of the account: status %d, want 401", r.status)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'user.totp_disable' AND resource_id = $1 AND auth_method = 'session'`, id); n != 1 {
		t.Errorf("recorded %d removals, want 1", n)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'user.update' AND resource_id = $1`, id); n != 0 {
		t.Errorf("recorded %d updates, want none for the removal alone", n)
	}

	// Without a factor, the request changes nothing and records nothing.
	if r := e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, map[string]any{"totp_enabled": false, "password": testPassword}); r.status != http.StatusOK {
		t.Errorf("remove again: status %d, want 200", r.status)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'user.totp_disable'`); n != 1 {
		t.Errorf("recorded %d removals after the second request, want 1", n)
	}
}

func TestUpdateUser_SecondFactorRules(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	adminID, cookie := e.signIn(t, "ada@example.com", "admin")
	e.addFactor(t, adminID)

	if r := e.do(t, http.MethodPatch, "/api/v1/users/"+adminID, cookie, map[string]any{"totp_enabled": false, "password": testPassword}); r.status != http.StatusConflict || r.code() != "own_account" {
		t.Errorf("own factor: status %d, body %s; want 409 own_account", r.status, r.raw)
	}
	if n := e.count(t, `SELECT count(*) FROM totp_factors WHERE user_id = $1`, adminID); n != 1 {
		t.Errorf("own factor removed")
	}
	id, _ := e.signIn(t, "jane@example.com", "viewer")
	if r := e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, map[string]any{"totp_enabled": true, "password": testPassword}); r.status != http.StatusBadRequest {
		t.Errorf("enable a factor: status %d, want 400", r.status)
	}

	// A rename and the removal take effect together and are recorded each.
	e.addFactor(t, id)
	r := e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, map[string]any{"display_name": "Jane Roe", "totp_enabled": false, "password": testPassword})
	if r.status != http.StatusOK || r.body["display_name"] != "Jane Roe" || r.body["totp_enabled"] != false {
		t.Errorf("rename and remove: status %d, body %s", r.status, r.raw)
	}
	for _, action := range []string{"user.update", "user.totp_disable"} {
		if n := e.count(t, `SELECT count(*) FROM audit_entries WHERE action = $1 AND resource_id = $2`, action, id); n != 1 {
			t.Errorf("recorded %d entries of %s, want 1", n, action)
		}
	}
}

// The removal of a second factor, with a reset link, would let a taken-over
// session of an administrator take over another account, so the administrator
// confirms it with their own password.
func TestUpdateUser_RemovingASecondFactorRequiresThePassword(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	adminID, cookie := e.signIn(t, "ada@example.com", "admin")
	id, _ := e.signIn(t, "jane@example.com", "viewer")
	e.addFactor(t, id)
	path := "/api/v1/users/" + id

	if r := e.do(t, http.MethodPatch, path, cookie, map[string]any{"totp_enabled": false}); r.status != http.StatusBadRequest {
		t.Errorf("without password: status %d, want 400", r.status)
	}
	if r := e.do(t, http.MethodPatch, path, cookie, map[string]any{"display_name": "Jane", "password": testPassword}); r.status != http.StatusBadRequest {
		t.Errorf("password without totp_enabled: status %d, want 400", r.status)
	}
	r := e.do(t, http.MethodPatch, path, cookie, map[string]any{"totp_enabled": false, "password": "wrong horse battery"})
	if r.status != http.StatusForbidden || r.code() != "wrong_password" {
		t.Fatalf("wrong password: status %d, body %s; want 403 wrong_password", r.status, r.raw)
	}
	if n := e.count(t, `SELECT failed_logins FROM users WHERE id = $1`, adminID); n != 1 {
		t.Errorf("failed_logins of the administrator = %d, want the wrong password counted", n)
	}
	if n := e.count(t, `SELECT count(*) FROM totp_factors WHERE user_id = $1`, id); n != 1 {
		t.Errorf("factor removed with a wrong password")
	}
	if n := e.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'user.totp_disable' AND outcome = 'failure' AND resource_id = $1`, id); n != 1 {
		t.Errorf("recorded %d failed removals, want 1", n)
	}

	// While the administrator is locked, only the correct password learns it.
	e.exec(t, `UPDATE users SET locked_until = clock_timestamp() + interval '15 minutes' WHERE id = $1`, adminID)
	if r := e.do(t, http.MethodPatch, path, cookie, map[string]any{"totp_enabled": false, "password": "wrong horse battery"}); r.code() != "wrong_password" {
		t.Errorf("wrong password while locked: status %d, body %s; want wrong_password", r.status, r.raw)
	}
	r = e.do(t, http.MethodPatch, path, cookie, map[string]any{"totp_enabled": false, "password": testPassword})
	if r.status != http.StatusForbidden || r.code() != "account_locked" || r.header.Get("Retry-After") == "" {
		t.Errorf("correct password while locked: status %d, body %s; want 403 account_locked with Retry-After", r.status, r.raw)
	}
	if n := e.count(t, `SELECT count(*) FROM totp_factors WHERE user_id = $1`, id); n != 1 {
		t.Errorf("factor removed while the administrator is locked")
	}
}

// The removal locks the administrators before the account, in the order of
// every change of accounts, so that two administrators removing each other's
// factor wait for each other instead of deadlocking.
func TestUpdateUser_RemovingASecondFactorLocksTheAdministratorsFirst(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	// Another administrator, uninvolved in the removal: only taking the locks
	// of all administrators waits for it.
	otherID, _ := e.signIn(t, "carl@example.com", "admin")
	id, _ := e.signIn(t, "jane@example.com", "viewer")
	e.addFactor(t, id)

	holder, err := e.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := holder.Exec(t.Context(), `SELECT FROM users WHERE id = $1 FOR UPDATE`, otherID); err != nil {
		t.Fatal(err)
	}
	done := make(chan response, 1)
	go func() {
		done <- e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, map[string]any{"totp_enabled": false, "password": testPassword})
	}()
	waitForLockWaiter(t, e.owner, done)

	if _, err := e.owner.Exec(t.Context(), `SELECT FROM users WHERE id = $1 FOR UPDATE NOWAIT`, id); err != nil {
		t.Errorf("lock the account while the removal waits for the administrators: error = %v, want it unlocked", err)
	}
	if err := holder.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r := <-done; r.status != http.StatusOK {
		t.Errorf("removal: status %d, body %s; want 200", r.status, r.raw)
	}
}

func (e env) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := e.owner.Exec(t.Context(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}
