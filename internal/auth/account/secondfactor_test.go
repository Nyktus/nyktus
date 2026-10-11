// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package account_test

import (
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
	r = e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, map[string]any{"totp_enabled": false})
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
	if r := e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, map[string]any{"totp_enabled": false}); r.status != http.StatusOK {
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

	if r := e.do(t, http.MethodPatch, "/api/v1/users/"+adminID, cookie, map[string]any{"totp_enabled": false}); r.status != http.StatusConflict || r.code() != "own_account" {
		t.Errorf("own factor: status %d, body %s; want 409 own_account", r.status, r.raw)
	}
	if n := e.count(t, `SELECT count(*) FROM totp_factors WHERE user_id = $1`, adminID); n != 1 {
		t.Errorf("own factor removed")
	}
	id, _ := e.signIn(t, "jane@example.com", "viewer")
	if r := e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, map[string]any{"totp_enabled": true}); r.status != http.StatusBadRequest {
		t.Errorf("enable a factor: status %d, want 400", r.status)
	}

	// A rename and the removal take effect together and are recorded each.
	e.addFactor(t, id)
	r := e.do(t, http.MethodPatch, "/api/v1/users/"+id, cookie, map[string]any{"display_name": "Jane Roe", "totp_enabled": false})
	if r.status != http.StatusOK || r.body["display_name"] != "Jane Roe" || r.body["totp_enabled"] != false {
		t.Errorf("rename and remove: status %d, body %s", r.status, r.raw)
	}
	for _, action := range []string{"user.update", "user.totp_disable"} {
		if n := e.count(t, `SELECT count(*) FROM audit_entries WHERE action = $1 AND resource_id = $2`, action, id); n != 1 {
			t.Errorf("recorded %d entries of %s, want 1", n, action)
		}
	}
}
