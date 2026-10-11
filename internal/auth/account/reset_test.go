// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package account_test

import (
	"context"
	"crypto/sha256"
	"net/http"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/user"
)

func resetTokenOf(t *testing.T, link string) string {
	t.Helper()
	tok, ok := strings.CutPrefix(link, consoleURL+"/reset-password#token=")
	if !ok || len(tok) != 43 {
		t.Fatalf("password reset link %q does not have the form %s/reset-password#token=<43 characters>", link, consoleURL)
	}
	return tok
}

// issueReset requests a password reset link for the account id and returns its
// token.
func (e env) issueReset(t *testing.T, cookie, id string) string {
	t.Helper()
	r := e.do(t, http.MethodPost, "/api/v1/users/"+id+"/password-reset-link", cookie, nil)
	if r.status != http.StatusCreated {
		t.Fatalf("issue password reset link: status %d, body %s", r.status, r.raw)
	}
	return resetTokenOf(t, r.body["url"].(string))
}

func (e env) reset(t *testing.T, tok, pw string) response {
	t.Helper()
	return e.do(t, http.MethodPost, "/api/v1/password-reset", "", map[string]string{"token": tok, "password": pw})
}

// A password reset link exists only for active accounts, also locked ones. It is
// stored as a hash and replaces the previous link of the account.
func TestIssueResetLink_OnlyForActiveAccounts(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	adminID, cookie := e.signIn(t, "ada@example.com", "admin")
	janeID, _ := e.signIn(t, "jane@example.com", "viewer")
	pendingID, _ := e.create(t, cookie, "pending@example.com")
	goneID, _ := e.signIn(t, "gone@example.com", "viewer")
	if r := e.do(t, http.MethodPatch, "/api/v1/users/"+goneID, cookie, map[string]string{"status": "deactivated"}); r.status != http.StatusOK {
		t.Fatalf("deactivate: status %d", r.status)
	}
	if _, err := e.owner.Exec(t.Context(), `UPDATE users SET locked_until = clock_timestamp() + interval '15 minutes' WHERE id = $1`, janeID); err != nil {
		t.Fatalf("lock: %v", err)
	}

	for name, id := range map[string]string{"pending": pendingID, "deactivated": goneID} {
		r := e.do(t, http.MethodPost, "/api/v1/users/"+id+"/password-reset-link", cookie, nil)
		if r.status != http.StatusConflict || r.code() != "invalid_state" {
			t.Errorf("%s: status %d, body %s; want 409 invalid_state", name, r.status, r.raw)
		}
	}
	if r := e.do(t, http.MethodPost, "/api/v1/users/"+unknownID+"/password-reset-link", cookie, nil); r.status != http.StatusNotFound {
		t.Errorf("unknown account: status %d, want 404", r.status)
	}

	first := e.issueReset(t, cookie, janeID)
	tok := e.issueReset(t, cookie, janeID)
	sum := sha256.Sum256([]byte(tok))
	if n := e.count(t, `SELECT count(*) FROM account_links WHERE user_id = $1 AND token_hash = $2 AND purpose = 'password_reset'`, janeID, sum[:]); n != 1 {
		t.Errorf("stored links for the token = %d, want 1 with the hash of the token", n)
	}
	if r := e.reset(t, first, "a new password for jane"); r.status != http.StatusNotFound {
		t.Errorf("replaced link: status %d, want 404", r.status)
	}
	entries := e.auditEntries(t, "password_reset_link.create")
	if len(entries) != 2 || entries[0].Kind != "user" || entries[0].Method != "session" ||
		deref(entries[0].ActorID) != adminID || deref(entries[0].ResourceID) != janeID {
		t.Errorf("audit entries = %+v, want two by the administrator for the account", entries)
	}
}

// Issuing a link changes nothing else. Using it sets the password, ends every
// session of the account and its lock, and does not sign in.
func TestResetPassword_SetsThePasswordAndEndsSessionsAndLock(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	janeID, janeCookie := e.signIn(t, "jane@example.com", "viewer")
	tok := e.issueReset(t, cookie, janeID)
	if r := e.do(t, http.MethodGet, "/api/v1/session", janeCookie, nil); r.status != http.StatusOK {
		t.Fatalf("issuing the link ended the session: status %d", r.status)
	}
	if e.startSession(t, "jane@example.com", testPassword) == "" {
		t.Fatal("issuing the link changed the password")
	}
	for range user.MaxFailedLogins {
		e.startSession(t, "jane@example.com", "wrong horse battery")
	}

	r := e.reset(t, tok, "a new password for jane")
	if r.status != http.StatusOK || r.body["id"] != janeID || r.body["status"] != "active" {
		t.Fatalf("reset: status %d, body %s; want 200 with the account", r.status, r.raw)
	}
	if len(r.cookies) != 0 {
		t.Error("the reset set a cookie; it must not sign in")
	}
	if r := e.do(t, http.MethodGet, "/api/v1/session", janeCookie, nil); r.status != http.StatusUnauthorized {
		t.Errorf("session after the reset: status %d, want 401", r.status)
	}
	if n := e.count(t, `SELECT count(*) FROM sessions WHERE user_id = $1`, janeID); n != 0 {
		t.Errorf("%d sessions after the reset, want none", n)
	}
	if e.startSession(t, "jane@example.com", testPassword) != "" {
		t.Error("the old password still signs in")
	}
	if e.startSession(t, "jane@example.com", "a new password for jane") == "" {
		t.Error("the new password does not sign in; the lock must end with the reset")
	}
	if again := e.reset(t, tok, "another password for jane"); again.status != http.StatusNotFound {
		t.Errorf("second use: status %d, want 404", again.status)
	}
	if n := e.count(t, `SELECT count(*) FROM account_links`); n != 0 {
		t.Errorf("account links = %d, want the used one removed", n)
	}
	entries := e.auditEntries(t, "user.password_reset")
	if len(entries) != 1 || entries[0].Kind != "user" || entries[0].Method != "password_reset_token" ||
		deref(entries[0].ActorID) != janeID || deref(entries[0].ResourceID) != janeID {
		t.Errorf("audit entries = %+v, want one by the account through its token", entries)
	}
}

// Unknown, expired and used tokens, and activation tokens, receive the same
// response as a route that does not exist. The password is not validated without
// a valid token, and nothing is recorded in the audit log.
func TestResetPassword_InvalidTokensAnswerLikeAnUnknownRoute(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	expiredID, _ := e.signIn(t, "expired@example.com", "viewer")
	expired := e.issueReset(t, cookie, expiredID)
	if _, err := e.owner.Exec(t.Context(), `UPDATE account_links SET expires_at = clock_timestamp() - interval '1 second'`); err != nil {
		t.Fatalf("expire token: %v", err)
	}
	usedID, _ := e.signIn(t, "used@example.com", "viewer")
	used := e.issueReset(t, cookie, usedID)
	if r := e.reset(t, used, testPassword); r.status != http.StatusOK {
		t.Fatalf("reset: status %d", r.status)
	}
	_, activationTok := e.create(t, cookie, "pending@example.com")
	entriesBefore := e.count(t, `SELECT count(*) FROM audit_entries`)

	unknownRoute := e.do(t, http.MethodPost, "/api/v1/no-such-route", "", map[string]string{"token": "x", "password": testPassword})
	for name, tok := range map[string]string{"unknown": strings.Repeat("A", 43), "expired": expired, "used": used, "activation": activationTok, "empty": ""} {
		for _, pw := range []string{testPassword, "short"} {
			r := e.reset(t, tok, pw)
			if r.status != unknownRoute.status || !sameError(r.body, unknownRoute.body) || !headersEqual(r.header, unknownRoute.header) {
				t.Errorf("%s token, password %q: %d %v %s; want the response of an unknown route: %d %v %s",
					name, pw, r.status, r.header, r.raw, unknownRoute.status, unknownRoute.header, unknownRoute.raw)
			}
		}
	}
	if n := e.count(t, `SELECT count(*) FROM audit_entries`); n != entriesBefore {
		t.Errorf("audit entries grew from %d to %d, want no entries for invalid tokens", entriesBefore, n)
	}
	if r := e.activate(t, activationTok, testPassword); r.status != http.StatusOK {
		t.Errorf("the activation link no longer works after the attempts: status %d", r.status)
	}
}

func TestResetPassword_ValidTokenRequiresAValidPassword(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	janeID, _ := e.signIn(t, "jane@example.com", "viewer")
	tok := e.issueReset(t, cookie, janeID)

	if r := e.reset(t, tok, "short"); r.status != http.StatusBadRequest || r.code() != "invalid_request" {
		t.Errorf("short password: status %d, body %s; want 400", r.status, r.raw)
	}
	if r := e.reset(t, tok, "a new password for jane"); r.status != http.StatusOK {
		t.Errorf("the link no longer works after a rejected password: status %d", r.status)
	}
}

// Deactivating an account removes its password reset link, as it removes an
// activation link.
func TestUpdateUser_DeactivationRemovesThePasswordResetLink(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	janeID, _ := e.signIn(t, "jane@example.com", "viewer")
	tok := e.issueReset(t, cookie, janeID)
	if r := e.do(t, http.MethodPatch, "/api/v1/users/"+janeID, cookie, map[string]string{"status": "deactivated"}); r.status != http.StatusOK {
		t.Fatalf("deactivate: status %d", r.status)
	}
	if r := e.do(t, http.MethodPatch, "/api/v1/users/"+janeID, cookie, map[string]string{"status": "active"}); r.status != http.StatusOK {
		t.Fatalf("reactivate: status %d", r.status)
	}
	if r := e.reset(t, tok, "a new password for jane"); r.status != http.StatusNotFound {
		t.Errorf("link after deactivation: status %d, want 404", r.status)
	}
}

// The reset locks the account before its link, as the activation does, so that
// it cannot deadlock with a deactivation, which holds the account and then
// removes the link.
func TestResetPassword_LocksTheAccountBeforeTheLink(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	id, _ := e.signIn(t, "jane@example.com", "viewer")
	tok := e.issueReset(t, cookie, id)

	holder, err := e.owner.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = holder.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := holder.Exec(t.Context(), `SELECT FROM users WHERE id = $1 FOR UPDATE`, id); err != nil {
		t.Fatalf("lock account: %v", err)
	}

	done := make(chan response, 1)
	go func() { done <- e.reset(t, tok, "a new password for jane") }()
	waitForLockWaiter(t, e.owner, done)

	_, err = e.owner.Exec(t.Context(), `SELECT FROM account_links WHERE user_id = $1 FOR UPDATE NOWAIT`, id)
	if err != nil {
		t.Errorf("lock the link while the reset waits for the account: error = %v, want the link unlocked", err)
	}
	if err := holder.Commit(t.Context()); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if r := <-done; r.status != http.StatusOK {
		t.Errorf("reset: status %d, body %s; want 200", r.status, r.raw)
	}
}

// A password reset link is moot once the user has set a password by other
// means. It must not stay usable, for example from a chat history, after the
// user changed the password themselves.
func TestChangePassword_RemovesAnOpenPasswordResetLink(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	janeID, janeCookie := e.signIn(t, "jane@example.com", "viewer")
	tok := e.issueReset(t, cookie, janeID)

	r := e.do(t, http.MethodPut, "/api/v1/session/password", janeCookie,
		map[string]string{"current_password": testPassword, "new_password": "jane remembered it after all"})
	if r.status != http.StatusNoContent {
		t.Fatalf("change password: status %d, body %s", r.status, r.raw)
	}
	if r := e.reset(t, tok, "the password of whoever found the link"); r.status != http.StatusNotFound {
		t.Errorf("reset link after the change: status %d, want 404", r.status)
	}
	if n := e.count(t, `SELECT count(*) FROM account_links WHERE user_id = $1`, janeID); n != 0 {
		t.Errorf("account links = %d, want none", n)
	}
}
