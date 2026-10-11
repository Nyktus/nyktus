// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/auth/totp"
)

// step returns the current time step of the database, whose clock checks the
// codes.
func step(t *testing.T, d testDB) int64 {
	t.Helper()
	return int64(d.count(t, `SELECT floor(extract(epoch FROM clock_timestamp()) / 30)::int`))
}

func jsonBody(t *testing.T, v map[string]string) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// enableTOTP sets up and confirms a TOTP factor through the session cookie and
// returns the secret, the recovery codes and the session cookie that replaces
// cookie. The confirmation uses the code of the previous time step, so that the
// codes of the current and the next one remain for the test.
func enableTOTP(t *testing.T, srv *httptest.Server, d testDB, cookie *http.Cookie) ([]byte, []string, *http.Cookie) {
	t.Helper()
	r := send(t, srv, http.MethodPost, "/api/v1/session/totp", jsonBody(t, map[string]string{"password": testPassword}), cookie, nil)
	if r.status != http.StatusCreated {
		t.Fatalf("begin TOTP setup: status %d, body %v", r.status, r.body)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(r.body["secret"].(string))
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	r = send(t, srv, http.MethodPost, "/api/v1/session/totp/confirmation",
		jsonBody(t, map[string]string{"code": totp.Code(secret, step(t, d)-1)}), cookie, nil)
	if r.status != http.StatusOK || r.cookie == nil {
		t.Fatalf("confirm TOTP factor: status %d, body %v", r.status, r.body)
	}
	var codes []string
	for _, c := range r.body["recovery_codes"].([]any) {
		codes = append(codes, c.(string))
	}
	return secret, codes, r.cookie
}

// challengeHeader sends the challenge cookie c.
func challengeHeader(c *http.Cookie) map[string]string {
	return map[string]string{"Cookie": c.Name + "=" + c.Value}
}

// startSignIn signs in ada@example.com, which has a second factor, and returns
// the challenge cookie.
func startSignIn(t *testing.T, srv *httptest.Server) *http.Cookie {
	t.Helper()
	r := signIn(t, srv, "ada@example.com", testPassword, nil)
	if r.status != http.StatusAccepted || r.challenge == nil {
		t.Fatalf("sign in: status %d, body %v; want 202 with a challenge", r.status, r.body)
	}
	return r.challenge
}

func completeSignIn(t *testing.T, srv *httptest.Server, challenge *http.Cookie, proof map[string]string, cookie *http.Cookie) response {
	t.Helper()
	var header map[string]string
	if challenge != nil {
		header = challengeHeader(challenge)
	}
	return send(t, srv, http.MethodPost, "/api/v1/session/second-factor", jsonBody(t, proof), cookie, header)
}

func errorCode(r response) string {
	e, _ := r.body["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

func TestSignIn_WithTOTPTakesTheSecondFactor(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	id := createUser(t, d, "ada@example.com", "viewer", "active", testPassword)
	srv := startConsole(t, d)
	secret, _, cookie := enableTOTP(t, srv, d, mustSignIn(t, srv))

	r := signIn(t, srv, "ada@example.com", testPassword, nil)
	if r.status != http.StatusAccepted || r.cookie != nil {
		t.Fatalf("sign in: status %d, session cookie %v; want 202 without a session", r.status, r.cookie)
	}
	if r.body["second_factor"] != "totp" || r.body["expires_at"] == nil {
		t.Errorf("body = %v, want second_factor totp and expires_at", r.body)
	}
	c := r.challenge
	if c == nil || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.MaxAge < 290 || c.MaxAge > 300 {
		t.Fatalf("challenge cookie = %+v, want HttpOnly, Secure, SameSite=Strict, Path=/ and five minutes", c)
	}

	// The session that the client still holds ends with the sign-in.
	code := totp.Code(secret, step(t, d))
	r = completeSignIn(t, srv, c, map[string]string{"code": code}, cookie)
	if r.status != http.StatusOK || r.cookie == nil {
		t.Fatalf("complete sign-in: status %d, body %v", r.status, r.body)
	}
	if r.challenge == nil || r.challenge.MaxAge >= 0 {
		t.Errorf("challenge cookie = %+v, want it cleared", r.challenge)
	}
	if user, _ := r.body["user"].(map[string]any); user["totp_enabled"] != true {
		t.Errorf("user = %v, want totp_enabled", r.body["user"])
	}
	if got := send(t, srv, http.MethodGet, "/api/v1/session", "", cookie, nil); got.status != http.StatusUnauthorized {
		t.Errorf("previous session: status %d, want 401", got.status)
	}
	if got := send(t, srv, http.MethodGet, "/api/v1/session", "", r.cookie, nil); got.status != http.StatusOK {
		t.Errorf("new session: status %d, want 200", got.status)
	}
	// The challenge is used up, and the code too.
	if got := completeSignIn(t, srv, c, map[string]string{"code": code}, nil); errorCode(got) != "invalid_challenge" {
		t.Errorf("used challenge: status %d, body %v; want invalid_challenge", got.status, got.body)
	}
	if got := completeSignIn(t, srv, startSignIn(t, srv), map[string]string{"code": code}, nil); got.status != http.StatusUnauthorized || errorCode(got) != "invalid_code" {
		t.Errorf("used code: status %d, body %v; want 401 invalid_code", got.status, got.body)
	}

	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'sign_in_challenge.create' AND auth_method = 'password' AND actor_user_id = $1`, id); n != 2 {
		t.Errorf("recorded %d challenges, want 2", n)
	}
	if n := d.count(t, `
SELECT count(*) FROM audit_entries
WHERE action = 'session.create' AND auth_method = 'totp' AND actor_user_id = $1 AND outcome = 'success' AND resource_type = 'session'`, id); n != 1 {
		t.Errorf("recorded %d sign-ins with TOTP, want 1", n)
	}
}

func TestCompleteSignIn_RecoveryCodeWorksOnce(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	id := createUser(t, d, "ada@example.com", "viewer", "active", testPassword)
	srv := startConsole(t, d)
	_, codes, _ := enableTOTP(t, srv, d, mustSignIn(t, srv))

	if r := completeSignIn(t, srv, startSignIn(t, srv), map[string]string{"recovery_code": codes[0]}, nil); r.status != http.StatusOK {
		t.Fatalf("recovery code: status %d, body %v", r.status, r.body)
	}
	if r := completeSignIn(t, srv, startSignIn(t, srv), map[string]string{"recovery_code": codes[0]}, nil); errorCode(r) != "invalid_code" {
		t.Errorf("used recovery code: status %d, body %v; want invalid_code", r.status, r.body)
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'session.create' AND auth_method = 'recovery_code' AND actor_user_id = $1`, id); n != 2 {
		t.Errorf("recorded %d attempts with a recovery code, want 2", n)
	}
}

// A wrong code counts as a failed sign-in. The correct password does not start
// the count again while the second factor is missing, or whoever knows the
// password could guess codes without limit.
func TestCompleteSignIn_WrongCodesCountTowardsTheLock(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	id := createUser(t, d, "ada@example.com", "viewer", "active", testPassword)
	srv := startConsole(t, d)
	secret, _, _ := enableTOTP(t, srv, d, mustSignIn(t, srv))
	wrong := map[string]string{"code": totp.Code(secret, step(t, d)+5)}

	first := startSignIn(t, srv)
	for i := range 4 {
		r := completeSignIn(t, srv, first, wrong, nil)
		if r.status != http.StatusUnauthorized || errorCode(r) != "invalid_code" || r.header.Get("WWW-Authenticate") == "" {
			t.Fatalf("wrong code %d: status %d, body %v; want 401 invalid_code", i+1, r.status, r.body)
		}
	}
	if n := d.count(t, `SELECT failed_logins FROM users WHERE id = $1`, id); n != 4 {
		t.Fatalf("failed_logins = %d after four wrong codes, want 4", n)
	}

	second := startSignIn(t, srv)
	if n := d.count(t, `SELECT failed_logins FROM users WHERE id = $1`, id); n != 4 {
		t.Errorf("failed_logins = %d after the correct password, want it kept at 4", n)
	}
	r := completeSignIn(t, srv, second, wrong, nil)
	if r.status != http.StatusForbidden || errorCode(r) != "account_locked" || r.header.Get("Retry-After") == "" {
		t.Fatalf("fifth wrong code: status %d, body %v; want 403 account_locked with Retry-After", r.status, r.body)
	}
	if r.challenge == nil || r.challenge.MaxAge >= 0 {
		t.Errorf("challenge cookie = %+v, want it cleared", r.challenge)
	}
	// The lock ends both challenges: the one it hit, and the first one with
	// the next attempt.
	correct := map[string]string{"code": totp.Code(secret, step(t, d))}
	if r := completeSignIn(t, srv, second, correct, nil); errorCode(r) != "invalid_challenge" {
		t.Errorf("challenge after the lock: status %d, body %v; want invalid_challenge", r.status, r.body)
	}
	if r := completeSignIn(t, srv, first, correct, nil); r.status != http.StatusForbidden || errorCode(r) != "account_locked" {
		t.Errorf("older challenge during the lock: status %d, body %v; want account_locked", r.status, r.body)
	}
	if r := completeSignIn(t, srv, first, correct, nil); errorCode(r) != "invalid_challenge" {
		t.Errorf("older challenge after it met the lock: status %d, body %v; want invalid_challenge", r.status, r.body)
	}
	if n := d.count(t, `
SELECT count(*) FROM audit_entries
WHERE action = 'session.create' AND auth_method = 'totp' AND outcome = 'failure' AND actor_user_id = $1`, id); n != 6 {
		t.Errorf("recorded %d failures with TOTP, want 6", n)
	}
}

// Requests without a valid challenge are rejected like requests without
// credentials: the same answer, and no audit entry.
func TestCompleteSignIn_RejectsInvalidChallenges(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	createUser(t, d, "ada@example.com", "viewer", "active", testPassword)
	srv := startConsole(t, d)
	secret, codes, _ := enableTOTP(t, srv, d, mustSignIn(t, srv))
	code := map[string]string{"code": totp.Code(secret, step(t, d))}

	expired := startSignIn(t, srv)
	d.exec(t, `UPDATE sign_in_challenges SET expires_at = clock_timestamp() - interval '1 second'`)
	before := d.count(t, `SELECT count(*) FROM audit_entries`)

	unknown := &http.Cookie{Name: session.ChallengeCookieName, Value: "unknown", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	for name, c := range map[string]*http.Cookie{"missing": nil, "unknown": unknown, "expired": expired} {
		r := completeSignIn(t, srv, c, code, nil)
		if r.status != http.StatusUnauthorized || errorCode(r) != "invalid_challenge" {
			t.Errorf("%s challenge: status %d, body %v; want 401 invalid_challenge", name, r.status, r.body)
		}
	}
	if after := d.count(t, `SELECT count(*) FROM audit_entries`); after != before {
		t.Errorf("invalid challenges added %d audit entries, want none", after-before)
	}

	valid := startSignIn(t, srv)
	for _, proof := range []map[string]string{{}, {"code": code["code"], "recovery_code": codes[0]}} {
		if r := completeSignIn(t, srv, valid, proof, nil); r.status != http.StatusBadRequest {
			t.Errorf("proof %v: status %d, want 400", proof, r.status)
		}
	}
}

// A change of password ends the sign-ins that wait for their second factor, so
// that the old password cannot complete one.
func TestCompleteSignIn_PasswordChangeEndsOpenChallenges(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	createUser(t, d, "ada@example.com", "viewer", "active", testPassword)
	srv := startConsole(t, d)
	secret, _, cookie := enableTOTP(t, srv, d, mustSignIn(t, srv))

	challenge := startSignIn(t, srv)
	if r := send(t, srv, http.MethodPut, "/api/v1/session/password", changeBody(testPassword, "a brand new horse battery"), cookie, nil); r.status != http.StatusNoContent {
		t.Fatalf("change password: status %d, body %v", r.status, r.body)
	}
	r := completeSignIn(t, srv, challenge, map[string]string{"code": totp.Code(secret, step(t, d))}, nil)
	if errorCode(r) != "invalid_challenge" {
		t.Errorf("challenge after a change of password: status %d, body %v; want invalid_challenge", r.status, r.body)
	}
}

// The second step locks the account before it checks the challenge and the
// code, as every change of the account does. Two requests with the same code
// are therefore checked one after the other, and a change that removes the
// challenge, such as a reset, cannot overlap.
func TestCompleteSignIn_LocksTheAccountFirst(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	id := createUser(t, d, "ada@example.com", "viewer", "active", testPassword)
	srv := startConsole(t, d)
	secret, _, _ := enableTOTP(t, srv, d, mustSignIn(t, srv))
	challenge := startSignIn(t, srv)

	holder, err := d.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := holder.Exec(t.Context(), `SELECT FROM users WHERE id = $1 FOR UPDATE`, id); err != nil {
		t.Fatal(err)
	}

	done := make(chan response, 1)
	go func() {
		done <- completeSignIn(t, srv, challenge, map[string]string{"code": totp.Code(secret, step(t, d))}, nil)
	}()
	waitForLockWaiter(t, d, done)

	if _, err := d.owner.Exec(t.Context(), `SELECT FROM totp_factors WHERE user_id = $1 FOR UPDATE NOWAIT`, id); err != nil {
		t.Errorf("lock the factor while the sign-in waits for the account: error = %v, want it unlocked", err)
	}
	if err := holder.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r := <-done; r.status != http.StatusOK {
		t.Errorf("complete sign-in: status %d, body %v; want 200", r.status, r.body)
	}
}

// waitForLockWaiter returns once a session of the test database waits for a
// lock, or fails the test if done receives first.
func waitForLockWaiter(t *testing.T, d testDB, done <-chan response) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		var waiting bool
		err := d.owner.QueryRow(ctx, `
SELECT EXISTS (SELECT FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting)
		if err != nil {
			t.Fatalf("query waiting sessions: %v", err)
		}
		if waiting {
			return
		}
		select {
		case r := <-done:
			t.Fatalf("the request completed without waiting for the account: status %d", r.status)
		default:
		}
	}
}

func TestBeginTOTP_RequiresThePassword(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	id := createUser(t, d, "ada@example.com", "viewer", "active", testPassword)
	srv := startConsole(t, d)
	cookie := mustSignIn(t, srv)

	r := send(t, srv, http.MethodPost, "/api/v1/session/totp", jsonBody(t, map[string]string{"password": "wrong horse battery"}), cookie, nil)
	if r.status != http.StatusForbidden || errorCode(r) != "wrong_password" {
		t.Fatalf("wrong password: status %d, body %v; want 403 wrong_password", r.status, r.body)
	}
	if n := d.count(t, `SELECT failed_logins FROM users WHERE id = $1`, id); n != 1 {
		t.Errorf("failed_logins = %d, want the wrong password counted", n)
	}
	if n := d.count(t, `SELECT count(*) FROM totp_factors`); n != 0 {
		t.Errorf("%d factors after a wrong password, want none", n)
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'user.totp_enroll' AND outcome = 'failure'`); n != 1 {
		t.Errorf("recorded %d failed setups, want 1", n)
	}

	r = send(t, srv, http.MethodPost, "/api/v1/session/totp", jsonBody(t, map[string]string{"password": testPassword}), cookie, nil)
	if r.status != http.StatusCreated {
		t.Fatalf("begin: status %d, body %v", r.status, r.body)
	}
	if uri, _ := r.body["uri"].(string); uri != totp.URI("Nyktus", "ada@example.com", mustDecode(t, r.body["secret"].(string))) {
		t.Errorf("uri = %q, want the otpauth URI of the secret", uri)
	}
	if got := send(t, srv, http.MethodGet, "/api/v1/session", "", cookie, nil); got.body["user"].(map[string]any)["totp_enabled"] != false {
		t.Errorf("totp_enabled before the confirmation = %v, want false", got.body["user"])
	}
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Enabling the second factor ends every other session, which began without it,
// and replaces the session of the caller.
func TestConfirmTOTP_EndsOtherSessions(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	id := createUser(t, d, "ada@example.com", "viewer", "active", testPassword)
	srv := startConsole(t, d)
	other := mustSignIn(t, srv)
	cookie := mustSignIn(t, srv)

	r := send(t, srv, http.MethodPost, "/api/v1/session/totp/confirmation", jsonBody(t, map[string]string{"code": "123456"}), cookie, nil)
	if r.status != http.StatusConflict || errorCode(r) != "no_totp_setup" {
		t.Errorf("confirm without a setup: status %d, body %v; want 409 no_totp_setup", r.status, r.body)
	}
	r = send(t, srv, http.MethodPost, "/api/v1/session/totp", jsonBody(t, map[string]string{"password": testPassword}), cookie, nil)
	secret := mustDecode(t, r.body["secret"].(string))
	r = send(t, srv, http.MethodPost, "/api/v1/session/totp/confirmation",
		jsonBody(t, map[string]string{"code": totp.Code(secret, step(t, d)+5)}), cookie, nil)
	if r.status != http.StatusForbidden || errorCode(r) != "wrong_code" {
		t.Errorf("wrong code: status %d, body %v; want 403 wrong_code", r.status, r.body)
	}
	if n := d.count(t, `SELECT failed_logins FROM users WHERE id = $1`, id); n != 1 {
		t.Errorf("failed_logins = %d after a wrong code at the confirmation, want it counted", n)
	}

	r = send(t, srv, http.MethodPost, "/api/v1/session/totp/confirmation",
		jsonBody(t, map[string]string{"code": totp.Code(secret, step(t, d))}), cookie, nil)
	if r.status != http.StatusOK || r.cookie == nil {
		t.Fatalf("confirm: status %d, body %v", r.status, r.body)
	}
	if codes, _ := r.body["recovery_codes"].([]any); len(codes) != totp.RecoveryCodeCount {
		t.Errorf("recovery codes = %v, want %d", r.body["recovery_codes"], totp.RecoveryCodeCount)
	}
	for name, c := range map[string]*http.Cookie{"other session": other, "replaced session": cookie} {
		if got := send(t, srv, http.MethodGet, "/api/v1/session", "", c, nil); got.status != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, got.status)
		}
	}
	got := send(t, srv, http.MethodGet, "/api/v1/session", "", r.cookie, nil)
	if got.status != http.StatusOK || got.body["user"].(map[string]any)["totp_enabled"] != true {
		t.Errorf("new session: status %d, user %v; want totp_enabled", got.status, got.body["user"])
	}
	r = send(t, srv, http.MethodPost, "/api/v1/session/totp", jsonBody(t, map[string]string{"password": testPassword}), r.cookie, nil)
	if r.status != http.StatusConflict || errorCode(r) != "totp_enabled" {
		t.Errorf("second setup: status %d, body %v; want 409 totp_enabled", r.status, r.body)
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'user.totp_enable' AND resource_id = $1`, id); n != 3 {
		t.Errorf("recorded %d confirmations, want 3 (no setup, wrong code, success)", n)
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'user.totp_enroll' AND outcome = 'failure' AND resource_id = $1`, id); n != 1 {
		t.Errorf("recorded %d failed setups, want the second setup", n)
	}
}

// A taken-over session cannot guess the code of a setup: wrong codes count
// towards the lock, and a locked account cannot confirm.
func TestConfirmTOTP_WrongCodesCountTowardsTheLock(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	id := createUser(t, d, "ada@example.com", "viewer", "active", testPassword)
	srv := startConsole(t, d)
	cookie := mustSignIn(t, srv)
	r := send(t, srv, http.MethodPost, "/api/v1/session/totp", jsonBody(t, map[string]string{"password": testPassword}), cookie, nil)
	secret := mustDecode(t, r.body["secret"].(string))

	wrong := jsonBody(t, map[string]string{"code": totp.Code(secret, step(t, d)+5)})
	for range 5 {
		send(t, srv, http.MethodPost, "/api/v1/session/totp/confirmation", wrong, cookie, nil)
	}
	r = send(t, srv, http.MethodPost, "/api/v1/session/totp/confirmation",
		jsonBody(t, map[string]string{"code": totp.Code(secret, step(t, d))}), cookie, nil)
	if r.status != http.StatusForbidden || errorCode(r) != "account_locked" {
		t.Errorf("correct code while locked: status %d, body %v; want 403 account_locked", r.status, r.body)
	}
	if n := d.count(t, `SELECT count(*) FROM totp_factors WHERE user_id = $1 AND confirmed_at IS NOT NULL`, id); n != 0 {
		t.Errorf("factor confirmed while the account is locked")
	}
}

func TestReplaceRecoveryCodes_RequiresPasswordAndCode(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	id := createUser(t, d, "ada@example.com", "viewer", "active", testPassword)
	srv := startConsole(t, d)
	secret, old, cookie := enableTOTP(t, srv, d, mustSignIn(t, srv))

	replace := func(pw string, proof map[string]string) response {
		body := map[string]string{"password": pw}
		for k, v := range proof {
			body[k] = v
		}
		return send(t, srv, http.MethodPost, "/api/v1/session/totp/recovery-codes", jsonBody(t, body), cookie, nil)
	}
	if r := replace(testPassword, map[string]string{"code": totp.Code(secret, step(t, d)+5)}); r.status != http.StatusForbidden || errorCode(r) != "wrong_code" {
		t.Errorf("wrong code: status %d, body %v; want 403 wrong_code", r.status, r.body)
	}
	if n := d.count(t, `SELECT failed_logins FROM users WHERE id = $1`, id); n != 1 {
		t.Errorf("failed_logins = %d, want the wrong code counted", n)
	}
	if r := replace("wrong horse battery", map[string]string{"code": totp.Code(secret, step(t, d))}); errorCode(r) != "wrong_password" {
		t.Errorf("wrong password: status %d, body %v; want wrong_password", r.status, r.body)
	}

	r := replace(testPassword, map[string]string{"recovery_code": old[0]})
	if r.status != http.StatusOK {
		t.Fatalf("replace: status %d, body %v", r.status, r.body)
	}
	fresh, _ := r.body["recovery_codes"].([]any)
	if len(fresh) != totp.RecoveryCodeCount {
		t.Fatalf("recovery codes = %v", r.body)
	}
	if r := completeSignIn(t, srv, startSignIn(t, srv), map[string]string{"recovery_code": old[1]}, nil); errorCode(r) != "invalid_code" {
		t.Errorf("replaced recovery code: status %d, body %v; want invalid_code", r.status, r.body)
	}
	if r := completeSignIn(t, srv, startSignIn(t, srv), map[string]string{"recovery_code": fresh[0].(string)}, nil); r.status != http.StatusOK {
		t.Errorf("new recovery code: status %d, body %v; want 200", r.status, r.body)
	}
}

func TestRemoveTOTP_EndsSessionsAndTheSecondStep(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	id := createUser(t, d, "ada@example.com", "viewer", "active", testPassword)
	srv := startConsole(t, d)
	secret, codes, cookie := enableTOTP(t, srv, d, mustSignIn(t, srv))
	other := completeSignIn(t, srv, startSignIn(t, srv), map[string]string{"recovery_code": codes[0]}, nil).cookie
	pending := startSignIn(t, srv)

	remove := func(body map[string]string) response {
		return send(t, srv, http.MethodDelete, "/api/v1/session/totp", jsonBody(t, body), cookie, nil)
	}
	if r := remove(map[string]string{"password": testPassword}); r.status != http.StatusBadRequest {
		t.Errorf("without a code: status %d, want 400", r.status)
	}
	if r := remove(map[string]string{"password": "wrong horse battery", "code": totp.Code(secret, step(t, d))}); errorCode(r) != "wrong_password" {
		t.Errorf("wrong password: status %d, body %v; want wrong_password", r.status, r.body)
	}
	r := remove(map[string]string{"password": testPassword, "code": totp.Code(secret, step(t, d))})
	if r.status != http.StatusNoContent || r.cookie == nil {
		t.Fatalf("remove: status %d, body %v; want 204 with a new session cookie", r.status, r.body)
	}
	for name, c := range map[string]*http.Cookie{"other session": other, "replaced session": cookie} {
		if got := send(t, srv, http.MethodGet, "/api/v1/session", "", c, nil); got.status != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, got.status)
		}
	}
	if got := completeSignIn(t, srv, pending, map[string]string{"recovery_code": codes[1]}, nil); errorCode(got) != "invalid_challenge" {
		t.Errorf("open challenge: status %d, body %v; want invalid_challenge", got.status, got.body)
	}
	if got := signIn(t, srv, "ada@example.com", testPassword, nil); got.status != http.StatusOK {
		t.Errorf("sign in without a factor: status %d, want 200", got.status)
	}
	if got := send(t, srv, http.MethodDelete, "/api/v1/session/totp",
		jsonBody(t, map[string]string{"password": testPassword, "code": "123456"}), r.cookie, nil); errorCode(got) != "totp_not_enabled" {
		t.Errorf("remove again: status %d, body %v; want totp_not_enabled", got.status, got.body)
	}
	if n := d.count(t, `SELECT count(*) FROM recovery_codes`); n != 0 {
		t.Errorf("%d recovery codes left, want none", n)
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'user.totp_disable' AND outcome = 'success' AND resource_id = $1`, id); n != 1 {
		t.Errorf("recorded %d removals, want 1", n)
	}
}
