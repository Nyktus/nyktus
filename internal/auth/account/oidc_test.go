// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package account_test

import (
	"errors"
	"net/http"
	"testing"

	"nyktus.org/nyktus/internal/auth/account"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/auth/token"
	"nyktus.org/nyktus/internal/user"
)

// createOIDC inserts an active account of the identity provider and returns
// its ID and the cookie of a session, as the sign-in through the provider
// would start it.
func (e env) createOIDC(t *testing.T, email, role string) (id, cookie string) {
	t.Helper()
	err := e.owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, oidc_issuer, oidc_subject)
VALUES ($1, 'Test User', $2, 'active', 'https://idp.example.com', $1)
RETURNING id`, email, role).Scan(&id)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	tok, err := token.New()
	if err != nil {
		t.Fatalf("token.New() error = %v", err)
	}
	e.exec(t, `INSERT INTO sessions (token_hash, user_id) VALUES ($1, $2)`, token.Hash(tok), id)
	return id, session.CookieName + "=" + tok
}

// The provider manages the password and the role of its accounts.
// Administrators change their name and status, nothing else.
func TestUpdateUser_AccountsOfTheProvider(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, cookie := e.signIn(t, "ada@example.com", "admin")
	jane, _ := e.createOIDC(t, "jane@example.com", "viewer")

	r := e.do(t, http.MethodPatch, "/api/v1/users/"+jane, cookie, map[string]string{"role": "admin"})
	if r.status != http.StatusConflict || r.code() != account.CodeOIDCAccount {
		t.Errorf("change of role: %d %s, want 409 %s", r.status, r.raw, account.CodeOIDCAccount)
	}
	r = e.do(t, http.MethodPost, "/api/v1/users/"+jane+"/password-reset-link", cookie, nil)
	if r.status != http.StatusConflict || r.code() != account.CodeOIDCAccount {
		t.Errorf("password reset link: %d %s, want 409 %s", r.status, r.raw, account.CodeOIDCAccount)
	}
	if n := e.count(t, `SELECT count(*) FROM account_links`); n != 0 {
		t.Errorf("%d links, want none", n)
	}

	r = e.do(t, http.MethodPatch, "/api/v1/users/"+jane, cookie, map[string]string{"display_name": "Jane Doe", "status": "deactivated"})
	if r.status != http.StatusOK || r.body["display_name"] != "Jane Doe" || r.body["status"] != "deactivated" || r.body["role"] != "viewer" {
		t.Errorf("change of name and status: %d %s, want both changed", r.status, r.raw)
	}
	r = e.do(t, http.MethodPatch, "/api/v1/users/"+jane, cookie, map[string]string{"status": "active"})
	if r.status != http.StatusOK || r.body["status"] != "active" || r.body["sign_in_method"] != "oidc" {
		t.Errorf("reactivation: %d %s, want the account active, not pending", r.status, r.raw)
	}
}

// An administrator of the provider has no password to confirm the removal of
// a second factor with; the request is refused instead of failing.
func TestUpdateUser_AdministratorOfTheProviderCannotConfirmWithAPassword(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, _ = e.signIn(t, "ada@example.com", "admin")
	_, cookie := e.createOIDC(t, "jane@example.com", "admin")
	bob, _ := e.signIn(t, "bob@example.com", "viewer")
	e.addFactor(t, bob)

	r := e.do(t, http.MethodPatch, "/api/v1/users/"+bob, cookie, map[string]any{"totp_enabled": false, "password": testPassword})
	if r.status != http.StatusConflict || r.code() != account.CodeOIDCAccount {
		t.Errorf("removal of a second factor: %d %s, want 409 %s", r.status, r.raw, account.CodeOIDCAccount)
	}
	if n := e.count(t, `SELECT count(*) FROM totp_factors WHERE user_id = $1`, bob); n != 1 {
		t.Error("the factor was removed")
	}
}

// The command line issues password reset links for administrators who sign in
// with a password, not for those of the provider.
func TestIssueAdminResetLink_RejectsAccountsOfTheProvider(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, _ = e.signIn(t, "ada@example.com", "admin")
	e.createOIDC(t, "jane@example.com", "admin")

	_, err := account.NewService(e.console, consoleURL, hasher).IssueAdminResetLink(t.Context(), "jane@example.com")
	if !errors.Is(err, user.ErrOIDCAccount) {
		t.Errorf("IssueAdminResetLink() error = %v, want user.ErrOIDCAccount", err)
	}
}
