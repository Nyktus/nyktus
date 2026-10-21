// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/sha256"
	"regexp"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/auth/password/passwordtest"
	"nyktus.org/nyktus/internal/platform/schematest"
)

func TestRunAdmin_ExitCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "no admin command", args: []string{"admin"}, want: exitUsage},
		{name: "unknown admin command", args: []string{"admin", "frobnicate"}, want: exitUsage},
		{name: "admin help", args: []string{"admin", "-h"}, want: exitOK},
		{name: "reset without address", args: []string{"admin", "reset-password"}, want: exitUsage},
		{name: "reset with two addresses", args: []string{"admin", "reset-password", "a@example.com", "b@example.com"}, want: exitUsage},
		{name: "reset with invalid address", args: []string{"admin", "reset-password", "not an address"}, want: exitUsage},
		{name: "reset with unknown flag", args: []string{"admin", "reset-password", "--force", "a@example.com"}, want: exitUsage},
		{name: "reset help", args: []string{"admin", "reset-password", "-h"}, want: exitOK},
		{name: "reset without configuration", args: []string{"admin", "reset-password", "a@example.com"}, want: exitFailure},
		{name: "remove TOTP without address", args: []string{"admin", "remove-totp"}, want: exitUsage},
		{name: "remove TOTP with invalid address", args: []string{"admin", "remove-totp", "not an address"}, want: exitUsage},
		{name: "remove TOTP help", args: []string{"admin", "remove-totp", "-h"}, want: exitOK},
		{name: "remove TOTP without configuration", args: []string{"admin", "remove-totp", "a@example.com"}, want: exitFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if got := run(t.Context(), tt.args, source(nil), &stdout, &stderr); got != tt.want {
				t.Errorf("run(%v) = %d, want %d; stderr: %s", tt.args, got, tt.want, stderr.String())
			}
		})
	}
}

// The command line prints a password reset link for an active administrator, with
// the database role of the console. The link goes to stdout only, and the audit
// log records the command line as the actor.
func TestRunAdmin_ResetPasswordPrintsALinkForAnAdministrator(t *testing.T) {
	t.Parallel()

	ownerURL, consoleURL := schematest.Console(t)
	owner := schematest.Open(t, ownerURL)
	hash, err := passwordtest.NewHasher().Hash(t.Context(), "correct horse battery")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	ids := map[string]string{}
	for _, u := range []struct{ email, role, status string }{
		{"ada@example.com", "admin", "active"},
		{"jane@example.com", "viewer", "active"},
		{"gone@example.com", "admin", "deactivated"},
	} {
		var id string
		err := owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, password_hash)
VALUES ($1, 'Test User', $2, $3, $4)
RETURNING id`, u.email, u.role, u.status, hash).Scan(&id)
		if err != nil {
			t.Fatalf("create %s: %v", u.email, err)
		}
		ids[u.email] = id
	}
	env := map[string]string{
		"NYKTUS_CONSOLE_DATABASE_URL": consoleURL,
		"NYKTUS_CONSOLE_URL":          "https://nyktus.example.com",
	}
	reset := func(email string) (code int, stdout, stderr string) {
		var out, errOut bytes.Buffer
		code = run(t.Context(), []string{"admin", "reset-password", email}, source(env), &out, &errOut)
		return code, out.String(), errOut.String()
	}

	for email, want := range map[string]string{
		"jane@example.com":   "not an administrator",
		"gone@example.com":   "not active",
		"nobody@example.com": "no account",
	} {
		code, stdout, stderr := reset(email)
		if code != exitFailure || stdout != "" || !strings.Contains(stderr, want) {
			t.Errorf("%s: exit %d, stdout %q, stderr %s; want failure naming %q", email, code, stdout, stderr, want)
		}
	}

	// Addresses are compared without regard to case, as at sign-in.
	code, stdout, stderr := reset("ADA@example.com")
	if code != exitOK {
		t.Fatalf("exit code = %d; stderr: %s", code, stderr)
	}
	match := regexp.MustCompile(`https://nyktus\.example\.com/reset-password#token=([A-Za-z0-9_-]{43})\n`).FindStringSubmatch(stdout)
	if match == nil {
		t.Fatalf("stdout does not contain the password reset link:\n%s", stdout)
	}
	if strings.Contains(stderr, match[1]) {
		t.Errorf("log contains the token: %s", stderr)
	}
	if !strings.Contains(stderr, `"msg":"admin: password reset link issued"`) {
		t.Errorf("log does not record the link: %s", stderr)
	}

	sum := sha256.Sum256([]byte(match[1]))
	var links, entries int
	if err := owner.QueryRow(t.Context(), `
SELECT count(*) FROM account_links WHERE user_id = $1 AND token_hash = $2 AND purpose = 'password_reset'`,
		ids["ada@example.com"], sum[:]).Scan(&links); err != nil {
		t.Fatalf("count links: %v", err)
	}
	if links != 1 {
		t.Errorf("stored links for the printed token = %d, want 1", links)
	}
	if err := owner.QueryRow(t.Context(), `
SELECT count(*) FROM audit_entries WHERE action = 'password_reset_link.create' AND outcome = 'success'
	AND actor_kind = 'system' AND auth_method = 'cli' AND resource_type = 'user' AND resource_id = $1`,
		ids["ada@example.com"]).Scan(&entries); err != nil {
		t.Fatalf("count audit entries: %v", err)
	}
	if entries != 1 {
		t.Errorf("audit entries = %d, want 1 by the command line", entries)
	}
	if err := owner.QueryRow(t.Context(), `SELECT count(*) FROM account_links`).Scan(&links); err != nil || links != 1 {
		t.Errorf("account links = %d (%v), want only the one for the administrator", links, err)
	}
}

// The command line removes the second factor of an active administrator who
// lost it, with the database role of the console and without encryption keys.
func TestRunAdmin_RemoveTOTPRemovesTheFactorOfAnAdministrator(t *testing.T) {
	t.Parallel()

	ownerURL, consoleURL := schematest.Console(t)
	owner := schematest.Open(t, ownerURL)
	ids := map[string]string{}
	for _, u := range []struct{ email, role, status string }{
		{"ada@example.com", "admin", "active"},
		{"bob@example.com", "admin", "active"},
		{"jane@example.com", "viewer", "active"},
		{"gone@example.com", "admin", "deactivated"},
	} {
		var id string
		err := owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, password_hash)
VALUES ($1, 'Test User', $2, $3, '$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
RETURNING id`, u.email, u.role, u.status).Scan(&id)
		if err != nil {
			t.Fatalf("create %s: %v", u.email, err)
		}
		ids[u.email] = id
		if u.email == "bob@example.com" {
			continue
		}
		for _, statement := range []string{
			`INSERT INTO totp_factors (user_id, secret, confirmed_at, last_used_step)
VALUES ($1, decode(repeat('01', 49), 'hex'), clock_timestamp(), 0)`,
			`INSERT INTO sessions (token_hash, user_id) VALUES (sha256(uuid_send($1::uuid)), $1)`,
		} {
			if _, err := owner.Exec(t.Context(), statement, id); err != nil {
				t.Fatalf("%s: %v", statement, err)
			}
		}
	}
	env := map[string]string{
		"NYKTUS_CONSOLE_DATABASE_URL": consoleURL,
		"NYKTUS_CONSOLE_URL":          "https://nyktus.example.com",
	}
	remove := func(email string) (code int, stdout, stderr string) {
		var out, errOut bytes.Buffer
		code = run(t.Context(), []string{"admin", "remove-totp", email}, source(env), &out, &errOut)
		return code, out.String(), errOut.String()
	}

	for email, want := range map[string]string{
		"jane@example.com":   "not an administrator",
		"gone@example.com":   "not active",
		"nobody@example.com": "no account",
		"bob@example.com":    "has no TOTP factor",
	} {
		code, stdout, stderr := remove(email)
		if code != exitFailure || stdout != "" || !strings.Contains(stderr, want) {
			t.Errorf("%s: exit %d, stdout %q, stderr %s; want failure naming %q", email, code, stdout, stderr, want)
		}
	}

	code, stdout, stderr := remove("ADA@example.com")
	if code != exitOK || !strings.Contains(stdout, "are removed") {
		t.Fatalf("exit code = %d, stdout %q; stderr: %s", code, stdout, stderr)
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := owner.QueryRow(t.Context(), sql, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return n
	}
	if n := count(`SELECT count(*) FROM totp_factors WHERE user_id = $1`, ids["ada@example.com"]); n != 0 {
		t.Errorf("factors of the administrator = %d, want none", n)
	}
	if n := count(`SELECT count(*) FROM sessions WHERE user_id = $1`, ids["ada@example.com"]); n != 0 {
		t.Errorf("sessions of the administrator = %d, want none", n)
	}
	if n := count(`SELECT count(*) FROM totp_factors`); n != 2 {
		t.Errorf("factors of other accounts = %d, want them kept", n)
	}
	if n := count(`
SELECT count(*) FROM audit_entries WHERE action = 'user.totp_disable' AND outcome = 'success'
	AND actor_kind = 'system' AND auth_method = 'cli' AND resource_id = $1`, ids["ada@example.com"]); n != 1 {
		t.Errorf("audit entries = %d, want 1 by the command line", n)
	}
}
