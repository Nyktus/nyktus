// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/auth/secondfactor"
	"nyktus.org/nyktus/internal/platform/config"
	"nyktus.org/nyktus/internal/platform/schematest"
)

// margin places a row this far before or after the point where it expires,
// far more than the test takes, so that no row crosses it meanwhile.
const margin = time.Minute

// signInRow is a row of sign-in data that the test places relative to the
// time of the database, and the query that tells whether it still exists.
type signInRow struct {
	name string
	// label names the row in its hash or address and is the first argument
	// of every statement.
	label   string
	insert  []statement
	exists  string
	expired bool
}

// statement is a statement with the arguments that follow the label.
type statement struct {
	sql  string
	args []any
}

// hashed tells whether a row whose hash is that of the label $1 exists.
func hashed(table, column string) string {
	return "SELECT EXISTS (SELECT FROM " + table + " WHERE " + column + " = sha256(convert_to($1, 'UTF8')))"
}

// ofUser tells whether a row of the account with the address $1 exists.
func ofUser(table string) string {
	return "SELECT EXISTS (SELECT FROM " + table + " AS t JOIN users AS u ON u.id = t.user_id WHERE u.email = $1)"
}

// signInRows places one row of every kind of sign-in data just before and one
// just after the point where it expires. The limits of sessions and factors
// come from the code, so that a change there fails this test until the schema
// follows.
func signInRows() []signInRow {
	const (
		session = `INSERT INTO sessions (token_hash, user_id, created_at)
SELECT sha256(convert_to($1, 'UTF8')), id, clock_timestamp() - $2::interval FROM users WHERE email = 'a@example.com'`
		seen      = `UPDATE sessions SET last_seen_at = clock_timestamp() - $2::interval WHERE token_hash = sha256(convert_to($1, 'UTF8'))`
		challenge = `INSERT INTO sign_in_challenges (token_hash, user_id, expires_at)
SELECT sha256(convert_to($1, 'UTF8')), id, clock_timestamp() + $2::interval FROM users WHERE email = 'a@example.com'`
		factor = `INSERT INTO totp_factors (user_id, secret, created_at)
SELECT id, '\x01'::bytea || decode(repeat('00', 48), 'hex'), clock_timestamp() - $2::interval FROM users WHERE email = $1`
		confirmedFactor = `INSERT INTO totp_factors (user_id, secret, created_at, confirmed_at, last_used_step)
SELECT id, '\x01'::bytea || decode(repeat('00', 48), 'hex'), clock_timestamp() - $2::interval, clock_timestamp() - $2::interval, 0
FROM users WHERE email = $1`
		link = `INSERT INTO account_links (user_id, token_hash, purpose, expires_at)
SELECT id, sha256(convert_to($1, 'UTF8')), 'activation', clock_timestamp() + $2::interval FROM users WHERE email = $1`
		key = `INSERT INTO api_keys (name, secret_hash, scopes, created_at, expires_at)
VALUES ($1, sha256(convert_to($1, 'UTF8')), '{incidents:read}', clock_timestamp() - interval '1 day', clock_timestamp() + $2::interval)`
		login = `INSERT INTO oidc_logins (state_hash, browser_hash, nonce, code_verifier, purpose, expires_at)
VALUES (sha256(convert_to($1, 'UTF8')), sha256(convert_to($1, 'UTF8')), repeat('n', 43), repeat('v', 43), 'sign_in', clock_timestamp() + $2::interval)`
		setup = `INSERT INTO setup_tokens (token_hash, expires_at) VALUES (sha256(convert_to($1, 'UTF8')), clock_timestamp() + $2::interval)`
	)
	idle, age, enrollment := config.MaxSessionIdleTimeout, config.MaxSessionMaxAge, secondfactor.EnrollmentTimeout
	one := func(sql string, args ...any) []statement { return []statement{{sql: sql, args: args}} }
	return []signInRow{
		{
			name: "idle session", label: "idle", exists: hashed("sessions", "token_hash"), expired: true,
			insert: []statement{{session, []any{idle + time.Hour}}, {seen, []any{idle + margin}}},
		},
		{
			name: "session used within the idle timeout", label: "used", exists: hashed("sessions", "token_hash"),
			insert: []statement{{session, []any{idle + time.Hour}}, {seen, []any{idle - margin}}},
		},
		{name: "session beyond its lifetime", label: "old", insert: []statement{{session, []any{age + margin}}, {seen, []any{time.Duration(0)}}}, exists: hashed("sessions", "token_hash"), expired: true},
		{name: "session within its lifetime", label: "young", insert: []statement{{session, []any{age - margin}}, {seen, []any{time.Duration(0)}}}, exists: hashed("sessions", "token_hash")},
		{name: "expired challenge", label: "challenge-expired", insert: one(challenge, -margin), exists: hashed("sign_in_challenges", "token_hash"), expired: true},
		{name: "challenge", label: "challenge", insert: one(challenge, margin), exists: hashed("sign_in_challenges", "token_hash")},
		{name: "unconfirmed factor beyond the enrollment", label: "a@example.com", insert: one(factor, enrollment+margin), exists: ofUser("totp_factors"), expired: true},
		{name: "unconfirmed factor within the enrollment", label: "b@example.com", insert: one(factor, enrollment-margin), exists: ofUser("totp_factors")},
		{name: "confirmed factor", label: "c@example.com", insert: one(confirmedFactor, 24*time.Hour), exists: ofUser("totp_factors")},
		{name: "expired link", label: "a@example.com", insert: one(link, -margin), exists: ofUser("account_links"), expired: true},
		{name: "link", label: "b@example.com", insert: one(link, margin), exists: ofUser("account_links")},
		{name: "expired API key", label: "key-expired", insert: one(key, -margin), exists: hashed("api_keys", "secret_hash"), expired: true},
		{name: "API key", label: "key", insert: one(key, margin), exists: hashed("api_keys", "secret_hash")},
		{name: "expired sign-in", label: "login-expired", insert: one(login, -margin), exists: hashed("oidc_logins", "state_hash"), expired: true},
		{name: "sign-in", label: "login", insert: one(login, margin), exists: hashed("oidc_logins", "state_hash")},
		{name: "expired setup token", label: "setup-expired", insert: one(setup, -margin), exists: hashed("setup_tokens", "token_hash"), expired: true},
		{name: "setup token", label: "setup", insert: one(setup, margin), exists: hashed("setup_tokens", "token_hash")},
	}
}

// placeSignInRows creates the accounts and the rows of signInRows as the
// owner.
func placeSignInRows(t *testing.T, owner *pgxpool.Pool) []signInRow {
	t.Helper()
	if _, err := owner.Exec(t.Context(), `
INSERT INTO users (email, display_name, role, status)
VALUES ('a@example.com', 'A', 'viewer', 'pending'), ('b@example.com', 'B', 'viewer', 'pending'),
	('c@example.com', 'C', 'viewer', 'pending')`); err != nil {
		t.Fatalf("insert users: %v", err)
	}
	rows := signInRows()
	for _, r := range rows {
		for _, st := range r.insert {
			if _, err := owner.Exec(t.Context(), st.sql, append([]any{r.label}, st.args...)...); err != nil {
				t.Fatalf("place %s: %v", r.name, err)
			}
		}
	}
	return rows
}

// The function removes every kind of expired sign-in data and nothing that the
// console still accepts, with the limits of the console.
func TestDeleteExpiredSignInData_RemovesOnlyExpiredRows(t *testing.T) {
	t.Parallel()

	ownerURL, workerURL := schematest.Worker(t)
	owner := schematest.Open(t, ownerURL)
	rows := placeSignInRows(t, owner)

	var removed int
	if err := schematest.Open(t, workerURL).QueryRow(t.Context(), "SELECT public.delete_expired_sign_in_data(100)").Scan(&removed); err != nil {
		t.Fatalf("delete_expired_sign_in_data() error = %v", err)
	}
	want := 0
	for _, r := range rows {
		var exists bool
		if err := owner.QueryRow(t.Context(), r.exists, r.label).Scan(&exists); err != nil {
			t.Fatalf("look up %s: %v", r.name, err)
		}
		if exists == r.expired {
			t.Errorf("%s: exists = %t, want %t", r.name, exists, !r.expired)
		}
		if r.expired {
			want++
		}
	}
	if removed != want {
		t.Errorf("delete_expired_sign_in_data() = %d, want %d", removed, want)
	}
}

// Each call removes at most batch rows of each table, so that no call holds
// many locks, and reports how many it removed, so that the worker calls again
// while rows remain.
func TestDeleteExpiredSignInData_RemovesABatchPerTable(t *testing.T) {
	t.Parallel()

	ownerURL, workerURL := schematest.Worker(t)
	owner := schematest.Open(t, ownerURL)
	if _, err := owner.Exec(t.Context(), `
INSERT INTO oidc_logins (state_hash, browser_hash, nonce, code_verifier, purpose, expires_at)
SELECT sha256(convert_to(i::text, 'UTF8')), sha256(convert_to(i::text, 'UTF8')), repeat('n', 43), repeat('v', 43), 'sign_in',
	clock_timestamp() - interval '1 second'
FROM generate_series(1, 3) AS i`); err != nil {
		t.Fatalf("insert sign-ins: %v", err)
	}
	worker := schematest.Open(t, workerURL)
	for _, want := range []int{2, 1, 0} {
		var removed int
		if err := worker.QueryRow(t.Context(), "SELECT public.delete_expired_sign_in_data(2)").Scan(&removed); err != nil {
			t.Fatalf("delete_expired_sign_in_data(2) error = %v", err)
		}
		if removed != want {
			t.Errorf("delete_expired_sign_in_data(2) = %d, want %d", removed, want)
		}
	}

	for _, batch := range []any{0, 10001, nil} {
		_, err := worker.Exec(t.Context(), "SELECT public.delete_expired_sign_in_data($1)", batch)
		var pgErr *pgconn.PgError
		// 22023 is invalid_parameter_value.
		if !errors.As(err, &pgErr) || pgErr.Code != "22023" {
			t.Errorf("delete_expired_sign_in_data(%v) error = %v, want invalid_parameter_value", batch, err)
		}
	}
}

// A row that another transaction holds, such as a session that the console is
// ending, is skipped instead of waited for, so that two workers or a worker and
// the console never wait for each other.
func TestDeleteExpiredSignInData_SkipsLockedRows(t *testing.T) {
	t.Parallel()

	ownerURL, workerURL := schematest.Worker(t)
	owner := schematest.Open(t, ownerURL)
	if _, err := owner.Exec(t.Context(), `
INSERT INTO setup_tokens (token_hash, expires_at)
SELECT sha256(convert_to(i::text, 'UTF8')), clock_timestamp() - interval '1 second' FROM generate_series(1, 2) AS i`); err != nil {
		t.Fatalf("insert setup tokens: %v", err)
	}
	tx, err := owner.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(t.Context()) })
	if _, err := tx.Exec(t.Context(), "SELECT FROM setup_tokens WHERE token_hash = sha256(convert_to('1', 'UTF8')) FOR UPDATE"); err != nil {
		t.Fatalf("lock setup token: %v", err)
	}

	// A wait would end on the lock timeout of the function with an error.
	var removed int
	if err := schematest.Open(t, workerURL).QueryRow(t.Context(), "SELECT public.delete_expired_sign_in_data(10)").Scan(&removed); err != nil {
		t.Fatalf("delete_expired_sign_in_data() error = %v", err)
	}
	if removed != 1 {
		t.Errorf("delete_expired_sign_in_data() = %d, want 1: the held token is skipped", removed)
	}
}

// The rows of the periodic tasks are those that the migration creates; a
// worker can record when they ran, but not add one.
func TestSchema_PeriodicTasksAreFixed(t *testing.T) {
	t.Parallel()

	pool := schematest.Open(t, schematest.New(t))
	_, err := pool.Exec(t.Context(), "INSERT INTO periodic_tasks (name) VALUES ('unknown')")
	if got := constraintOf(err); got != "periodic_tasks_name_check" {
		t.Errorf("insert unknown task: constraint = %q (%v), want periodic_tasks_name_check", got, err)
	}
	_, err = pool.Exec(t.Context(), "UPDATE periodic_tasks SET last_rows = -1")
	if got := constraintOf(err); got != "periodic_tasks_last_rows_check" {
		t.Errorf("negative rows: constraint = %q (%v), want periodic_tasks_last_rows_check", got, err)
	}
}
