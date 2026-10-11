// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"crypto/rand"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/migrate"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/migrations"
)

func TestApply_RevokesPublicSchemaPrivileges(t *testing.T) {
	t.Parallel()

	pool := schematest.Open(t, schematest.New(t))
	var usage, create bool
	err := pool.QueryRow(t.Context(),
		"SELECT has_schema_privilege('public', 'public', 'USAGE'), has_schema_privilege('public', 'public', 'CREATE')",
	).Scan(&usage, &create)
	if err != nil {
		t.Fatalf("query schema privileges: %v", err)
	}
	if usage || create {
		t.Errorf("PUBLIC privileges on schema public: usage=%v create=%v, want none", usage, create)
	}
}

func TestApply_FailsWithoutSchemaOwnership(t *testing.T) {
	t.Parallel()

	dbURL := dbtest.New(t)
	role, roleURL := dbtest.Role(t, dbURL, "migrator", "")
	dbtest.Exec(t, dbURL, "GRANT CREATE ON SCHEMA public TO "+pgx.Identifier{role}.Sanitize())

	err := apply(t, roleURL, load(t))
	if err == nil || !strings.Contains(err.Error(), "run migrations as the owner of the schema") {
		t.Errorf("Apply() error = %v, want the schema ownership error", err)
	}
}

func TestApply_FailsWithoutConsoleRole(t *testing.T) {
	t.Parallel()

	// Roles are global to the server, and other tests create nyktus_console, so
	// the migrations refer to a role that certainly does not exist instead.
	missing := "nyktus_missing_" + strings.ToLower(rand.Text())
	all := load(t)
	for i := range all {
		all[i].SQL = strings.ReplaceAll(all[i].SQL, schematest.ConsoleRole, missing)
	}

	dbURL := dbtest.New(t)
	err := apply(t, dbURL, all)
	want := "database role " + missing + " does not exist; create the server roles with deploy/postgres/roles.sql"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Apply() error = %v, want it to contain %q", err, want)
	}

	var table *string
	if err := schematest.Open(t, dbURL).QueryRow(t.Context(), "SELECT to_regclass('public.users')::text").Scan(&table); err != nil {
		t.Fatalf("query table: %v", err)
	}
	if table != nil {
		t.Error("the failed migration left the users table behind")
	}
}

func TestApply_FailsWithoutUTF8Encoding(t *testing.T) {
	t.Parallel()

	dbURL := dbtest.New(t)
	u, err := url.Parse(dbURL)
	if err != nil {
		t.Fatalf("parse database url: %v", err)
	}
	name := pgx.Identifier{strings.TrimPrefix(u.Path, "/") + "_ascii"}.Sanitize()
	dbtest.Exec(t, dbURL, "CREATE DATABASE "+name+" ENCODING 'SQL_ASCII' TEMPLATE template0 LOCALE 'C'")
	t.Cleanup(func() { dbtest.Exec(t, dbURL, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	dbtest.GroupRole(t, schematest.ConsoleRole)

	u.Path = "/" + strings.TrimPrefix(u.Path, "/") + "_ascii"
	err = apply(t, u.String(), load(t))
	if want := "database encoding is SQL_ASCII, but Nyktus requires UTF8"; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("Apply() error = %v, want it to contain %q", err, want)
	}
}

func TestRolesScript_CreatesConsoleRoleIdempotently(t *testing.T) {
	t.Parallel()

	script, err := os.ReadFile("../deploy/postgres/roles.sql")
	if err != nil {
		t.Fatalf("read roles script: %v", err)
	}
	dbURL := dbtest.New(t)
	dbtest.Exec(t, dbURL, string(script), string(script))

	var canLogin bool
	err = schematest.Open(t, dbURL).QueryRow(t.Context(), "SELECT rolcanlogin FROM pg_roles WHERE rolname = $1", schematest.ConsoleRole).Scan(&canLogin)
	if err != nil {
		t.Fatalf("query role %s: %v", schematest.ConsoleRole, err)
	}
	if canLogin {
		t.Errorf("role %s can log in, want a group role", schematest.ConsoleRole)
	}
}

func TestConsoleRole_PassesLeastPrivilegeCheck(t *testing.T) {
	t.Parallel()

	_, consoleURL := schematest.Console(t)
	if err := db.CheckLeastPrivilege(t.Context(), schematest.Open(t, consoleURL)); err != nil {
		t.Errorf("CheckLeastPrivilege() error = %v, want nil", err)
	}
}

func TestConsoleRole_HasOnlyGrantedPrivileges(t *testing.T) {
	t.Parallel()

	_, consoleURL := schematest.Console(t)
	pool := schematest.Open(t, consoleURL)

	allowed := []string{
		"SELECT count(*) FROM users",
		"INSERT INTO users (email, display_name, role, status) VALUES ('a@example.com', 'A', 'viewer', 'pending')",
		"UPDATE users SET display_name = 'B', updated_at = now()",
		"DELETE FROM users",
		"SELECT count(*) FROM audit_entries",
		"INSERT INTO audit_entries (action, outcome, actor_kind, auth_method, changed_fields) VALUES ('user.create', 'success', 'system', 'cli', '{}')",
		"INSERT INTO setup_tokens (token_hash) VALUES (sha256('a'))",
		"SELECT count(*) FROM setup_tokens WHERE expires_at > clock_timestamp()",
		"BEGIN; LOCK TABLE setup_tokens IN EXCLUSIVE MODE; COMMIT",
		"DELETE FROM setup_tokens",
		"UPDATE users SET failed_logins = 1, locked_until = now()",
		"INSERT INTO users (email, display_name, role, status) VALUES ('s@example.com', 'S', 'viewer', 'pending')",
		"INSERT INTO sessions (token_hash, user_id) SELECT sha256('s'), id FROM users WHERE email = 's@example.com'",
		"UPDATE sessions SET last_seen_at = clock_timestamp()",
		"SELECT count(*) FROM sessions",
		"DELETE FROM sessions",
		"INSERT INTO account_links (user_id, token_hash, purpose) SELECT id, sha256('a'), 'activation' FROM users WHERE email = 's@example.com'",
		"SELECT count(*) FROM account_links WHERE expires_at > clock_timestamp()",
		"DELETE FROM account_links",
		"INSERT INTO sign_in_challenges (token_hash, user_id) SELECT sha256('c'), id FROM users WHERE email = 's@example.com'",
		"SELECT count(*) FROM sign_in_challenges WHERE expires_at > clock_timestamp()",
		"DELETE FROM sign_in_challenges",
		"INSERT INTO totp_factors (user_id, secret) SELECT id, decode(repeat('01', 49), 'hex') FROM users WHERE email = 's@example.com'",
		"UPDATE totp_factors SET confirmed_at = clock_timestamp(), last_used_step = 1, secret = secret",
		"INSERT INTO recovery_codes (user_id, code_hash) SELECT user_id, sha256('r') FROM totp_factors",
		"SELECT count(*) FROM recovery_codes",
		"DELETE FROM recovery_codes",
		"SELECT count(*) FROM totp_factors",
		"DELETE FROM totp_factors",
		"INSERT INTO api_keys (created_by, name, secret_hash, scopes, expires_at) SELECT id, 'k', sha256('k'), '{audit:read}', clock_timestamp() + interval '1 day' FROM users WHERE email = 's@example.com'",
		"UPDATE api_keys SET last_used_at = clock_timestamp()",
		"SELECT count(*) FROM api_keys",
		"DELETE FROM api_keys",
		"INSERT INTO users (email, display_name, role, status, oidc_issuer, oidc_subject) VALUES ('o@example.com', 'O', 'viewer', 'active', 'https://idp.example.com', 'o')",
		"INSERT INTO oidc_logins (state_hash, browser_hash, nonce, code_verifier, previous_session_hash) VALUES (sha256('s'), sha256('b'), repeat('n', 43), repeat('v', 43), sha256('p'))",
		"SELECT count(*) FROM oidc_logins WHERE expires_at > clock_timestamp()",
		"DELETE FROM oidc_logins",
	}
	for _, statement := range allowed {
		if _, err := pool.Exec(t.Context(), statement); err != nil {
			t.Errorf("%s: error = %v, want nil", statement, err)
		}
	}

	denied := []string{
		"SELECT * FROM schema_migrations",
		"CREATE TABLE extra (id int)",
		"INSERT INTO users (id, email, display_name, role, status) VALUES (gen_random_uuid(), 'b@example.com', 'B', 'viewer', 'pending')",
		"INSERT INTO users (email, display_name, role, status, created_at) VALUES ('c@example.com', 'C', 'viewer', 'pending', now())",
		"UPDATE users SET id = gen_random_uuid()",
		"UPDATE users SET created_at = now()",
		"TRUNCATE users",
		"UPDATE audit_entries SET outcome = 'failure'",
		"DELETE FROM audit_entries",
		"TRUNCATE audit_entries",
		"INSERT INTO setup_tokens (token_hash, expires_at) VALUES (sha256('b'), now() + interval '1 year')",
		"UPDATE setup_tokens SET expires_at = now() + interval '1 year'",
		"TRUNCATE setup_tokens",
		"INSERT INTO users (email, display_name, role, status, failed_logins) VALUES ('f@example.com', 'F', 'viewer', 'pending', 4)",
		"INSERT INTO users (email, display_name, role, status, locked_until) VALUES ('l@example.com', 'L', 'viewer', 'pending', now())",
		"INSERT INTO sessions (id, token_hash, user_id) SELECT gen_random_uuid(), sha256('t'), id FROM users LIMIT 1",
		"INSERT INTO sessions (token_hash, user_id, created_at) SELECT sha256('u'), id, now() - interval '1 day' FROM users LIMIT 1",
		"UPDATE sessions SET created_at = now()",
		"UPDATE sessions SET user_id = user_id",
		"UPDATE sessions SET token_hash = token_hash",
		"TRUNCATE sessions",
		"UPDATE users SET email = 'z@example.com'",
		"INSERT INTO account_links (user_id, token_hash, purpose, expires_at) SELECT id, sha256('b'), 'activation', now() + interval '1 year' FROM users LIMIT 1",
		"UPDATE account_links SET expires_at = now() + interval '1 year'",
		"UPDATE account_links SET user_id = user_id",
		"UPDATE account_links SET purpose = 'password_reset'",
		"TRUNCATE account_links",
		"SELECT public.users_keep_active_admin()",
		"SELECT public.users_set_updated_at()",
		"INSERT INTO sign_in_challenges (token_hash, user_id, expires_at) SELECT sha256('d'), id, now() + interval '1 year' FROM users LIMIT 1",
		"UPDATE sign_in_challenges SET expires_at = now() + interval '1 year'",
		"UPDATE sign_in_challenges SET user_id = user_id",
		"TRUNCATE sign_in_challenges",
		"INSERT INTO totp_factors (user_id, secret, confirmed_at) SELECT id, decode(repeat('01', 49), 'hex'), now() FROM users LIMIT 1",
		"INSERT INTO totp_factors (user_id, secret, last_used_step) SELECT id, decode(repeat('01', 49), 'hex'), 0 FROM users LIMIT 1",
		"UPDATE totp_factors SET user_id = user_id",
		"UPDATE totp_factors SET created_at = now()",
		"TRUNCATE totp_factors",
		"UPDATE recovery_codes SET code_hash = code_hash",
		"TRUNCATE recovery_codes",
		"INSERT INTO api_keys (id, created_by, name, secret_hash, scopes, expires_at) SELECT gen_random_uuid(), id, 'k', sha256('k'), '{audit:read}', now() + interval '1 day' FROM users LIMIT 1",
		"INSERT INTO api_keys (created_by, name, secret_hash, scopes, expires_at, created_at) SELECT id, 'k', sha256('k'), '{audit:read}', now() + interval '1 day', now() FROM users LIMIT 1",
		"INSERT INTO api_keys (created_by, name, secret_hash, scopes, expires_at, last_used_at) SELECT id, 'k', sha256('k'), '{audit:read}', now() + interval '1 day', now() FROM users LIMIT 1",
		"UPDATE api_keys SET scopes = '{users:write}'",
		"UPDATE api_keys SET expires_at = now() + interval '10 years'",
		"UPDATE api_keys SET secret_hash = secret_hash",
		"UPDATE api_keys SET created_by = created_by",
		"UPDATE api_keys SET name = name",
		"UPDATE api_keys SET created_at = now()",
		"TRUNCATE api_keys",
		"UPDATE users SET oidc_issuer = 'https://other.example.com'",
		"UPDATE users SET oidc_subject = 'other'",
		"INSERT INTO oidc_logins (state_hash, browser_hash, nonce, code_verifier, expires_at) VALUES (sha256('t'), sha256('b'), repeat('n', 43), repeat('v', 43), now() + interval '1 year')",
		"UPDATE oidc_logins SET expires_at = now() + interval '1 year'",
		"UPDATE oidc_logins SET nonce = nonce",
		"UPDATE oidc_logins SET previous_session_hash = NULL",
		"TRUNCATE oidc_logins",
	}
	for _, statement := range denied {
		_, err := pool.Exec(t.Context(), statement)
		var pgErr *pgconn.PgError
		// 42501 is insufficient_privilege.
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s: error = %v, want insufficient_privilege", statement, err)
		}
	}
}

// An operator may have set default privileges for the owner, for example to grant
// a monitoring role read access. Such defaults must not widen the privileges of
// the console beyond its grants.
func TestApply_IgnoresDefaultPrivileges(t *testing.T) {
	t.Parallel()

	dbURL := dbtest.New(t)
	dbtest.GroupRole(t, schematest.ConsoleRole)
	console := pgx.Identifier{schematest.ConsoleRole}.Sanitize()
	dbtest.Exec(t, dbURL,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "+console,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO "+console,
	)
	if err := apply(t, dbURL, load(t)); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	pool := schematest.Open(t, dbURL)
	for _, privilege := range []string{
		"has_table_privilege($1, 'public.users', 'TRUNCATE')",
		"has_table_privilege($1, 'public.users', 'REFERENCES')",
		"has_table_privilege($1, 'public.users', 'TRIGGER')",
		"has_column_privilege($1, 'public.users', 'id', 'INSERT')",
		"has_column_privilege($1, 'public.users', 'id', 'UPDATE')",
		"has_column_privilege($1, 'public.users', 'created_at', 'INSERT')",
		"has_column_privilege($1, 'public.users', 'created_at', 'UPDATE')",
		"has_any_column_privilege($1, 'public.audit_entries', 'UPDATE')",
		"has_table_privilege($1, 'public.audit_entries', 'DELETE')",
		"has_table_privilege($1, 'public.audit_entries', 'TRUNCATE')",
		"has_column_privilege($1, 'public.audit_entries', 'id', 'INSERT')",
		"has_function_privilege($1, 'public.audit_entries_copy_actor()', 'EXECUTE')",
		"has_any_column_privilege($1, 'public.setup_tokens', 'UPDATE')",
		"has_table_privilege($1, 'public.setup_tokens', 'TRUNCATE')",
		"has_column_privilege($1, 'public.setup_tokens', 'expires_at', 'INSERT')",
		"has_table_privilege($1, 'public.sessions', 'TRUNCATE')",
		"has_column_privilege($1, 'public.sessions', 'created_at', 'INSERT')",
		"has_column_privilege($1, 'public.sessions', 'created_at', 'UPDATE')",
		"has_column_privilege($1, 'public.sessions', 'token_hash', 'UPDATE')",
		"has_column_privilege($1, 'public.users', 'failed_logins', 'INSERT')",
		"has_column_privilege($1, 'public.users', 'email', 'UPDATE')",
		"has_function_privilege($1, 'public.users_keep_active_admin()', 'EXECUTE')",
		"has_function_privilege($1, 'public.users_set_updated_at()', 'EXECUTE')",
		"has_any_column_privilege($1, 'public.account_links', 'UPDATE')",
		"has_table_privilege($1, 'public.account_links', 'TRUNCATE')",
		"has_table_privilege($1, 'public.account_links', 'REFERENCES')",
		"has_column_privilege($1, 'public.account_links', 'expires_at', 'INSERT')",
		"has_column_privilege($1, 'public.account_links', 'purpose', 'UPDATE')",
		"has_any_column_privilege($1, 'public.sign_in_challenges', 'UPDATE')",
		"has_table_privilege($1, 'public.sign_in_challenges', 'TRUNCATE')",
		"has_column_privilege($1, 'public.sign_in_challenges', 'expires_at', 'INSERT')",
		"has_table_privilege($1, 'public.totp_factors', 'TRUNCATE')",
		"has_column_privilege($1, 'public.totp_factors', 'confirmed_at', 'INSERT')",
		"has_column_privilege($1, 'public.totp_factors', 'user_id', 'UPDATE')",
		"has_column_privilege($1, 'public.totp_factors', 'created_at', 'UPDATE')",
		"has_any_column_privilege($1, 'public.recovery_codes', 'UPDATE')",
		"has_table_privilege($1, 'public.recovery_codes', 'TRUNCATE')",
		"has_table_privilege($1, 'public.api_keys', 'TRUNCATE')",
		"has_column_privilege($1, 'public.api_keys', 'created_by', 'UPDATE')",
		"has_table_privilege($1, 'public.api_keys', 'REFERENCES')",
		"has_column_privilege($1, 'public.api_keys', 'created_at', 'INSERT')",
		"has_column_privilege($1, 'public.api_keys', 'scopes', 'UPDATE')",
		"has_column_privilege($1, 'public.api_keys', 'expires_at', 'UPDATE')",
		"has_column_privilege($1, 'public.api_keys', 'secret_hash', 'UPDATE')",
		"has_column_privilege($1, 'public.users', 'oidc_issuer', 'UPDATE')",
		"has_column_privilege($1, 'public.users', 'oidc_subject', 'UPDATE')",
		"has_any_column_privilege($1, 'public.oidc_logins', 'UPDATE')",
		"has_table_privilege($1, 'public.oidc_logins', 'TRUNCATE')",
		"has_table_privilege($1, 'public.oidc_logins', 'REFERENCES')",
		"has_column_privilege($1, 'public.oidc_logins', 'expires_at', 'INSERT')",
	} {
		var held bool
		if err := pool.QueryRow(t.Context(), "SELECT "+privilege, schematest.ConsoleRole).Scan(&held); err != nil {
			t.Fatalf("query %s: %v", privilege, err)
		}
		if held {
			t.Errorf("%s = true, want false", privilege)
		}
	}
}

func load(t *testing.T) []migrate.Migration {
	t.Helper()
	all, err := migrate.Load(migrations.FS)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return all
}

func apply(t *testing.T, dbURL string, all []migrate.Migration) error {
	t.Helper()
	_, err := migrate.Apply(t.Context(), schematest.Open(t, dbURL), all, slog.New(slog.DiscardHandler))
	return err
}
