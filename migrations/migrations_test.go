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
	schematest.GroupRoles(t)
	role, roleURL := dbtest.Role(t, dbURL, "migrator", "")
	dbtest.Exec(t, dbURL, "GRANT CREATE ON SCHEMA public TO "+pgx.Identifier{role}.Sanitize())

	err := apply(t, roleURL, load(t))
	if err == nil || !strings.Contains(err.Error(), "run migrations as the owner of the schema") {
		t.Errorf("Apply() error = %v, want the schema ownership error", err)
	}
}

func TestApply_FailsWithoutGroupRole(t *testing.T) {
	t.Parallel()

	for _, role := range []string{schematest.ConsoleRole, schematest.TriggerRole, schematest.DNSRole, schematest.WorkerRole} {
		t.Run(role, func(t *testing.T) {
			t.Parallel()

			// Roles are global to the server, and other tests create the group
			// roles, so the migrations refer to a role that certainly does not
			// exist instead.
			missing := "nyktus_missing_" + strings.ToLower(rand.Text())
			all := load(t)
			for i := range all {
				all[i].SQL = strings.ReplaceAll(all[i].SQL, role, missing)
			}

			dbURL := dbtest.New(t)
			schematest.GroupRoles(t)
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
		})
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
	schematest.GroupRoles(t)

	u.Path = "/" + strings.TrimPrefix(u.Path, "/") + "_ascii"
	err = apply(t, u.String(), load(t))
	if want := "database encoding is SQL_ASCII, but Nyktus requires UTF8"; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("Apply() error = %v, want it to contain %q", err, want)
	}
}

func TestRolesScript_CreatesGroupRolesIdempotently(t *testing.T) {
	t.Parallel()

	script, err := os.ReadFile("../deploy/postgres/roles.sql")
	if err != nil {
		t.Fatalf("read roles script: %v", err)
	}
	// Group roles are global and other tests create them, so their presence
	// proves nothing about the script; the script must create each of them.
	for _, role := range []string{schematest.ConsoleRole, schematest.TriggerRole, schematest.DNSRole, schematest.WorkerRole} {
		if !strings.Contains(string(script), "CREATE ROLE "+role+" NOLOGIN;") {
			t.Errorf("the roles script does not create %s", role)
		}
	}
	dbURL := dbtest.New(t)
	dbtest.Exec(t, dbURL, string(script), string(script))

	for _, role := range []string{schematest.ConsoleRole, schematest.TriggerRole, schematest.DNSRole, schematest.WorkerRole} {
		var canLogin bool
		err = schematest.Open(t, dbURL).QueryRow(t.Context(), "SELECT rolcanlogin FROM pg_roles WHERE rolname = $1", role).Scan(&canLogin)
		if err != nil {
			t.Fatalf("query role %s: %v", role, err)
		}
		if canLogin {
			t.Errorf("role %s can log in, want a group role", role)
		}
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
		"SELECT * FROM public.read_metrics()",
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
		"INSERT INTO oidc_logins (state_hash, browser_hash, nonce, code_verifier, purpose, previous_session_hash) VALUES (sha256('s'), sha256('b'), repeat('n', 43), repeat('v', 43), 'sign_in', sha256('p'))",
		"INSERT INTO sessions (token_hash, user_id) SELECT sha256('r'), id FROM users WHERE email = 'o@example.com'",
		"UPDATE sessions SET reauthenticated_at = clock_timestamp()",
		"INSERT INTO oidc_logins (state_hash, browser_hash, nonce, code_verifier, purpose, session_id, return_to) SELECT sha256('t'), sha256('b'), repeat('n', 43), repeat('v', 43), 'reauthentication', id, '/settings' FROM sessions",
		"SELECT count(*) FROM oidc_logins WHERE expires_at > clock_timestamp()",
		"DELETE FROM oidc_logins",
		"INSERT INTO scenarios (name, notes, engage_activities) VALUES ('s', '', '{EAC0005}')",
		"UPDATE scenarios SET name = 't', notes = 'n', engage_activities = '{}', updated_at = clock_timestamp()",
		"SELECT count(*) FROM scenarios",
		"SELECT public.engage_activity_ids_valid('{EAC0005}')",
		"INSERT INTO honeytokens (type, name, notes, enabled, redirect_url, techniques, severity, trigger_value) VALUES ('web_url', 'h', '', true, 'https://example.com', '{T1078}', 'medium', repeat('a', 26))",
		"UPDATE honeytokens SET name = 'i', notes = 'n', enabled = false, redirect_url = NULL, techniques = '{}', severity = 'high', updated_at = clock_timestamp()",
		"UPDATE honeytokens SET scenario_id = (SELECT id FROM scenarios)",
		"SELECT id FROM scenarios FOR KEY SHARE",
		"SELECT id FROM scenarios FOR UPDATE",
		"SELECT count(*) FROM honeytokens",
		"SELECT public.attack_technique_ids_valid('{T1078}')",
		"INSERT INTO scenarios (name, deception_id, language, persona, guide) VALUES ('d', 'ssh-config', 'en', '{\"Domain\": \"corp.example.com\"}', 'g')",
		"INSERT INTO artifacts (scenario_id, deception_artifact, file_name, format, content) SELECT id, 'config', 'config', 'config', '\\x41' FROM scenarios WHERE deception_id IS NOT NULL",
		"UPDATE artifacts SET placement_notes = 'n', updated_at = clock_timestamp()",
		"SELECT count(*) FROM artifacts",
		"UPDATE artifacts SET scenario_id = NULL",
		"DELETE FROM artifacts",
		"DELETE FROM honeytokens",
		"DELETE FROM scenarios",
		"SELECT count(*) FROM events",
		"SELECT count(*) FROM incidents",
		"UPDATE incidents SET status = status, notes = notes, severity_override = NULL, techniques_override = NULL",
		"INSERT INTO alert_channels (name, type, enabled, target, header_name) VALUES ('c', 'webhook', true, 'https://h.example.com', 'X-Token')",
		"INSERT INTO alert_channel_secrets (channel_id, url, header_value) SELECT id, decode(repeat('01', 40), 'hex'), decode(repeat('01', 40), 'hex') FROM alert_channels",
		"UPDATE alert_channel_secrets SET url = decode(repeat('02', 40), 'hex'), header_value = NULL WHERE channel_id = channel_id",
		"UPDATE alert_channels SET name = 'd', enabled = false, target = 'https://i.example.com', header_name = NULL, updated_at = clock_timestamp()",
		"INSERT INTO alert_channels (name, type, enabled, recipients) VALUES ('m', 'email', true, '{soc@example.com}')",
		"UPDATE alert_channels SET recipients = '{oncall@example.com}' WHERE type = 'email'",
		"SELECT count(*) FROM alert_channels",
		"SELECT channel_id FROM alert_channel_secrets",
		"INSERT INTO alert_deliveries (channel_id, channel_type, channel_name) SELECT id, type, name FROM alert_channels",
		"SELECT count(*) FROM alert_deliveries",
		"SELECT public.retry_alert_delivery(gen_random_uuid())",
		"DELETE FROM alert_channels",
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
		"SELECT public.set_updated_at()",
		"SELECT public.sessions_set_last_seen_at()",
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
		"UPDATE oidc_logins SET return_to = '/'",
		"UPDATE oidc_logins SET session_id = session_id",
		"INSERT INTO oidc_logins (state_hash, browser_hash, nonce, code_verifier, purpose, created_at) VALUES (sha256('u'), sha256('b'), repeat('n', 43), repeat('v', 43), 'sign_in', now() - interval '1 day')",
		"INSERT INTO sessions (token_hash, user_id, reauthenticated_at) SELECT sha256('v'), id, now() FROM users LIMIT 1",
		"TRUNCATE oidc_logins",
		"INSERT INTO honeytokens (id, type, name, trigger_value) VALUES (gen_random_uuid(), 'web_url', 'h', repeat('b', 26))",
		"INSERT INTO honeytokens (type, name, trigger_value, created_at) VALUES ('web_url', 'h', repeat('c', 26), now() - interval '1 day')",
		"INSERT INTO honeytokens (type, name, trigger_value, updated_at) VALUES ('web_url', 'h', repeat('d', 26), now())",
		"UPDATE honeytokens SET type = 'web_image'",
		"UPDATE honeytokens SET trigger_value = repeat('e', 26)",
		"UPDATE honeytokens SET id = gen_random_uuid()",
		"UPDATE honeytokens SET created_at = now()",
		"TRUNCATE honeytokens",
		"INSERT INTO honeytokens (type, name, trigger_value, scenario_id) VALUES ('web_url', 'h', repeat('f', 26), NULL)",
		"INSERT INTO scenarios (id, name) VALUES (gen_random_uuid(), 's')",
		"INSERT INTO scenarios (name, created_at) VALUES ('s', now() - interval '1 day')",
		"INSERT INTO scenarios (name, updated_at) VALUES ('s', now())",
		"UPDATE scenarios SET deception_id = 'ssh-config'",
		"UPDATE scenarios SET language = 'de'",
		"UPDATE scenarios SET persona = '{}'",
		"UPDATE scenarios SET guide = 'g'",
		"INSERT INTO artifacts (id, scenario_id, deception_artifact, file_name, format, content) VALUES (gen_random_uuid(), NULL, 'a', 'a', 'text', '')",
		"INSERT INTO artifacts (scenario_id, deception_artifact, file_name, format, content, placement_notes) VALUES (NULL, 'a', 'a', 'text', '', 'n')",
		"INSERT INTO artifacts (scenario_id, deception_artifact, file_name, format, content, created_at) VALUES (NULL, 'a', 'a', 'text', '', now())",
		"UPDATE artifacts SET content = ''",
		"UPDATE artifacts SET file_name = 'b'",
		"UPDATE artifacts SET format = 'text'",
		"UPDATE artifacts SET deception_artifact = 'b'",
		"UPDATE artifacts SET id = gen_random_uuid()",
		"UPDATE artifacts SET created_at = now()",
		"TRUNCATE artifacts",
		"SELECT public.artifacts_keep_scenario()",
		"UPDATE scenarios SET id = gen_random_uuid()",
		"UPDATE scenarios SET created_at = now()",
		"TRUNCATE scenarios",
		"INSERT INTO events (resource_type, resource_id, honeytoken_type, method) VALUES ('honeytoken', gen_random_uuid(), 'web_url', 'GET')",
		"DELETE FROM events",
		"SELECT count(*) FROM event_jobs",
		"INSERT INTO event_jobs (event_id) VALUES (gen_random_uuid())",
		"SELECT * FROM public.record_honeytoken_request(repeat('a', 26), 'GET', NULL, '', '', '')",
		"SELECT * FROM public.record_dns_query(repeat('a', 26), 'd.example.com', '', 'A', 'udp', NULL, interval '0')",
		"SELECT public.honeytoken_event_limit_reached(gen_random_uuid())",
		"UPDATE events SET incident_id = NULL",
		"UPDATE events SET client_ip = NULL",
		"INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at) VALUES ('honeytoken', gen_random_uuid(), 'low', now(), now())",
		"UPDATE incidents SET severity = 'low'",
		"UPDATE incidents SET techniques = '{}'",
		"UPDATE incidents SET event_count = 1",
		"UPDATE incidents SET acknowledged_at = now()",
		"UPDATE incidents SET closed_at = now()",
		"UPDATE incidents SET resource_id = gen_random_uuid()",
		"DELETE FROM incidents",
		"TRUNCATE incidents",
		"SELECT count(*) FROM alerts",
		"INSERT INTO alerts (incident_id, severity) VALUES (gen_random_uuid(), 'low')",
		"SELECT public.incidents_change_status()",
		"SELECT url FROM alert_channel_secrets",
		"SELECT header_value FROM alert_channel_secrets",
		"UPDATE alert_channel_secrets SET channel_id = channel_id",
		"DELETE FROM alert_channel_secrets",
		"TRUNCATE alert_channel_secrets",
		"INSERT INTO alert_channels (id, name, type, target) VALUES (gen_random_uuid(), 'e', 'slack', 'https://h.example.com')",
		"INSERT INTO alert_channels (name, type, target, created_at) VALUES ('f', 'slack', 'https://h.example.com', now())",
		"INSERT INTO alert_channels (name, type, target, updated_at) VALUES ('g', 'slack', 'https://h.example.com', now())",
		"UPDATE alert_channels SET type = 'slack'",
		"UPDATE alert_channels SET id = gen_random_uuid()",
		"UPDATE alert_channels SET created_at = now()",
		"TRUNCATE alert_channels",
		"INSERT INTO alert_deliveries (alert_id, channel_id, channel_type, channel_name) VALUES (gen_random_uuid(), gen_random_uuid(), 'webhook', 'c')",
		"INSERT INTO alert_deliveries (channel_id, channel_type, channel_name, status) VALUES (gen_random_uuid(), 'webhook', 'c', 'delivered')",
		"UPDATE alert_deliveries SET status = 'delivered'",
		"UPDATE alert_deliveries SET attempts = 0",
		"DELETE FROM alert_deliveries",
		"TRUNCATE alert_deliveries",
		"SELECT count(*) FROM periodic_tasks",
		"UPDATE periodic_tasks SET next_run_at = now()",
		"SELECT public.delete_expired_sign_in_data(1)",
		"SELECT public.delete_expired_audit_entries(365, 1)",
		"SELECT public.delete_expired_incident_data(180, 1)",
		"SELECT public.close_inactive_incidents(14, 1)",
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
	schematest.GroupRoles(t)
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
		"has_function_privilege($1, 'public.set_updated_at()', 'EXECUTE')",
		"has_function_privilege($1, 'public.sessions_set_last_seen_at()', 'EXECUTE')",
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
		"has_table_privilege($1, 'public.honeytokens', 'TRUNCATE')",
		"has_table_privilege($1, 'public.honeytokens', 'REFERENCES')",
		"has_table_privilege($1, 'public.honeytokens', 'TRIGGER')",
		"has_column_privilege($1, 'public.honeytokens', 'id', 'INSERT')",
		"has_column_privilege($1, 'public.honeytokens', 'created_at', 'INSERT')",
		"has_column_privilege($1, 'public.honeytokens', 'updated_at', 'INSERT')",
		"has_column_privilege($1, 'public.honeytokens', 'type', 'UPDATE')",
		"has_column_privilege($1, 'public.honeytokens', 'trigger_value', 'UPDATE')",
		"has_column_privilege($1, 'public.honeytokens', 'created_at', 'UPDATE')",
		"has_column_privilege($1, 'public.honeytokens', 'scenario_id', 'INSERT')",
		"has_table_privilege($1, 'public.scenarios', 'TRUNCATE')",
		"has_table_privilege($1, 'public.scenarios', 'REFERENCES')",
		"has_table_privilege($1, 'public.scenarios', 'TRIGGER')",
		"has_column_privilege($1, 'public.scenarios', 'id', 'INSERT')",
		"has_column_privilege($1, 'public.scenarios', 'created_at', 'INSERT')",
		"has_column_privilege($1, 'public.scenarios', 'updated_at', 'INSERT')",
		"has_column_privilege($1, 'public.scenarios', 'id', 'UPDATE')",
		"has_column_privilege($1, 'public.scenarios', 'deception_id', 'UPDATE')",
		"has_column_privilege($1, 'public.scenarios', 'created_at', 'UPDATE')",
		"has_column_privilege($1, 'public.scenarios', 'guide', 'UPDATE')",
		"has_table_privilege($1, 'public.artifacts', 'TRUNCATE')",
		"has_table_privilege($1, 'public.artifacts', 'REFERENCES')",
		"has_table_privilege($1, 'public.artifacts', 'TRIGGER')",
		"has_column_privilege($1, 'public.artifacts', 'id', 'INSERT')",
		"has_column_privilege($1, 'public.artifacts', 'content', 'UPDATE')",
		"has_column_privilege($1, 'public.artifacts', 'file_name', 'UPDATE')",
		"has_function_privilege($1, 'public.artifacts_keep_scenario()', 'EXECUTE')",
		"has_table_privilege($1, 'public.events', 'INSERT')",
		"has_table_privilege($1, 'public.event_jobs', 'INSERT')",
		"has_function_privilege($1, 'public.record_honeytoken_request(text, text, inet, text, text, text)', 'EXECUTE')",
		"has_function_privilege($1, 'public.record_dns_query(text, text, text, text, text, inet, interval)', 'EXECUTE')",
		"has_function_privilege($1, 'public.honeytoken_event_limit_reached(uuid)', 'EXECUTE')",
		"has_table_privilege($1, 'public.events', 'UPDATE')",
		"has_table_privilege($1, 'public.event_jobs', 'SELECT')",
		"has_table_privilege($1, 'public.incidents', 'UPDATE')",
		"has_table_privilege($1, 'public.incidents', 'INSERT')",
		"has_column_privilege($1, 'public.incidents', 'closed_at', 'UPDATE')",
		"has_column_privilege($1, 'public.incidents', 'severity', 'UPDATE')",
		"has_table_privilege($1, 'public.alerts', 'SELECT')",
		"has_table_privilege($1, 'public.alerts', 'INSERT')",
		"has_function_privilege($1, 'public.incidents_change_status()', 'EXECUTE')",
		"has_table_privilege($1, 'public.periodic_tasks', 'SELECT')",
		"has_function_privilege($1, 'public.delete_expired_sign_in_data(integer)', 'EXECUTE')",
		"has_function_privilege($1, 'public.delete_expired_audit_entries(integer, integer)', 'EXECUTE')",
		"has_function_privilege($1, 'public.delete_expired_incident_data(integer, integer)', 'EXECUTE')",
		"has_function_privilege($1, 'public.close_inactive_incidents(integer, integer)', 'EXECUTE')",
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

// A new session was last seen when it was created. Two defaults would read the
// clock twice, in an order that nothing guarantees: the times would differ, and
// a last_seen_at read before created_at would fail its check. Many sessions in
// one statement make a tick of the clock between two reads all but certain.
func TestSchema_NewSessionWasLastSeenWhenCreated(t *testing.T) {
	t.Parallel()

	_, consoleURL := schematest.Console(t)
	pool := schematest.Open(t, consoleURL)
	if _, err := pool.Exec(t.Context(), `
WITH u AS (
	INSERT INTO users (email, display_name, role, status) VALUES ('s@example.com', 'S', 'viewer', 'pending') RETURNING id
)
INSERT INTO sessions (token_hash, user_id) SELECT sha256(i::text::bytea), u.id FROM u, generate_series(1, 2000) AS i`); err != nil {
		t.Fatalf("insert sessions: %v", err)
	}
	var differing int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM sessions WHERE last_seen_at <> created_at").Scan(&differing); err != nil {
		t.Fatal(err)
	}
	if differing != 0 {
		t.Errorf("%d new sessions were last seen at another time than they were created", differing)
	}
}
