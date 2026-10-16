-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- The schema of Nyktus. Until the first release it lives in this one file and is
-- changed in place; released versions add numbered migrations after it.

-- The console, the trigger, the DNS role and the worker connect as members of the
-- group roles nyktus_console, nyktus_trigger, nyktus_dns and nyktus_worker.
-- Operators create the group roles before the
-- first migration, so that the migrating role does not need CREATEROLE. A missing
-- role stops the migration here with a clear message instead of failing at the
-- first GRANT.
DO $$
DECLARE
	role_name text;
BEGIN
	FOREACH role_name IN ARRAY ARRAY['nyktus_console', 'nyktus_trigger', 'nyktus_dns', 'nyktus_worker'] LOOP
		IF to_regrole(role_name) IS NULL THEN
			RAISE EXCEPTION 'database role % does not exist; create the server roles with deploy/postgres/roles.sql before running migrations', role_name;
		END IF;
	END LOOP;
END
$$;

-- Addresses are stored in NFC normalization, which the schema checks with IS NFC
-- NORMALIZED. PostgreSQL normalizes only in UTF8 databases, so another encoding
-- would let every insert fail later.
DO $$
BEGIN
	IF current_setting('server_encoding') <> 'UTF8' THEN
		RAISE EXCEPTION 'database encoding is %, but Nyktus requires UTF8', current_setting('server_encoding');
	END IF;
END
$$;

-- Every server role receives explicit grants for the objects it needs. Removing the
-- default privileges of PUBLIC on the schema ensures that no role reaches these
-- objects implicitly, including roles created later for unrelated purposes.
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- REVOKE only warns when the executing role lacks the grant option, so the result
-- is verified instead of assumed.
DO $$
BEGIN
	IF has_schema_privilege('public', 'public', 'USAGE')
		OR has_schema_privilege('public', 'public', 'CREATE') THEN
		RAISE EXCEPTION 'PUBLIC still has privileges on schema public; run migrations as the owner of the schema';
	END IF;
END
$$;

CREATE TABLE public.users (
	-- Random identifiers reveal neither the number of accounts nor the order in
	-- which they were created.
	id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	-- The address is the sign-in name of an account and cannot be changed. An
	-- account with another address is a new account.
	email         text NOT NULL,
	display_name  text NOT NULL,
	role          text NOT NULL,
	status        text NOT NULL,
	password_hash text,
	-- An account of the identity provider signs in through OpenID Connect and
	-- has no password. The provider names it by its issuer and subject, never by
	-- the address, which the provider may let users change. Both are set when
	-- the account is created and cannot be changed.
	oidc_issuer   text,
	oidc_subject  text,
	-- The time of the insert, not the start of the transaction, so that accounts
	-- created in one transaction keep their order in the list, and an account
	-- created after waiting for a lock records the time it was created.
	created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
	-- Set by the trigger below on insert, so that an account that was never
	-- changed has equal times. A second clock_timestamp() would differ.
	updated_at    timestamptz NOT NULL,
	-- Five failed sign-ins in a row lock an account for 15 minutes. The counters
	-- live in the database, so that neither a restart nor a second console process
	-- resets them. failed_logins counts the failures since the last successful
	-- sign-in or the last lock; the fifth locks the account and starts the count
	-- again.
	failed_logins integer NOT NULL DEFAULT 0
		CONSTRAINT users_failed_logins_check CHECK (failed_logins BETWEEN 0 AND 4),
	locked_until  timestamptz,

	-- The application validates addresses and stores them in lower case and NFC,
	-- so the unique constraint covers every spelling of an address. The checks are
	-- deliberately simple and independent of the database locale; they reject what
	-- the application never writes.
	CONSTRAINT users_email_key UNIQUE (email),
	CONSTRAINT users_email_check CHECK (
		octet_length(email) <= 254
		AND email ~ '^[^@]+@[^@]+$'
		AND email !~ '[\x01-\x20\x7f"A-Z]'
		AND email IS NFC NORMALIZED
	),
	CONSTRAINT users_display_name_check CHECK (
		char_length(display_name) BETWEEN 1 AND 100
		AND display_name = btrim(display_name)
		AND display_name !~ '[\x01-\x1f\x7f]'
	),
	CONSTRAINT users_role_check CHECK (role IN ('admin', 'user', 'viewer')),
	-- A pending account has been created but has not set a password yet. An active
	-- account can sign in with its password. A deactivated account keeps its hash,
	-- if it had one, so that it can be reactivated without a new activation link.
	CONSTRAINT users_status_check CHECK (status IN ('pending', 'active', 'deactivated')),
	-- An account of the identity provider is created active and never sets a
	-- password, so it is never pending. An active account signs in with its
	-- password or through the provider, never both.
	CONSTRAINT users_password_check CHECK (
		(status <> 'pending' OR (password_hash IS NULL AND oidc_subject IS NULL))
		AND (status <> 'active' OR password_hash IS NOT NULL OR oidc_subject IS NOT NULL)
		AND (password_hash IS NULL OR oidc_subject IS NULL)
	),
	-- Only encoded Argon2id hashes are accepted, so a plain-text password can
	-- never be stored by mistake.
	CONSTRAINT users_password_hash_check CHECK (
		password_hash ~ '^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$'
	),
	CONSTRAINT users_updated_at_check CHECK (updated_at >= created_at),
	-- A subject has at most 255 ASCII characters (OpenID Connect Core 1.0,
	-- section 2) and is unique within its issuer.
	CONSTRAINT users_oidc_key UNIQUE (oidc_issuer, oidc_subject),
	CONSTRAINT users_oidc_check CHECK (
		(oidc_issuer IS NULL) = (oidc_subject IS NULL)
		AND char_length(oidc_issuer) BETWEEN 1 AND 2048
		AND oidc_issuer !~ '[^\x21-\x7e]'
		AND char_length(oidc_subject) BETWEEN 1 AND 255
		AND oidc_subject !~ '[^\x20-\x7e]'
	)
);

-- Administrators list accounts from the newest to the oldest, a page at a time,
-- continuing after the last account of the previous page. The identifier makes
-- the order total for accounts with the same creation time. The address is not
-- used as the position: it would end up in the query string of the next page,
-- and with it in the logs of proxies.
CREATE INDEX users_created_at_id_idx ON public.users (created_at DESC, id DESC);

-- A new row takes its creation time as the time of its last change, so that a
-- row that was never changed has equal times. A second clock_timestamp() in a
-- default would differ.
CREATE FUNCTION public.set_updated_at() RETURNS trigger
	LANGUAGE plpgsql
	SET search_path = ''
AS $$
BEGIN
	NEW.updated_at := NEW.created_at;
	RETURN NEW;
END
$$;

CREATE TRIGGER users_set_updated_at
	BEFORE INSERT ON public.users
	FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- At least one active administrator must remain once one exists. Without one,
-- nobody could manage the installation, and once no account with the role admin
-- is left, the setup of a first administrator opens again with the next start.
-- The console checks this rule before it demotes, deactivates or deletes an
-- account. This trigger is the last line of defense for every other way of
-- changing the table, such as a statement of a compromised console.
--
-- The function locks the other active administrators before it counts them. A
-- plain count would see the state before concurrent transactions commit, so two
-- transactions that each remove a different one of the last two administrators
-- would both pass. With the lock, the second one waits for the first and then
-- sees its result, or one of them fails with a deadlock; either way, one
-- administrator remains. The console locks all active administrators in a fixed
-- order before it changes one, so its own requests wait instead of deadlocking.
--
-- The error names the constraint users_active_admin_check, which does not exist
-- as a table constraint. The console recognizes the violation by this name, so
-- it must not change.
CREATE FUNCTION public.users_keep_active_admin() RETURNS trigger
	LANGUAGE plpgsql
	SET search_path = ''
AS $$
BEGIN
	IF OLD.role = 'admin' AND OLD.status = 'active'
		AND (TG_OP = 'DELETE' OR NEW.role <> 'admin' OR NEW.status <> 'active') THEN
		PERFORM FROM public.users AS u
		WHERE u.role = 'admin' AND u.status = 'active' AND u.id <> OLD.id
		ORDER BY u.id
		FOR UPDATE;
		IF NOT FOUND THEN
			RAISE EXCEPTION 'the last active administrator cannot be demoted, deactivated or deleted'
				USING ERRCODE = 'check_violation', CONSTRAINT = 'users_active_admin_check',
					TABLE = 'users', SCHEMA = 'public';
		END IF;
	END IF;
	IF TG_OP = 'DELETE' THEN
		RETURN OLD;
	END IF;
	RETURN NEW;
END
$$;

CREATE TRIGGER users_keep_active_admin
	BEFORE UPDATE OF role, status OR DELETE ON public.users
	FOR EACH ROW EXECUTE FUNCTION public.users_keep_active_admin();

-- Default privileges set by an operator for the owner, for example to give a
-- monitoring role read access, also apply when they name the console's group
-- role. The console would then hold more than its grants intend, such as TRUNCATE
-- or the right to set identifiers, so everything is revoked before the grants.
-- Revoking a table privilege also revokes it on every column.
REVOKE ALL ON public.users FROM PUBLIC, nyktus_console;
-- A trigger function runs with the rights of the role that fires the trigger, and
-- needs no grant for it. Nobody calls them directly.
REVOKE ALL ON FUNCTION public.set_updated_at() FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.users_keep_active_admin() FROM PUBLIC, nyktus_console;

-- The console reaches no table without the schema. It is granted with the first
-- table the console uses, because the migration of the schema runs before any
-- server role is checked.
GRANT USAGE ON SCHEMA public TO nyktus_console;
GRANT SELECT, DELETE ON public.users TO nyktus_console;
-- Identifiers, creation times and the lockout counters come from the database
-- when an account is created. The console cannot set them, and it cannot change
-- identifiers, creation times, addresses or the identity of an account of the
-- identity provider.
GRANT INSERT (email, display_name, role, status, password_hash, oidc_issuer, oidc_subject) ON public.users TO nyktus_console;
GRANT UPDATE (display_name, role, status, password_hash, updated_at, failed_logins, locked_until)
	ON public.users TO nyktus_console;

-- GRANT and REVOKE only warn when the executing role lacks the privilege, so the
-- result is verified instead of assumed, in both directions.
DO $$
BEGIN
	IF NOT has_schema_privilege('nyktus_console', 'public', 'USAGE')
		OR NOT has_table_privilege('nyktus_console', 'public.users', 'SELECT')
		OR NOT has_table_privilege('nyktus_console', 'public.users', 'DELETE')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['email', 'display_name', 'role', 'status', 'password_hash', 'oidc_issuer',
				'oidc_subject']) AS c (name)
			WHERE NOT has_column_privilege('nyktus_console', 'public.users', c.name, 'INSERT')
		)
		OR EXISTS (
			SELECT FROM unnest(ARRAY['display_name', 'role', 'status', 'password_hash', 'updated_at',
				'failed_logins', 'locked_until']) AS c (name)
			WHERE NOT has_column_privilege('nyktus_console', 'public.users', c.name, 'UPDATE')
		) THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.users; run migrations as the owner of the schema';
	END IF;

	IF has_table_privilege('nyktus_console', 'public.users', 'INSERT')
		OR has_table_privilege('nyktus_console', 'public.users', 'UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.users', 'REFERENCES')
		OR has_function_privilege('nyktus_console', 'public.set_updated_at()', 'EXECUTE')
		OR has_function_privilege('nyktus_console', 'public.users_keep_active_admin()', 'EXECUTE')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['id', 'created_at', 'updated_at', 'failed_logins', 'locked_until']) AS c (name)
			WHERE has_column_privilege('nyktus_console', 'public.users', c.name, 'INSERT')
		)
		OR EXISTS (
			SELECT FROM unnest(ARRAY['id', 'email', 'created_at', 'oidc_issuer', 'oidc_subject']) AS c (name)
			WHERE has_column_privilege('nyktus_console', 'public.users', c.name, 'UPDATE')
		) THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on public.users than granted; check the default privileges of the owner';
	END IF;
END
$$;

-- The audit log records security-relevant actions. It is append-only for the
-- application: the console may add and read entries, but never change or remove
-- them, so a compromised console cannot cover its tracks.
-- Field names of an update, without their values: the audit log must not become a
-- second copy of the inventory. A CHECK constraint cannot hold a subquery, so the
-- rules for the elements live in this function.
CREATE FUNCTION public.audit_field_names_valid(names text[]) RETURNS boolean
	LANGUAGE sql IMMUTABLE STRICT
	SET search_path = ''
	RETURN cardinality(names) <= 32
		AND coalesce(array_ndims(names), 1) = 1
		AND NOT EXISTS (
			SELECT FROM unnest(names) AS n (name)
			WHERE n.name IS NULL OR n.name !~ '^[a-z][a-z_]{0,63}$'
		)
		AND cardinality(names) = (SELECT count(DISTINCT n.name) FROM unnest(names) AS n (name));

CREATE TABLE public.audit_entries (
	id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	-- The time of the write, not the start of the transaction, so that the
	-- entries of one transaction keep their order.
	occurred_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
	action             text NOT NULL,
	outcome            text NOT NULL,
	actor_kind         text NOT NULL,
	auth_method        text NOT NULL,
	-- Users can be deleted. Their entries stay readable through the copies of
	-- address and display name, which the trigger below takes from the account
	-- when the entry is written.
	actor_user_id      uuid CONSTRAINT audit_entries_actor_user_id_fkey REFERENCES public.users (id) ON DELETE SET NULL,
	actor_email        text,
	actor_display_name text,
	-- Keys are deleted when they are revoked, so there is no foreign key. Their
	-- entries stay readable through the copy of the name of the key, which the
	-- trigger below takes from the key when the entry is written.
	api_key_id         uuid,
	-- Resources can be deleted while their entries remain, so there is no foreign
	-- key. Names are never copied: the audit log must not reveal the inventory.
	resource_type      text,
	resource_id        uuid,
	changed_fields     text[] NOT NULL,
	client_ip          inet,
	request_id         text,

	-- Actions are named "resource.verb", for example "user.create".
	CONSTRAINT audit_entries_action_check CHECK (
		char_length(action) <= 64 AND action ~ '^[a-z][a-z_]*\.[a-z][a-z_]*$'
	),
	CONSTRAINT audit_entries_outcome_check CHECK (outcome IN ('success', 'failure', 'denied')),
	-- An API key belongs to the team, not to a user, so it is an actor of its own,
	-- named by the copy of its name. A user who activates their account or
	-- resets their password authenticates with the token of the link, before
	-- they have a new password; requests with an invalid token are not recorded,
	-- so anonymous actors never use those methods. The second step of a sign-in
	-- authenticates with a TOTP code or a recovery code; it always belongs to a
	-- known account, because only the correct password starts it. The command
	-- line and background jobs act as the system.
	CONSTRAINT audit_entries_actor_check CHECK (
		CASE actor_kind
			WHEN 'user' THEN auth_method IN ('password', 'oidc', 'session', 'activation_token', 'password_reset_token',
					'totp', 'recovery_code')
				AND actor_email IS NOT NULL AND actor_display_name IS NOT NULL
			WHEN 'api_key' THEN auth_method = 'api_key'
				AND actor_user_id IS NULL AND actor_email IS NULL AND actor_display_name IS NOT NULL
			WHEN 'setup' THEN auth_method = 'setup_token'
				AND actor_user_id IS NULL AND actor_email IS NULL AND actor_display_name IS NULL
			WHEN 'system' THEN auth_method IN ('cli', 'none')
				AND actor_user_id IS NULL AND actor_email IS NULL AND actor_display_name IS NULL
			WHEN 'anonymous' THEN auth_method IN ('password', 'oidc', 'setup_token')
				AND actor_user_id IS NULL AND actor_email IS NULL AND actor_display_name IS NULL
			ELSE false
		END
	),
	CONSTRAINT audit_entries_api_key_check CHECK ((auth_method = 'api_key') = (api_key_id IS NOT NULL)),
	CONSTRAINT audit_entries_resource_check CHECK (
		(resource_type IS NULL) = (resource_id IS NULL)
		AND (char_length(resource_type) <= 64 AND resource_type ~ '^[a-z][a-z_]*$')
	),
	CONSTRAINT audit_entries_changed_fields_check CHECK (public.audit_field_names_valid(changed_fields)),
	-- A client address, never a network.
	CONSTRAINT audit_entries_client_ip_check CHECK (
		masklen(client_ip) = CASE family(client_ip) WHEN 4 THEN 32 ELSE 128 END
	),
	-- Request IDs are generated by the server, never taken from a request.
	CONSTRAINT audit_entries_request_id_check CHECK (request_id ~ '^[A-Z2-7]{26}$')
);

-- Deleting a user sets the reference of every entry to NULL, which would scan
-- the whole table without this index. Entries that are recorded at most once
-- per window look for a recent entry of the same user, action and outcome, and
-- must not read every entry the user ever caused: an integration that polls
-- the audit log adds one every minute.
CREATE INDEX audit_entries_actor_user_id_idx ON public.audit_entries (actor_user_id, action, outcome, occurred_at);

-- The same lookup for the entries of an API key, which polls more than anyone.
CREATE INDEX audit_entries_api_key_id_idx ON public.audit_entries (api_key_id, action, outcome, occurred_at);

-- The console lists entries from the newest to the oldest, a page at a time,
-- continuing after the last entry of the previous page. The identifier makes the
-- order total for entries with the same time.
CREATE INDEX audit_entries_occurred_at_id_idx ON public.audit_entries (occurred_at DESC, id DESC);

-- The copies of the actor's address and display name are taken from the account,
-- or the name of an API key from the key, not from the application, so they
-- always match the actor at the time of the entry. Without an account or key,
-- they are NULL, and the actor check rejects an entry of an actor that does not
-- exist.
CREATE FUNCTION public.audit_entries_copy_actor() RETURNS trigger
	LANGUAGE plpgsql
	SET search_path = ''
AS $$
BEGIN
	NEW.actor_email := NULL;
	NEW.actor_display_name := NULL;
	IF NEW.actor_user_id IS NOT NULL THEN
		SELECT u.email, u.display_name INTO NEW.actor_email, NEW.actor_display_name
		FROM public.users AS u
		WHERE u.id = NEW.actor_user_id;
	ELSIF NEW.actor_kind = 'api_key' AND NEW.api_key_id IS NOT NULL THEN
		SELECT k.name INTO NEW.actor_display_name
		FROM public.api_keys AS k
		WHERE k.id = NEW.api_key_id;
	END IF;
	RETURN NEW;
END
$$;

CREATE TRIGGER audit_entries_copy_actor
	BEFORE INSERT ON public.audit_entries
	FOR EACH ROW EXECUTE FUNCTION public.audit_entries_copy_actor();

-- Default privileges set by an operator could grant more than this migration
-- intends, so everything is revoked before the grants.
REVOKE ALL ON public.audit_entries FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.audit_field_names_valid(text[]) FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.audit_entries_copy_actor() FROM PUBLIC, nyktus_console;

-- The console evaluates the check of the changed fields when it inserts.
GRANT EXECUTE ON FUNCTION public.audit_field_names_valid(text[]) TO nyktus_console;
GRANT SELECT ON public.audit_entries TO nyktus_console;
-- Identifiers, times and the copies of the actor come from the database. The
-- console cannot set them.
GRANT INSERT (action, outcome, actor_kind, auth_method, actor_user_id, api_key_id,
	resource_type, resource_id, changed_fields, client_ip, request_id)
	ON public.audit_entries TO nyktus_console;

-- GRANT and REVOKE only warn when the executing role lacks the privilege, so the
-- result is verified instead of assumed: the console can add and read entries,
-- and nothing else.
DO $$
BEGIN
	IF NOT has_table_privilege('nyktus_console', 'public.audit_entries', 'SELECT')
		OR NOT has_function_privilege('nyktus_console', 'public.audit_field_names_valid(text[])', 'EXECUTE')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['action', 'outcome', 'actor_kind', 'auth_method', 'actor_user_id',
				'api_key_id', 'resource_type', 'resource_id', 'changed_fields', 'client_ip', 'request_id']) AS c (name)
			WHERE NOT has_column_privilege('nyktus_console', 'public.audit_entries', c.name, 'INSERT')
		) THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.audit_entries; run migrations as the owner of the schema';
	END IF;

	IF has_table_privilege('nyktus_console', 'public.audit_entries', 'INSERT')
		OR has_table_privilege('nyktus_console', 'public.audit_entries', 'UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.audit_entries', 'UPDATE, REFERENCES')
		OR has_function_privilege('nyktus_console', 'public.audit_entries_copy_actor()', 'EXECUTE')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['id', 'occurred_at', 'actor_email', 'actor_display_name']) AS c (name)
			WHERE has_column_privilege('nyktus_console', 'public.audit_entries', c.name, 'INSERT')
		) THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on public.audit_entries than granted; check the default privileges of the owner';
	END IF;
END
$$;

-- While no administrator exists, every console process that starts issues a
-- setup token and prints it. Whoever holds one can create the first
-- administrator. Tokens of other console processes stay valid until they expire,
-- so that the setup works behind a load balancer.
CREATE TABLE public.setup_tokens (
	-- Only the SHA-256 hash of a token is stored, so that reading the table does
	-- not reveal a usable token.
	token_hash bytea NOT NULL,
	-- The database sets the expiry, so that the console cannot issue a token that
	-- stays valid longer.
	expires_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '1 hour',

	CONSTRAINT setup_tokens_pkey PRIMARY KEY (token_hash),
	CONSTRAINT setup_tokens_token_hash_check CHECK (octet_length(token_hash) = 32)
);

-- Default privileges set by an operator could grant more than this migration
-- intends, so everything is revoked before the grants.
REVOKE ALL ON public.setup_tokens FROM PUBLIC, nyktus_console;

-- The console looks tokens up, issues them and consumes them. DELETE also lets it
-- lock the table, which serializes the creation of the first administrator.
GRANT SELECT, DELETE ON public.setup_tokens TO nyktus_console;
GRANT INSERT (token_hash) ON public.setup_tokens TO nyktus_console;

-- GRANT and REVOKE only warn when the executing role lacks the privilege, so the
-- result is verified instead of assumed, in both directions.
DO $$
BEGIN
	IF NOT has_table_privilege('nyktus_console', 'public.setup_tokens', 'SELECT')
		OR NOT has_table_privilege('nyktus_console', 'public.setup_tokens', 'DELETE')
		OR NOT has_column_privilege('nyktus_console', 'public.setup_tokens', 'token_hash', 'INSERT') THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.setup_tokens; run migrations as the owner of the schema';
	END IF;

	IF has_table_privilege('nyktus_console', 'public.setup_tokens', 'INSERT')
		OR has_table_privilege('nyktus_console', 'public.setup_tokens', 'UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.setup_tokens', 'UPDATE, REFERENCES')
		OR has_column_privilege('nyktus_console', 'public.setup_tokens', 'expires_at', 'INSERT') THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on public.setup_tokens than granted; check the default privileges of the owner';
	END IF;
END
$$;

-- Sessions of signed-in users. The browser holds an opaque token in a cookie; the
-- database stores only its SHA-256 hash, so reading the table does not reveal a
-- usable session. A session ends after a period without requests and after an
-- absolute lifetime. Both limits are configuration of the console, which applies
-- them in its queries against the time of the database.
CREATE TABLE public.sessions (
	-- A random identifier names a session in the audit log and lets a user end a
	-- single session, without revealing its token.
	id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	token_hash   bytea NOT NULL,
	-- Deleting a user ends all of their sessions.
	user_id      uuid NOT NULL CONSTRAINT sessions_user_id_fkey REFERENCES public.users (id) ON DELETE CASCADE,
	created_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
	-- Set by the trigger below on insert, so that a new session was last seen
	-- when it was created. A second default would read the clock again, in an
	-- order that nothing guarantees, and could fail the check below.
	last_seen_at timestamptz NOT NULL,
	-- When the user of an account of the identity provider last signed in there
	-- again for this session. A sensitive action, which a local account
	-- confirms with its password, requires that it was a few minutes ago.
	reauthenticated_at timestamptz,

	CONSTRAINT sessions_token_hash_key UNIQUE (token_hash),
	CONSTRAINT sessions_token_hash_check CHECK (octet_length(token_hash) = 32),
	CONSTRAINT sessions_last_seen_at_check CHECK (last_seen_at >= created_at),
	CONSTRAINT sessions_reauthenticated_at_check CHECK (reauthenticated_at >= created_at)
)
-- Rows of this table come and go all the time while few of them live at once.
-- The default lets dead rows reach a fifth of the table before autovacuum
-- removes them, which for a small, busy table means scans over mostly dead
-- rows; a fiftieth keeps it compact. The same applies to the other tables
-- with these settings.
WITH (autovacuum_vacuum_scale_factor = 0.02, autovacuum_analyze_scale_factor = 0.05);

-- Signing in removes the expired sessions of the user, and deleting a user
-- removes all of them.
CREATE INDEX sessions_user_id_idx ON public.sessions (user_id);

CREATE FUNCTION public.sessions_set_last_seen_at() RETURNS trigger
	LANGUAGE plpgsql
	SET search_path = ''
AS $$
BEGIN
	NEW.last_seen_at := NEW.created_at;
	RETURN NEW;
END
$$;

CREATE TRIGGER sessions_set_last_seen_at
	BEFORE INSERT ON public.sessions
	FOR EACH ROW EXECUTE FUNCTION public.sessions_set_last_seen_at();

-- Default privileges set by an operator could grant more than this migration
-- intends, so everything is revoked before the grants.
REVOKE ALL ON public.sessions FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.sessions_set_last_seen_at() FROM PUBLIC, nyktus_console;

GRANT SELECT, DELETE ON public.sessions TO nyktus_console;
-- Identifiers and times come from the database. The console only records when a
-- session was last used and when its user signed in at the identity provider
-- again.
GRANT INSERT (token_hash, user_id) ON public.sessions TO nyktus_console;
GRANT UPDATE (last_seen_at, reauthenticated_at) ON public.sessions TO nyktus_console;

-- GRANT and REVOKE only warn when the executing role lacks the privilege, so the
-- result is verified instead of assumed, in both directions.
DO $$
BEGIN
	IF NOT has_table_privilege('nyktus_console', 'public.sessions', 'SELECT')
		OR NOT has_table_privilege('nyktus_console', 'public.sessions', 'DELETE')
		OR NOT has_column_privilege('nyktus_console', 'public.sessions', 'token_hash', 'INSERT')
		OR NOT has_column_privilege('nyktus_console', 'public.sessions', 'user_id', 'INSERT')
		OR NOT has_column_privilege('nyktus_console', 'public.sessions', 'last_seen_at', 'UPDATE')
		OR NOT has_column_privilege('nyktus_console', 'public.sessions', 'reauthenticated_at', 'UPDATE') THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.sessions; run migrations as the owner of the schema';
	END IF;

	IF has_table_privilege('nyktus_console', 'public.sessions', 'INSERT')
		OR has_table_privilege('nyktus_console', 'public.sessions', 'UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.sessions', 'REFERENCES')
		OR has_function_privilege('nyktus_console', 'public.sessions_set_last_seen_at()', 'EXECUTE')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['id', 'created_at', 'last_seen_at', 'reauthenticated_at']) AS c (name)
			WHERE has_column_privilege('nyktus_console', 'public.sessions', c.name, 'INSERT')
		)
		OR EXISTS (
			SELECT FROM unnest(ARRAY['id', 'token_hash', 'user_id', 'created_at']) AS c (name)
			WHERE has_column_privilege('nyktus_console', 'public.sessions', c.name, 'UPDATE')
		) THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on public.sessions than granted; check the default privileges of the owner';
	END IF;
END
$$;

-- A user who enabled a second factor signs in in two steps. The correct password
-- yields a challenge, a short-lived token in a cookie, which a code of the second
-- factor turns into a session. As with sessions, the database stores only the
-- SHA-256 hash of the token. Every change that ends the sessions of an account
-- also removes its challenges, so a challenge cannot outlive the password that
-- earned it.
CREATE TABLE public.sign_in_challenges (
	token_hash bytea PRIMARY KEY,
	user_id    uuid NOT NULL CONSTRAINT sign_in_challenges_user_id_fkey REFERENCES public.users (id) ON DELETE CASCADE,
	-- The lifetime is fixed here, so that the console cannot extend it.
	expires_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '5 minutes',

	CONSTRAINT sign_in_challenges_token_hash_check CHECK (octet_length(token_hash) = 32)
);

-- Ending the sessions of an account removes its challenges as well.
CREATE INDEX sign_in_challenges_user_id_idx ON public.sign_in_challenges (user_id);

-- The TOTP factor of an account (RFC 6238). The secret must be read back to
-- check a code, so it is encrypted by the console with a key from its
-- configuration, which never reaches the database. The first byte names that
-- key, so that keys can be replaced.
CREATE TABLE public.totp_factors (
	user_id        uuid PRIMARY KEY CONSTRAINT totp_factors_user_id_fkey REFERENCES public.users (id) ON DELETE CASCADE,
	secret         bytea NOT NULL,
	created_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
	-- NULL while the user has not yet confirmed the factor with a first code. An
	-- unconfirmed factor does not protect the sign-in.
	confirmed_at   timestamptz,
	-- The time step of the last accepted code. Only codes of later steps are
	-- accepted, so that a code cannot be used twice.
	last_used_step bigint,

	-- Key ID (1 to 255), nonce (12 bytes), the encrypted secret of 20 bytes and
	-- the authentication tag (16 bytes).
	CONSTRAINT totp_factors_secret_check CHECK (octet_length(secret) = 49 AND get_byte(secret, 0) > 0),
	CONSTRAINT totp_factors_confirmed_check CHECK (
		(confirmed_at IS NULL) = (last_used_step IS NULL) AND confirmed_at >= created_at
	),
	CONSTRAINT totp_factors_last_used_step_check CHECK (last_used_step >= 0)
);

-- Recovery codes of a TOTP factor. Each signs in once in place of a code. They
-- are random values of 80 bits, so a SHA-256 hash is enough to store them.
-- Removing the factor removes its codes.
CREATE TABLE public.recovery_codes (
	user_id   uuid NOT NULL CONSTRAINT recovery_codes_user_id_fkey REFERENCES public.totp_factors (user_id) ON DELETE CASCADE,
	code_hash bytea NOT NULL,

	CONSTRAINT recovery_codes_pkey PRIMARY KEY (user_id, code_hash),
	CONSTRAINT recovery_codes_code_hash_check CHECK (octet_length(code_hash) = 32)
);

REVOKE ALL ON public.sign_in_challenges, public.totp_factors, public.recovery_codes FROM PUBLIC, nyktus_console;

-- Challenges and recovery codes are issued, looked up and consumed, never
-- changed. Expiry times come from the database.
GRANT SELECT, DELETE ON public.sign_in_challenges TO nyktus_console;
GRANT INSERT (token_hash, user_id) ON public.sign_in_challenges TO nyktus_console;
GRANT SELECT, DELETE ON public.recovery_codes TO nyktus_console;
GRANT INSERT (user_id, code_hash) ON public.recovery_codes TO nyktus_console;
-- The console confirms a factor, records the step of each accepted code and
-- encrypts the secret again under a new key. It cannot move a factor to another
-- account or change its creation time.
GRANT SELECT, DELETE ON public.totp_factors TO nyktus_console;
GRANT INSERT (user_id, secret) ON public.totp_factors TO nyktus_console;
GRANT UPDATE (secret, confirmed_at, last_used_step) ON public.totp_factors TO nyktus_console;

DO $$
BEGIN
	-- has_table_privilege with several privileges is true if any is held, so
	-- each one is checked on its own.
	IF EXISTS (
			SELECT FROM unnest(ARRAY['public.sign_in_challenges', 'public.recovery_codes', 'public.totp_factors']) AS t (tbl),
				unnest(ARRAY['SELECT', 'DELETE']) AS p (priv)
			WHERE NOT has_table_privilege('nyktus_console', t.tbl, p.priv)
		)
		OR EXISTS (
			SELECT FROM (VALUES
				('public.sign_in_challenges', 'token_hash', 'INSERT'),
				('public.sign_in_challenges', 'user_id', 'INSERT'),
				('public.recovery_codes', 'user_id', 'INSERT'),
				('public.recovery_codes', 'code_hash', 'INSERT'),
				('public.totp_factors', 'user_id', 'INSERT'),
				('public.totp_factors', 'secret', 'INSERT'),
				('public.totp_factors', 'secret', 'UPDATE'),
				('public.totp_factors', 'confirmed_at', 'UPDATE'),
				('public.totp_factors', 'last_used_step', 'UPDATE')
			) AS p (tbl, col, priv)
			WHERE NOT has_column_privilege('nyktus_console', p.tbl, p.col, p.priv)
		) THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on the tables of the second factor; run migrations as the owner of the schema';
	END IF;

	IF has_table_privilege('nyktus_console', 'public.sign_in_challenges', 'INSERT, UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_table_privilege('nyktus_console', 'public.recovery_codes', 'INSERT, UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_table_privilege('nyktus_console', 'public.totp_factors', 'INSERT, UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.sign_in_challenges', 'UPDATE, REFERENCES')
		OR has_any_column_privilege('nyktus_console', 'public.recovery_codes', 'UPDATE, REFERENCES')
		OR has_any_column_privilege('nyktus_console', 'public.totp_factors', 'REFERENCES')
		OR EXISTS (
			SELECT FROM (VALUES
				('public.sign_in_challenges', 'expires_at', 'INSERT'),
				('public.totp_factors', 'created_at', 'INSERT'),
				('public.totp_factors', 'confirmed_at', 'INSERT'),
				('public.totp_factors', 'last_used_step', 'INSERT'),
				('public.totp_factors', 'user_id', 'UPDATE'),
				('public.totp_factors', 'created_at', 'UPDATE')
			) AS p (tbl, col, priv)
			WHERE has_column_privilege('nyktus_console', p.tbl, p.col, p.priv)
		) THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on the tables of the second factor than granted; check the default privileges of the owner';
	END IF;
END
$$;

-- A sign-in through OpenID Connect leaves the console for the identity provider
-- and returns with a code. So does a reauthentication, with which a signed-in
-- user of the provider confirms a sensitive action. Its state is kept here between the two requests, so
-- that it works across console processes. The browser that started the sign-in
-- holds a token in a cookie, which binds the sign-in to it; the state parameter
-- travels through the provider and names the row. Only the SHA-256 hashes of
-- both are stored. The nonce and the PKCE verifier go to the provider in the
-- course of the sign-in, so they are kept as they are; they are of no use
-- without the code, which only the browser receives. A row is consumed once.
CREATE TABLE public.oidc_logins (
	state_hash    bytea PRIMARY KEY,
	browser_hash  bytea NOT NULL,
	nonce         text NOT NULL,
	code_verifier text NOT NULL,
	purpose       text NOT NULL,
	-- The hash of the token of the session that the browser held when the
	-- sign-in started, which ends when the new one starts. The browser does
	-- not send its session cookie, which is SameSite=Strict, when the provider
	-- sends it back from another site.
	previous_session_hash bytea,
	-- The session that a reauthentication confirms, and the page of the
	-- console to which the browser returns. A reauthentication ends with its
	-- session.
	session_id    uuid CONSTRAINT oidc_logins_session_id_fkey REFERENCES public.sessions (id) ON DELETE CASCADE,
	return_to     text,
	created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
	-- The lifetime is fixed here, so that the console cannot extend it.
	expires_at    timestamptz NOT NULL DEFAULT clock_timestamp() + interval '10 minutes',

	CONSTRAINT oidc_logins_purpose_check CHECK (
		CASE purpose
			WHEN 'sign_in' THEN session_id IS NULL AND return_to IS NULL
			WHEN 'reauthentication' THEN session_id IS NOT NULL AND return_to IS NOT NULL AND previous_session_hash IS NULL
			ELSE false
		END
	),
	-- A path of the console, never another site: not a URL, not
	-- protocol-relative, and without a fragment, to which the console appends
	-- its own.
	CONSTRAINT oidc_logins_return_to_check CHECK (
		char_length(return_to) <= 512 AND return_to ~ '^/([^/\\]|$)' AND return_to !~ '[#\\\x01-\x20\x7f]'
	),
	CONSTRAINT oidc_logins_state_hash_check CHECK (octet_length(state_hash) = 32),
	CONSTRAINT oidc_logins_browser_hash_check CHECK (octet_length(browser_hash) = 32),
	CONSTRAINT oidc_logins_previous_session_hash_check CHECK (octet_length(previous_session_hash) = 32),
	-- Unpadded base64url of 256 random bits. A PKCE verifier must have 43 to 128
	-- unreserved characters (RFC 7636, section 4.1).
	CONSTRAINT oidc_logins_nonce_check CHECK (nonce ~ '^[A-Za-z0-9_-]{43}$'),
	CONSTRAINT oidc_logins_code_verifier_check CHECK (code_verifier ~ '^[A-Za-z0-9_-]{43}$')
)
-- Busy and short-lived, like sessions.
WITH (autovacuum_vacuum_scale_factor = 0.02, autovacuum_analyze_scale_factor = 0.05);

-- The worker removes the expired sign-ins through this index. Every request
-- that starts a sign-in adds a row, before any authentication.
CREATE INDEX oidc_logins_expires_at_idx ON public.oidc_logins (expires_at);

-- Ending a session removes its reauthentication.
CREATE INDEX oidc_logins_session_id_idx ON public.oidc_logins (session_id);

REVOKE ALL ON public.oidc_logins FROM PUBLIC, nyktus_console;

-- Sign-ins are started, consumed and removed when they expire, never changed.
GRANT SELECT, DELETE ON public.oidc_logins TO nyktus_console;
GRANT INSERT (state_hash, browser_hash, nonce, code_verifier, purpose, previous_session_hash, session_id, return_to)
	ON public.oidc_logins TO nyktus_console;

DO $$
BEGIN
	IF NOT has_table_privilege('nyktus_console', 'public.oidc_logins', 'SELECT')
		OR NOT has_table_privilege('nyktus_console', 'public.oidc_logins', 'DELETE')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['state_hash', 'browser_hash', 'nonce', 'code_verifier', 'purpose', 'previous_session_hash',
				'session_id', 'return_to']) AS c (name)
			WHERE NOT has_column_privilege('nyktus_console', 'public.oidc_logins', c.name, 'INSERT')
		) THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.oidc_logins; run migrations as the owner of the schema';
	END IF;

	IF has_table_privilege('nyktus_console', 'public.oidc_logins', 'INSERT, UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.oidc_logins', 'UPDATE, REFERENCES')
		OR has_column_privilege('nyktus_console', 'public.oidc_logins', 'expires_at', 'INSERT')
		OR has_column_privilege('nyktus_console', 'public.oidc_logins', 'created_at', 'INSERT') THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on public.oidc_logins than granted; check the default privileges of the owner';
	END IF;
END
$$;

-- API keys let integrations call the API. They belong to the team, not to the
-- administrator who created them, and act with their scopes alone. As with
-- sessions, the database stores only the SHA-256 hash of the secret; the key
-- itself also carries the identifier, which looks the key up, so that the
-- secret is compared in the application in constant time. The application
-- decides which scopes keys may carry, so they are only checked for their form
-- here. Revoking a key deletes it.
CREATE FUNCTION public.api_key_scopes_valid(scopes text[]) RETURNS boolean
	LANGUAGE sql IMMUTABLE STRICT
	SET search_path = ''
	RETURN cardinality(scopes) BETWEEN 1 AND 16
		AND array_ndims(scopes) = 1
		AND NOT EXISTS (
			SELECT FROM unnest(scopes) AS s (scope)
			WHERE s.scope IS NULL OR char_length(s.scope) > 64 OR s.scope !~ '^[a-z][a-z_]*:[a-z][a-z_]*$'
		)
		AND cardinality(scopes) = (SELECT count(DISTINCT s.scope) FROM unnest(scopes) AS s (scope));

CREATE TABLE public.api_keys (
	id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	-- The administrator who created the key. The key outlives the account.
	created_by   uuid CONSTRAINT api_keys_created_by_fkey REFERENCES public.users (id) ON DELETE SET NULL,
	name         text NOT NULL,
	secret_hash  bytea NOT NULL,
	scopes       text[] NOT NULL,
	created_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
	expires_at   timestamptz NOT NULL,
	last_used_at timestamptz,

	CONSTRAINT api_keys_name_check CHECK (char_length(name) BETWEEN 1 AND 64),
	CONSTRAINT api_keys_secret_hash_check CHECK (octet_length(secret_hash) = 32),
	CONSTRAINT api_keys_scopes_check CHECK (public.api_key_scopes_valid(scopes)),
	-- Every key expires within three years. The difference of two times is
	-- immutable, unlike the sum of a time and an interval, which depends on the
	-- time zone.
	CONSTRAINT api_keys_expires_at_check CHECK (expires_at > created_at AND expires_at - created_at <= interval '1096 days'),
	CONSTRAINT api_keys_last_used_at_check CHECK (last_used_at >= created_at)
);

-- Deleting a user sets the reference of their keys to NULL, which would scan
-- the table without this index.
CREATE INDEX api_keys_created_by_idx ON public.api_keys (created_by);

REVOKE ALL ON public.api_keys FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.api_key_scopes_valid(text[]) FROM PUBLIC, nyktus_console;

-- The console evaluates the check of the scopes when it inserts. It issues,
-- lists and deletes keys and records their last use; it cannot change the
-- secret, the scopes, the creator or the expiry of a key, and identifiers and
-- creation times come from the database.
GRANT EXECUTE ON FUNCTION public.api_key_scopes_valid(text[]) TO nyktus_console;
GRANT SELECT, DELETE ON public.api_keys TO nyktus_console;
GRANT INSERT (created_by, name, secret_hash, scopes, expires_at) ON public.api_keys TO nyktus_console;
GRANT UPDATE (last_used_at) ON public.api_keys TO nyktus_console;

DO $$
BEGIN
	IF NOT has_table_privilege('nyktus_console', 'public.api_keys', 'SELECT')
		OR NOT has_table_privilege('nyktus_console', 'public.api_keys', 'DELETE')
		OR NOT has_function_privilege('nyktus_console', 'public.api_key_scopes_valid(text[])', 'EXECUTE')
		OR NOT has_column_privilege('nyktus_console', 'public.api_keys', 'last_used_at', 'UPDATE')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['created_by', 'name', 'secret_hash', 'scopes', 'expires_at']) AS c (name)
			WHERE NOT has_column_privilege('nyktus_console', 'public.api_keys', c.name, 'INSERT')
		) THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.api_keys; run migrations as the owner of the schema';
	END IF;

	IF has_table_privilege('nyktus_console', 'public.api_keys', 'INSERT, UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.api_keys', 'REFERENCES')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['id', 'created_at', 'last_used_at']) AS c (name)
			WHERE has_column_privilege('nyktus_console', 'public.api_keys', c.name, 'INSERT')
		)
		OR EXISTS (
			SELECT FROM unnest(ARRAY['id', 'created_by', 'name', 'secret_hash', 'scopes', 'created_at', 'expires_at']) AS c (name)
			WHERE has_column_privilege('nyktus_console', 'public.api_keys', c.name, 'UPDATE')
		) THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on public.api_keys than granted; check the default privileges of the owner';
	END IF;
END
$$;

-- A link lets a user set their password, for two purposes: activating a new
-- account and resetting the password of an active one. Both are issued by an
-- administrator, who sees the link once and passes it on, so they share one
-- table, and an account has at most one open link; a new link replaces the
-- previous one. The purpose is stored so that each public endpoint consumes only
-- links issued for it.
CREATE TABLE public.account_links (
	-- Deleting an account removes its link.
	user_id    uuid CONSTRAINT account_links_pkey PRIMARY KEY
		CONSTRAINT account_links_user_id_fkey REFERENCES public.users (id) ON DELETE CASCADE,
	-- Only the SHA-256 hash of a token is stored, so that reading the table does
	-- not reveal a usable link.
	token_hash bytea NOT NULL,
	purpose    text NOT NULL,
	-- The database sets the expiry, so that the console cannot issue a link that
	-- stays valid longer. Both purposes share it: both links travel the same way
	-- and carry the same risk.
	expires_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '72 hours',

	CONSTRAINT account_links_token_hash_key UNIQUE (token_hash),
	CONSTRAINT account_links_token_hash_check CHECK (octet_length(token_hash) = 32),
	CONSTRAINT account_links_purpose_check CHECK (purpose IN ('activation', 'password_reset'))
);

-- Default privileges set by an operator could grant more than this migration
-- intends, so everything is revoked before the grants.
REVOKE ALL ON public.account_links FROM PUBLIC, nyktus_console;

-- The console issues, looks up and consumes links. It never changes one.
GRANT SELECT, DELETE ON public.account_links TO nyktus_console;
GRANT INSERT (user_id, token_hash, purpose) ON public.account_links TO nyktus_console;

-- GRANT and REVOKE only warn when the executing role lacks the privilege, so the
-- result is verified instead of assumed, in both directions.
DO $$
BEGIN
	IF NOT has_table_privilege('nyktus_console', 'public.account_links', 'SELECT')
		OR NOT has_table_privilege('nyktus_console', 'public.account_links', 'DELETE')
		OR NOT has_column_privilege('nyktus_console', 'public.account_links', 'user_id', 'INSERT')
		OR NOT has_column_privilege('nyktus_console', 'public.account_links', 'token_hash', 'INSERT')
		OR NOT has_column_privilege('nyktus_console', 'public.account_links', 'purpose', 'INSERT') THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.account_links; run migrations as the owner of the schema';
	END IF;

	IF has_table_privilege('nyktus_console', 'public.account_links', 'INSERT')
		OR has_table_privilege('nyktus_console', 'public.account_links', 'UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.account_links', 'UPDATE, REFERENCES')
		OR has_column_privilege('nyktus_console', 'public.account_links', 'expires_at', 'INSERT') THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on public.account_links than granted; check the default privileges of the owner';
	END IF;
END
$$;

-- Identifiers of MITRE ATT&CK techniques and sub-techniques, such as T1003 and
-- T1003.001. The application checks them against the bundled list of the
-- pinned ATT&CK version; the database checks only their form, so that a newer
-- version needs no migration.
CREATE FUNCTION public.attack_technique_ids_valid(ids text[]) RETURNS boolean
	LANGUAGE sql IMMUTABLE STRICT
	SET search_path = ''
	RETURN coalesce(array_ndims(ids), 1) = 1
		AND NOT EXISTS (
			SELECT FROM unnest(ids) AS t (id)
			WHERE t.id IS NULL OR t.id !~ '^T[0-9]{4}(\.[0-9]{3})?$'
		)
		AND cardinality(ids) = (SELECT count(DISTINCT t.id) FROM unnest(ids) AS t (id));

-- A honeytoken raises an event when its trigger value is requested or resolved.
-- The value is part of the URL or name that is placed in the monitored
-- environment, so it is not
-- a secret towards the readers of the console, who see it again whenever they
-- need it. Towards everyone else it is: whoever knows it can trigger the
-- honeytoken, and whoever reads this table knows every decoy.
CREATE TABLE public.honeytokens (
	id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	-- A honeytoken keeps its type: a placed URL cannot turn into an image.
	type          text NOT NULL,
	name          text NOT NULL,
	-- Where and why the honeytoken was placed, for the team that cleans up or
	-- triages an incident.
	notes         text NOT NULL DEFAULT '',
	enabled       boolean NOT NULL DEFAULT true,
	-- The page that a click on a URL leads to, so that the click raises no
	-- suspicion. Only URLs are clicked.
	redirect_url  text,
	-- The ATT&CK techniques that a trigger of the honeytoken suggests.
	techniques    text[] NOT NULL DEFAULT '{}',
	-- 128 bits from crypto/rand in lowercase base32 without padding, which is a
	-- valid DNS label. A new value means a new honeytoken, because the old one
	-- stays placed, so the value cannot be changed.
	trigger_value text NOT NULL,
	created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
	-- Set by the trigger below on insert, as for accounts.
	updated_at    timestamptz NOT NULL,

	CONSTRAINT honeytokens_type_check CHECK (type IN ('web_url', 'web_image', 'dns')),
	CONSTRAINT honeytokens_name_check CHECK (
		char_length(name) BETWEEN 1 AND 100
		AND name = btrim(name)
		AND name !~ '[\x01-\x1f\x7f]'
	),
	-- Notes may span several lines.
	CONSTRAINT honeytokens_notes_check CHECK (
		char_length(notes) <= 2000
		AND notes !~ '[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]'
	),
	-- The application validates the URL in full; the schema keeps other types
	-- free of a redirect and the URL free of spaces, line breaks and other
	-- schemes.
	CONSTRAINT honeytokens_redirect_url_check CHECK (
		(redirect_url IS NULL OR type = 'web_url')
		AND octet_length(redirect_url) <= 2048
		AND redirect_url ~ '^https?://[\x21-\x7e]+$'
	),
	CONSTRAINT honeytokens_techniques_check CHECK (
		cardinality(techniques) <= 20 AND public.attack_technique_ids_valid(techniques)
	),
	CONSTRAINT honeytokens_trigger_value_key UNIQUE (trigger_value),
	CONSTRAINT honeytokens_trigger_value_check CHECK (trigger_value ~ '^[a-z2-7]{26}$'),
	CONSTRAINT honeytokens_updated_at_check CHECK (updated_at >= created_at)
);

-- The console lists honeytokens from the newest to the oldest, a page at a
-- time, continuing after the last honeytoken of the previous page.
CREATE INDEX honeytokens_created_at_id_idx ON public.honeytokens (created_at DESC, id DESC);

CREATE TRIGGER honeytokens_set_updated_at
	BEFORE INSERT ON public.honeytokens
	FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- Default privileges set by an operator could grant more than this migration
-- intends, so everything is revoked before the grants.
REVOKE ALL ON public.honeytokens FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.attack_technique_ids_valid(text[]) FROM PUBLIC, nyktus_console;

-- The console evaluates the check of the techniques when it writes. It creates,
-- lists, changes and deletes honeytokens; it cannot change the type or the
-- trigger value of one, and identifiers and creation times come from the
-- database.
GRANT EXECUTE ON FUNCTION public.attack_technique_ids_valid(text[]) TO nyktus_console;
GRANT SELECT, DELETE ON public.honeytokens TO nyktus_console;
GRANT INSERT (type, name, notes, enabled, redirect_url, techniques, trigger_value) ON public.honeytokens TO nyktus_console;
GRANT UPDATE (name, notes, enabled, redirect_url, techniques, updated_at) ON public.honeytokens TO nyktus_console;

-- GRANT and REVOKE only warn when the executing role lacks the privilege, so the
-- result is verified instead of assumed, in both directions.
DO $$
BEGIN
	IF NOT has_table_privilege('nyktus_console', 'public.honeytokens', 'SELECT')
		OR NOT has_table_privilege('nyktus_console', 'public.honeytokens', 'DELETE')
		OR NOT has_function_privilege('nyktus_console', 'public.attack_technique_ids_valid(text[])', 'EXECUTE')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['type', 'name', 'notes', 'enabled', 'redirect_url', 'techniques',
				'trigger_value']) AS c (name)
			WHERE NOT has_column_privilege('nyktus_console', 'public.honeytokens', c.name, 'INSERT')
		)
		OR EXISTS (
			SELECT FROM unnest(ARRAY['name', 'notes', 'enabled', 'redirect_url', 'techniques', 'updated_at']) AS c (name)
			WHERE NOT has_column_privilege('nyktus_console', 'public.honeytokens', c.name, 'UPDATE')
		) THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.honeytokens; run migrations as the owner of the schema';
	END IF;

	IF has_table_privilege('nyktus_console', 'public.honeytokens', 'INSERT, UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.honeytokens', 'REFERENCES')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['id', 'created_at', 'updated_at']) AS c (name)
			WHERE has_column_privilege('nyktus_console', 'public.honeytokens', c.name, 'INSERT')
		)
		OR EXISTS (
			SELECT FROM unnest(ARRAY['id', 'type', 'trigger_value', 'created_at']) AS c (name)
			WHERE has_column_privilege('nyktus_console', 'public.honeytokens', c.name, 'UPDATE')
		) THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on public.honeytokens than granted; check the default privileges of the owner';
	END IF;
END
$$;

-- An event is a recorded request of a honeytoken, over HTTP or DNS. It is
-- evidence and outlives the honeytoken: it names it by type and identifier
-- without a foreign key, as the audit log names resources, and keeps a copy of
-- the type and the techniques that the honeytoken had when it was requested.
-- Name and notes are not copied, so that events do not become a second copy of
-- the inventory, and neither is the trigger value.
CREATE TABLE public.events (
	id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	resource_type   text NOT NULL,
	resource_id     uuid NOT NULL,
	honeytoken_type text,
	techniques      text[] NOT NULL DEFAULT '{}',
	-- When the request arrived. The trigger records at once; the DNS role
	-- answers first and passes how long the query waited, which the recording
	-- function keeps within the window below. Both times are set by
	-- the recording functions from one reading of the clock, because two
	-- defaults would read it twice in an order that nothing guarantees.
	occurred_at     timestamptz NOT NULL,
	-- When the event was written. The limit of events per honeytoken counts
	-- this time, which the DNS role cannot choose, so that a compromised host
	-- cannot evade the limit with earlier times.
	recorded_at     timestamptz NOT NULL,
	-- How the request arrived: 'http' at the trigger, 'dns' at the DNS role.
	-- The columns of the other channel stay empty.
	channel         text NOT NULL,
	-- The address of the client as the trigger determined it, or NULL if it is
	-- unknown. For a DNS query, it is the address of the resolver that asked,
	-- not of whoever looked up the name: resolvers ask on behalf of their
	-- clients.
	client_ip       inet,
	method          text,
	-- Headers of the request. Whoever sends a request chooses them, so they are
	-- untrusted: they describe what the client claimed, not what it is. The
	-- trigger shortens them and replaces control characters.
	user_agent      text NOT NULL DEFAULT '',
	referer         text NOT NULL DEFAULT '',
	accept_language text NOT NULL DEFAULT '',
	-- The zone under which the name was queried, and the labels in front of
	-- the trigger value, such as 'vpn' for 'vpn.<value>.<zone>'. Both are
	-- chosen by whoever sends the query and are untrusted. The DNS role
	-- replaces every character of a label other than a letter, a digit, '-' or
	-- '_' with '?'.
	dns_zone        text,
	dns_prefix      text,
	-- The type of the query, such as 'A' or 'TYPE65280', and whether it came
	-- over UDP or TCP.
	dns_qtype       text,
	dns_transport   text,

	CONSTRAINT events_resource_type_check CHECK (resource_type IN ('honeytoken')),
	CONSTRAINT events_honeytoken_type_check CHECK (
		(resource_type = 'honeytoken') = (honeytoken_type IS NOT NULL)
		AND honeytoken_type IN ('web_url', 'web_image', 'dns')
	),
	CONSTRAINT events_techniques_check CHECK (
		cardinality(techniques) <= 20 AND public.attack_technique_ids_valid(techniques)
	),
	CONSTRAINT events_channel_check CHECK (channel IN ('http', 'dns')),
	-- A query waits at most five minutes to be recorded.
	CONSTRAINT events_occurred_at_check CHECK (
		occurred_at <= recorded_at AND occurred_at >= recorded_at - interval '5 minutes'
	),
	-- The columns of a channel are set exactly for its events.
	CONSTRAINT events_http_check CHECK (
		(channel = 'http') = (method IS NOT NULL)
		AND (channel = 'http' OR (user_agent = '' AND referer = '' AND accept_language = ''))
	),
	CONSTRAINT events_dns_check CHECK (
		(channel = 'dns') = (dns_zone IS NOT NULL)
		AND (channel = 'dns') = (dns_prefix IS NOT NULL)
		AND (channel = 'dns') = (dns_qtype IS NOT NULL)
		AND (channel = 'dns') = (dns_transport IS NOT NULL)
	),
	-- Only requests that read a honeytoken are recorded.
	CONSTRAINT events_method_check CHECK (method IN ('GET', 'HEAD')),
	CONSTRAINT events_user_agent_check CHECK (
		octet_length(user_agent) <= 512 AND user_agent !~ '[\x01-\x1f\x7f]'
	),
	CONSTRAINT events_referer_check CHECK (
		octet_length(referer) <= 1024 AND referer !~ '[\x01-\x1f\x7f]'
	),
	CONSTRAINT events_accept_language_check CHECK (
		octet_length(accept_language) <= 128 AND accept_language !~ '[\x01-\x1f\x7f]'
	),
	CONSTRAINT events_dns_zone_check CHECK (
		octet_length(dns_zone) <= 200 AND dns_zone ~ '^[a-z0-9-]+(\.[a-z0-9-]+)+$'
	),
	CONSTRAINT events_dns_prefix_check CHECK (
		octet_length(dns_prefix) <= 200 AND dns_prefix ~ '^([a-z0-9_?-]+(\.[a-z0-9_?-]+)*)?$'
	),
	CONSTRAINT events_dns_qtype_check CHECK (dns_qtype ~ '^[A-Z0-9-]{1,16}$'),
	CONSTRAINT events_dns_transport_check CHECK (dns_transport IN ('udp', 'tcp'))
);

-- The limit of events per honeytoken counts its events written in the last
-- minute.
CREATE INDEX events_resource_id_recorded_at_idx ON public.events (resource_id, recorded_at);

-- The outbox: every event has a job that processes it, written in the same
-- transaction, so that no event goes unprocessed. The worker deletes the job in
-- the transaction that assigns the event to an incident. A job that fails stays
-- and is tried again after not_before, which moves further out with every
-- attempt, so that it does not hold up the jobs behind it.
CREATE TABLE public.event_jobs (
	event_id   uuid PRIMARY KEY REFERENCES public.events (id) ON DELETE CASCADE,
	created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
	attempts   integer NOT NULL DEFAULT 0,
	not_before timestamptz NOT NULL DEFAULT clock_timestamp(),

	CONSTRAINT event_jobs_attempts_check CHECK (attempts >= 0)
)
-- A queue: busy and short-lived, like sessions.
WITH (autovacuum_vacuum_scale_factor = 0.02, autovacuum_analyze_scale_factor = 0.05);

-- The worker takes the due job that has waited longest. The window starts at
-- statement_timestamp(), so that the index can be used.
CREATE INDEX event_jobs_not_before_idx ON public.event_jobs (not_before);

-- At most 10 events per honeytoken and minute are recorded, over HTTP and DNS
-- together, so that a flood of requests for one known value cannot fill the
-- database; the outcome "limited" lets the trigger and the DNS role count the
-- rest. Concurrent requests can exceed the limit slightly, which is accepted.
-- The window starts at statement_timestamp(), so that the index can be used.
-- Only the recording functions below call this function, with the rights of
-- the owner.
CREATE FUNCTION public.honeytoken_event_limit_reached(honeytoken_id uuid) RETURNS boolean
	LANGUAGE plpgsql
	STABLE
	SET search_path = ''
AS $$
BEGIN
	RETURN (
		SELECT count(*) FROM (
			SELECT FROM public.events AS e
			WHERE e.resource_id = honeytoken_id
				AND e.resource_type = 'honeytoken'
				AND e.recorded_at >= statement_timestamp() - interval '1 minute'
			LIMIT 10
		) AS recent
	) >= 10;
END
$$;

-- The trigger answers requests from the internet and must never be able to read
-- the inventory. It records a request through this function, which resolves one
-- trigger value, writes the event and its job in one transaction if the
-- honeytoken is enabled, and returns only what the response and the log need.
-- Whoever controls the trigger can test a value they already know, but cannot
-- list honeytokens or write an event without a job.
--
-- A disabled honeytoken still returns its redirect target, so that disabling
-- it does not change what a client sees.
CREATE FUNCTION public.record_honeytoken_request(
	requested_value text,
	request_method text,
	request_client_ip inet,
	request_user_agent text,
	request_referer text,
	request_accept_language text,
	OUT outcome text,
	OUT honeytoken_id uuid,
	OUT redirect_url text
)
	LANGUAGE plpgsql
	SECURITY DEFINER
	SET search_path = ''
AS $$
DECLARE
	h record;
	new_event_id uuid;
	now_at timestamptz := clock_timestamp();
BEGIN
	SELECT t.id, t.type, t.enabled, t.techniques, t.redirect_url INTO h
	FROM public.honeytokens AS t
	WHERE t.trigger_value = requested_value;
	IF NOT FOUND THEN
		outcome := 'unknown';
		RETURN;
	END IF;

	honeytoken_id := h.id;
	redirect_url := h.redirect_url;
	IF NOT h.enabled THEN
		outcome := 'disabled';
		RETURN;
	END IF;
	IF public.honeytoken_event_limit_reached(h.id) THEN
		outcome := 'limited';
		RETURN;
	END IF;

	INSERT INTO public.events (resource_type, resource_id, honeytoken_type, techniques, occurred_at, recorded_at,
		channel, client_ip, method, user_agent, referer, accept_language)
	VALUES ('honeytoken', h.id, h.type, h.techniques, now_at, now_at,
		'http', request_client_ip, request_method, request_user_agent, request_referer, request_accept_language)
	RETURNING id INTO new_event_id;
	INSERT INTO public.event_jobs (event_id) VALUES (new_event_id);
	outcome := 'recorded';
END
$$;

-- The DNS role answers queries from the internet and, like the trigger, must
-- never be able to read the inventory. It records a query through this
-- function, which resolves one trigger value and writes the event and its job
-- in one transaction if the honeytoken is enabled. It returns nothing that the
-- answer could depend on: the DNS role answers before it records.
--
-- The DNS role passes how long the query waited, measured with its own clock,
-- so that the time of the event does not depend on the clocks of two hosts
-- agreeing. The delay is kept between zero and five minutes, so that a
-- compromised DNS role cannot write events into the future or the distant
-- past.
CREATE FUNCTION public.record_dns_query(
	requested_value text,
	query_zone text,
	query_prefix text,
	query_type text,
	query_transport text,
	query_resolver_ip inet,
	query_delay interval,
	OUT outcome text,
	OUT honeytoken_id uuid
)
	LANGUAGE plpgsql
	SECURITY DEFINER
	SET search_path = ''
AS $$
DECLARE
	h record;
	new_event_id uuid;
	now_at timestamptz := clock_timestamp();
BEGIN
	SELECT t.id, t.type, t.enabled, t.techniques INTO h
	FROM public.honeytokens AS t
	WHERE t.trigger_value = requested_value;
	IF NOT FOUND THEN
		outcome := 'unknown';
		RETURN;
	END IF;

	honeytoken_id := h.id;
	IF NOT h.enabled THEN
		outcome := 'disabled';
		RETURN;
	END IF;
	IF public.honeytoken_event_limit_reached(h.id) THEN
		outcome := 'limited';
		RETURN;
	END IF;

	INSERT INTO public.events (resource_type, resource_id, honeytoken_type, techniques, occurred_at, recorded_at,
		channel, client_ip, dns_zone, dns_prefix, dns_qtype, dns_transport)
	VALUES ('honeytoken', h.id, h.type, h.techniques,
		now_at - least(greatest(coalesce(query_delay, interval '0'), interval '0'), interval '5 minutes'), now_at,
		'dns', query_resolver_ip, query_zone, query_prefix, query_type, query_transport)
	RETURNING id INTO new_event_id;
	INSERT INTO public.event_jobs (event_id) VALUES (new_event_id);
	outcome := 'recorded';
END
$$;

-- An incident correlates the events of one resource: the worker assigns every
-- event to the open incident of its resource, or opens one. Triage happens on
-- incidents. Like events, an incident names its resource without a foreign key,
-- so that it outlives the resource.
--
-- The worker maintains the severity, the techniques, the count and the times of
-- the events; the analyst's judgment is kept beside them in the override
-- columns, so that both stay visible.
CREATE TABLE public.incidents (
	id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	resource_type       text NOT NULL,
	resource_id         uuid NOT NULL,
	-- An acknowledged incident is still open: it collects the events of its
	-- resource until it is closed.
	status              text NOT NULL DEFAULT 'open',
	-- The highest severity of the events.
	severity            text NOT NULL,
	severity_override   text,
	-- Every technique of the events. The limit lies above the number of
	-- techniques and sub-techniques in ATT&CK, so a union of identifiers that
	-- the console validated can never reach it.
	techniques          text[] NOT NULL DEFAULT '{}',
	techniques_override text[],
	notes               text NOT NULL DEFAULT '',
	event_count         integer NOT NULL DEFAULT 1,
	first_event_at      timestamptz NOT NULL,
	last_event_at       timestamptz NOT NULL,
	opened_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
	acknowledged_at     timestamptz,
	closed_at           timestamptz,

	CONSTRAINT incidents_resource_type_check CHECK (resource_type IN ('honeytoken')),
	CONSTRAINT incidents_status_check CHECK (status IN ('open', 'acknowledged', 'closed')),
	-- An incident can be closed without having been acknowledged.
	CONSTRAINT incidents_status_times_check CHECK (
		(status = 'closed') = (closed_at IS NOT NULL)
		AND (status <> 'open' OR acknowledged_at IS NULL)
		AND (status <> 'acknowledged' OR acknowledged_at IS NOT NULL)
		AND acknowledged_at >= opened_at
		AND closed_at >= opened_at
	),
	-- 'info' is only an analyst's judgment, never what an event suggests.
	CONSTRAINT incidents_severity_check CHECK (severity IN ('low', 'medium', 'high', 'critical')),
	CONSTRAINT incidents_severity_override_check CHECK (
		severity_override IN ('info', 'low', 'medium', 'high', 'critical')
	),
	CONSTRAINT incidents_techniques_check CHECK (
		cardinality(techniques) <= 1000 AND public.attack_technique_ids_valid(techniques)
	),
	CONSTRAINT incidents_techniques_override_check CHECK (
		cardinality(techniques_override) <= 20 AND public.attack_technique_ids_valid(techniques_override)
	),
	-- Notes may span several lines.
	CONSTRAINT incidents_notes_check CHECK (
		char_length(notes) <= 10000
		AND notes !~ '[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]'
	),
	CONSTRAINT incidents_event_count_check CHECK (event_count >= 1),
	CONSTRAINT incidents_event_times_check CHECK (first_event_at <= last_event_at)
);

-- At most one incident per resource is open. The worker relies on this index to
-- open an incident only once when two events of a resource arrive together.
CREATE UNIQUE INDEX incidents_open_resource_key ON public.incidents (resource_type, resource_id)
	WHERE status <> 'closed';

-- The console lists incidents from the newest to the oldest, also those of
-- one resource, a page at a time.
CREATE INDEX incidents_opened_at_id_idx ON public.incidents (opened_at DESC, id DESC);
CREATE INDEX incidents_resource_id_opened_at_id_idx ON public.incidents (resource_id, opened_at DESC, id DESC);

-- The status of an incident only moves forward, from open over acknowledged to
-- closed, so a closed incident is never opened again: new events of its
-- resource open a new incident and raise a new alert. The worker and the
-- console both check this; the trigger is the last line of defense.
--
-- The trigger also records when the status changed, so that no application
-- role chooses these times: the database sets them when the status moves, and
-- keeps them otherwise.
CREATE FUNCTION public.incidents_change_status() RETURNS trigger
	LANGUAGE plpgsql
	SET search_path = ''
AS $$
BEGIN
	IF array_position(ARRAY['open', 'acknowledged', 'closed'], NEW.status)
		< array_position(ARRAY['open', 'acknowledged', 'closed'], OLD.status) THEN
		RAISE EXCEPTION 'the status of incident % cannot move from % back to %', OLD.id, OLD.status, NEW.status
			USING ERRCODE = 'check_violation', CONSTRAINT = 'incidents_status_forward';
	END IF;
	NEW.acknowledged_at := OLD.acknowledged_at;
	NEW.closed_at := OLD.closed_at;
	IF NEW.status <> OLD.status THEN
		IF NEW.status = 'acknowledged' THEN
			NEW.acknowledged_at := clock_timestamp();
		ELSIF NEW.status = 'closed' THEN
			NEW.closed_at := clock_timestamp();
		END IF;
	END IF;
	RETURN NEW;
END
$$;

-- The trigger fires only for updates that name the status or its times, so
-- that the updates of the worker, which name neither, do not run it.
CREATE TRIGGER incidents_change_status
	BEFORE UPDATE OF status, acknowledged_at, closed_at ON public.incidents
	FOR EACH ROW EXECUTE FUNCTION public.incidents_change_status();

-- Every event belongs to the incident that the worker assigned it to, and to no
-- other. The column is empty until the worker processed the event.
ALTER TABLE public.events ADD COLUMN incident_id uuid CONSTRAINT events_incident_id_fkey REFERENCES public.incidents (id);

-- The console lists events from the most recently recorded to the oldest, also
-- those of one incident, a page at a time. The order follows the time of
-- writing, not of arrival: a DNS query is recorded up to five minutes after it
-- arrived, and ordered by arrival it could land behind pages that a client has
-- already read. Events are written on the path of the trigger, so they get no
-- further index; the events of a honeytoken are those of its incidents.
CREATE INDEX events_recorded_at_id_idx ON public.events (recorded_at DESC, id DESC);
CREATE INDEX events_incident_id_recorded_at_id_idx ON public.events (incident_id, recorded_at DESC, id DESC);

-- The single alert of an incident, written in the transaction that opens the
-- incident. It keeps the severity and the techniques that the incident had
-- when it opened, because those are what it reports.
CREATE TABLE public.alerts (
	incident_id uuid PRIMARY KEY REFERENCES public.incidents (id),
	severity    text NOT NULL,
	techniques  text[] NOT NULL DEFAULT '{}',
	created_at  timestamptz NOT NULL DEFAULT clock_timestamp(),

	CONSTRAINT alerts_severity_check CHECK (severity IN ('low', 'medium', 'high', 'critical')),
	CONSTRAINT alerts_techniques_check CHECK (
		cardinality(techniques) <= 1000 AND public.attack_technique_ids_valid(techniques)
	)
);

-- Nobody writes events except through the functions above, and incidents and
-- alerts only the worker, apart from the triage of the console.
REVOKE ALL ON public.events, public.event_jobs, public.incidents, public.alerts FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.incidents_change_status() FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.honeytoken_event_limit_reached(uuid) FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.record_honeytoken_request(text, text, inet, text, text, text)
	FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.record_dns_query(text, text, text, text, text, inet, interval) FROM PUBLIC, nyktus_console;

-- The console reads events and incidents and triages incidents: it moves their
-- status, writes notes and overrides the severity and the techniques. It cannot
-- write or change an event, open an incident, change what the worker
-- correlated, or choose when the status changed. It reads neither the jobs nor
-- the alerts.
GRANT SELECT ON public.events, public.incidents TO nyktus_console;
GRANT UPDATE (status, notes, severity_override, techniques_override) ON public.incidents TO nyktus_console;

-- GRANT and REVOKE only warn when the executing role lacks the privilege, so the
-- result is verified instead of assumed, in both directions: every privilege on
-- these tables, their columns and the functions that write them is compared
-- with the grants above. An event that the console could write would have no
-- job, or a job no event, and an incident it could write no alert.
DO $$
DECLARE
	missing text;
	extra text;
BEGIN
	WITH granted (relname, attname, privilege) AS (
		-- A NULL column stands for the whole table.
		VALUES
			('events', NULL, 'SELECT'), ('incidents', NULL, 'SELECT'),
			('incidents', 'status', 'UPDATE'), ('incidents', 'notes', 'UPDATE'),
			('incidents', 'severity_override', 'UPDATE'), ('incidents', 'techniques_override', 'UPDATE')
	),
	tables AS (
		SELECT c.oid, c.relname FROM pg_catalog.pg_class AS c
		WHERE c.oid IN ('public.events'::regclass, 'public.event_jobs'::regclass, 'public.incidents'::regclass,
			'public.alerts'::regclass)
	),
	privileges (object, privilege, held, wanted) AS (
		SELECT t.relname::text, p.privilege,
			has_table_privilege('nyktus_console', t.oid, p.privilege),
			EXISTS (
				SELECT FROM granted AS g
				WHERE g.relname = t.relname AND g.attname IS NULL AND g.privilege = p.privilege
			)
		FROM tables AS t
		CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p (privilege)
		UNION ALL
		SELECT t.relname || '.' || a.attname, p.privilege,
			has_column_privilege('nyktus_console', t.oid, a.attnum, p.privilege),
			EXISTS (
				SELECT FROM granted AS g
				WHERE g.relname = t.relname AND coalesce(g.attname, a.attname) = a.attname AND g.privilege = p.privilege
			)
		FROM tables AS t
		JOIN pg_catalog.pg_attribute AS a ON a.attrelid = t.oid AND a.attnum > 0 AND NOT a.attisdropped
		CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS p (privilege)
		UNION ALL
		SELECT f.signature, 'EXECUTE', has_function_privilege('nyktus_console', f.signature, 'EXECUTE'), false
		FROM unnest(ARRAY[
			'public.incidents_change_status()',
			'public.honeytoken_event_limit_reached(uuid)',
			'public.record_honeytoken_request(text, text, inet, text, text, text)',
			'public.record_dns_query(text, text, text, text, text, inet, interval)'
		]) AS f (signature)
	)
	SELECT string_agg(object || ': ' || privilege, ', ' ORDER BY object, privilege) FILTER (WHERE wanted AND NOT held),
		string_agg(object || ': ' || privilege, ', ' ORDER BY object, privilege) FILTER (WHERE held AND NOT wanted)
	INTO missing, extra
	FROM privileges;

	IF missing IS NOT NULL THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on events or incidents (%); run migrations as the owner of the schema', missing;
	END IF;
	IF extra IS NOT NULL THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on events or incidents than granted (%); check the default privileges of the owner', extra;
	END IF;
END
$$;

-- An alert channel is a target that every alert is delivered to. Its URL and
-- the value of its header are secrets: a chat webhook accepts messages from
-- whoever knows its URL, and a header authenticates at the receiver. They are
-- kept apart in alert_channel_secrets, which the console can write but not
-- read; the channel shows only the scheme, host and port of its URL.
CREATE TABLE public.alert_channels (
	id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	name        text NOT NULL,
	-- The type chooses the format of the request body. It cannot change,
	-- because the URL of one type is no URL of another.
	type        text NOT NULL,
	enabled     boolean NOT NULL DEFAULT true,
	-- The scheme, host and port of the URL, shown instead of it.
	target      text NOT NULL,
	-- The name of a header that a webhook sends, whose value is a secret.
	header_name text,
	created_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
	-- Set by the trigger below on insert, as for accounts.
	updated_at  timestamptz NOT NULL,

	CONSTRAINT alert_channels_name_key UNIQUE (name),
	CONSTRAINT alert_channels_name_check CHECK (
		char_length(name) BETWEEN 1 AND 64
		AND name = btrim(name)
		AND name !~ '[\x01-\x1f\x7f]'
	),
	CONSTRAINT alert_channels_type_check CHECK (type IN ('webhook', 'slack', 'teams')),
	CONSTRAINT alert_channels_target_check CHECK (
		octet_length(target) <= 300 AND target ~ '^https?://[\x21-\x2e\x30-\x3e\x41-\x7e]+$'
	),
	-- A token of RFC 9110, other than the headers that the client sets
	-- itself or that change how the request is transferred.
	CONSTRAINT alert_channels_header_name_check CHECK (
		header_name IS NULL OR (
			type = 'webhook'
			AND header_name ~ '^[!#$%&''*+.^_`|~0-9A-Za-z-]{1,64}$'
			AND lower(header_name) NOT IN ('host', 'content-length', 'content-type', 'content-encoding',
				'transfer-encoding', 'connection', 'keep-alive', 'te', 'trailer', 'upgrade', 'expect')
			AND lower(header_name) NOT LIKE 'proxy-%'
		)
	),
	CONSTRAINT alert_channels_updated_at_check CHECK (updated_at >= created_at)
);

CREATE TRIGGER alert_channels_set_updated_at
	BEFORE INSERT ON public.alert_channels
	FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- The secrets of a channel, encrypted with AES-256-GCM: a key identifier, a
-- nonce and the sealed value, bound to the channel and the purpose.
CREATE TABLE public.alert_channel_secrets (
	channel_id   uuid PRIMARY KEY REFERENCES public.alert_channels (id) ON DELETE CASCADE,
	url          bytea NOT NULL,
	header_value bytea,

	CONSTRAINT alert_channel_secrets_url_check CHECK (octet_length(url) BETWEEN 30 AND 4096),
	CONSTRAINT alert_channel_secrets_header_value_check CHECK (octet_length(header_value) BETWEEN 30 AND 2048)
);

REVOKE ALL ON public.alert_channels, public.alert_channel_secrets FROM PUBLIC, nyktus_console;

-- The console manages the channels and writes their secrets, but never reads
-- them: it needs the identifier of a secret only to replace it. Identifiers
-- and creation times come from the database, and the type of a channel never
-- changes. The secrets of a deleted channel go with it.
GRANT SELECT, DELETE ON public.alert_channels TO nyktus_console;
GRANT INSERT (name, type, enabled, target, header_name) ON public.alert_channels TO nyktus_console;
GRANT UPDATE (name, enabled, target, header_name, updated_at) ON public.alert_channels TO nyktus_console;
GRANT SELECT (channel_id) ON public.alert_channel_secrets TO nyktus_console;
GRANT INSERT (channel_id, url, header_value) ON public.alert_channel_secrets TO nyktus_console;
GRANT UPDATE (url, header_value) ON public.alert_channel_secrets TO nyktus_console;

-- GRANT and REVOKE only warn when the executing role lacks the privilege, so the
-- result is verified instead of assumed, in both directions: every privilege on
-- these tables and their columns is compared with the grants above. A console
-- that could read the secrets would hand out every channel to whoever
-- compromises it.
DO $$
DECLARE
	missing text;
	extra text;
BEGIN
	WITH granted (relname, attname, privilege) AS (
		-- A NULL column stands for the whole table.
		VALUES
			('alert_channels', NULL, 'SELECT'), ('alert_channels', NULL, 'DELETE'),
			('alert_channels', 'name', 'INSERT'), ('alert_channels', 'type', 'INSERT'),
			('alert_channels', 'enabled', 'INSERT'), ('alert_channels', 'target', 'INSERT'),
			('alert_channels', 'header_name', 'INSERT'),
			('alert_channels', 'name', 'UPDATE'), ('alert_channels', 'enabled', 'UPDATE'),
			('alert_channels', 'target', 'UPDATE'), ('alert_channels', 'header_name', 'UPDATE'),
			('alert_channels', 'updated_at', 'UPDATE'),
			('alert_channel_secrets', 'channel_id', 'SELECT'),
			('alert_channel_secrets', 'channel_id', 'INSERT'), ('alert_channel_secrets', 'url', 'INSERT'),
			('alert_channel_secrets', 'header_value', 'INSERT'),
			('alert_channel_secrets', 'url', 'UPDATE'), ('alert_channel_secrets', 'header_value', 'UPDATE')
	),
	tables AS (
		SELECT c.oid, c.relname FROM pg_catalog.pg_class AS c
		WHERE c.oid IN ('public.alert_channels'::regclass, 'public.alert_channel_secrets'::regclass)
	),
	privileges (object, privilege, held, wanted) AS (
		SELECT t.relname::text, p.privilege,
			has_table_privilege('nyktus_console', t.oid, p.privilege),
			EXISTS (
				SELECT FROM granted AS g
				WHERE g.relname = t.relname AND g.attname IS NULL AND g.privilege = p.privilege
			)
		FROM tables AS t
		CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p (privilege)
		UNION ALL
		SELECT t.relname || '.' || a.attname, p.privilege,
			has_column_privilege('nyktus_console', t.oid, a.attnum, p.privilege),
			EXISTS (
				SELECT FROM granted AS g
				WHERE g.relname = t.relname AND coalesce(g.attname, a.attname) = a.attname AND g.privilege = p.privilege
			)
		FROM tables AS t
		JOIN pg_catalog.pg_attribute AS a ON a.attrelid = t.oid AND a.attnum > 0 AND NOT a.attisdropped
		CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS p (privilege)
	)
	SELECT string_agg(object || ': ' || privilege, ', ' ORDER BY object, privilege) FILTER (WHERE wanted AND NOT held),
		string_agg(object || ': ' || privilege, ', ' ORDER BY object, privilege) FILTER (WHERE held AND NOT wanted)
	INTO missing, extra
	FROM privileges;

	IF missing IS NOT NULL THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on the alert channels (%); run migrations as the owner of the schema', missing;
	END IF;
	IF extra IS NOT NULL THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on the alert channels than granted (%); check the default privileges of the owner', extra;
	END IF;
END
$$;

-- A delivery is the job, the state of retries and the receipt of one alert to
-- one channel, or of a test of a channel without an alert. The worker creates
-- the deliveries of an alert in the transaction that opens its incident, one
-- for every enabled channel, so that a channel added later does not receive
-- old alerts. A delivery names its channel without a foreign key and keeps a
-- copy of its type and name, so that the receipt outlives the channel, as the
-- audit log names resources.
CREATE TABLE public.alert_deliveries (
	id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	-- Empty for a test of a channel.
	alert_id         uuid CONSTRAINT alert_deliveries_alert_id_fkey REFERENCES public.alerts (incident_id),
	channel_id       uuid NOT NULL,
	channel_type     text NOT NULL,
	channel_name     text NOT NULL,
	-- pending until it is delivered, dead after the last failed attempt or a
	-- failure that no retry can mend, canceled if its channel was disabled or
	-- deleted first.
	status           text NOT NULL DEFAULT 'pending',
	attempts         integer NOT NULL DEFAULT 0,
	-- When the next attempt is due.
	not_before       timestamptz NOT NULL DEFAULT clock_timestamp(),
	-- The last attempt: its time, the status code of the response, if there
	-- was one, the class of its failure and how long it took. The response
	-- itself is never stored.
	last_attempt_at  timestamptz,
	last_status_code integer,
	last_error       text,
	last_duration_ms integer,
	delivered_at     timestamptz,
	created_at       timestamptz NOT NULL DEFAULT clock_timestamp(),

	CONSTRAINT alert_deliveries_channel_type_check CHECK (channel_type IN ('webhook', 'slack', 'teams')),
	CONSTRAINT alert_deliveries_channel_name_check CHECK (char_length(channel_name) BETWEEN 1 AND 64),
	CONSTRAINT alert_deliveries_status_check CHECK (status IN ('pending', 'delivered', 'dead', 'canceled')),
	CONSTRAINT alert_deliveries_attempts_check CHECK (attempts BETWEEN 0 AND 100),
	CONSTRAINT alert_deliveries_delivered_check CHECK ((status = 'delivered') = (delivered_at IS NOT NULL)),
	CONSTRAINT alert_deliveries_last_attempt_check CHECK (
		(attempts = 0) = (last_attempt_at IS NULL)
		AND (last_attempt_at IS NOT NULL OR (last_status_code IS NULL AND last_error IS NULL AND last_duration_ms IS NULL))
	),
	CONSTRAINT alert_deliveries_last_status_code_check CHECK (last_status_code BETWEEN 100 AND 599),
	CONSTRAINT alert_deliveries_last_error_check CHECK (
		last_error IN ('http_status', 'redirect', 'timeout', 'network', 'tls', 'blocked', 'invalid_channel')
	),
	CONSTRAINT alert_deliveries_last_duration_check CHECK (last_duration_ms >= 0)
)
-- A queue as well: every attempt updates its delivery.
WITH (autovacuum_vacuum_scale_factor = 0.02, autovacuum_analyze_scale_factor = 0.05);

-- An alert reaches each channel once, also when two workers raise it.
CREATE UNIQUE INDEX alert_deliveries_alert_channel_key ON public.alert_deliveries (alert_id, channel_id)
	WHERE alert_id IS NOT NULL;
-- A channel has at most one test waiting, which bounds what a session can make
-- the worker send.
CREATE UNIQUE INDEX alert_deliveries_pending_test_key ON public.alert_deliveries (channel_id)
	WHERE alert_id IS NULL AND status = 'pending';
-- The worker takes the deliveries that are due, in order.
CREATE INDEX alert_deliveries_pending_not_before_idx ON public.alert_deliveries (not_before)
	WHERE status = 'pending';

-- An administrator delivers a dead delivery again, with a new count of
-- attempts. The console changes deliveries only through this function, so
-- that it can neither forge a receipt nor change where a delivery goes. It
-- returns whether the delivery was dead.
CREATE FUNCTION public.retry_alert_delivery(delivery uuid) RETURNS boolean
	LANGUAGE sql
	SECURITY DEFINER
	SET search_path = ''
AS $$
	WITH retried AS (
		UPDATE public.alert_deliveries
		SET status = 'pending', attempts = 0, not_before = clock_timestamp(), last_attempt_at = NULL,
			last_status_code = NULL, last_error = NULL, last_duration_ms = NULL
		WHERE id = delivery AND status = 'dead' AND alert_id IS NOT NULL
		RETURNING id
	)
	SELECT EXISTS (SELECT FROM retried)
$$;

REVOKE ALL ON public.alert_deliveries FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.retry_alert_delivery(uuid) FROM PUBLIC, nyktus_console;

-- The console reads deliveries, requests tests of channels, which have no
-- alert, and retries dead deliveries through the function above. It cannot
-- create the delivery of an alert or change one otherwise.
GRANT SELECT ON public.alert_deliveries TO nyktus_console;
GRANT INSERT (channel_id, channel_type, channel_name) ON public.alert_deliveries TO nyktus_console;
GRANT EXECUTE ON FUNCTION public.retry_alert_delivery(uuid) TO nyktus_console;

-- GRANT and REVOKE only warn when the executing role lacks the privilege, so the
-- result is verified instead of assumed, in both directions.
DO $$
DECLARE
	missing text;
	extra text;
BEGIN
	WITH granted (attname, privilege) AS (
		-- A NULL column stands for the whole table.
		VALUES
			(NULL, 'SELECT'),
			('channel_id', 'INSERT'), ('channel_type', 'INSERT'), ('channel_name', 'INSERT')
	),
	privileges (object, privilege, held, wanted) AS (
		SELECT 'alert_deliveries', p.privilege,
			has_table_privilege('nyktus_console', 'public.alert_deliveries', p.privilege),
			EXISTS (SELECT FROM granted AS g WHERE g.attname IS NULL AND g.privilege = p.privilege)
		FROM unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p (privilege)
		UNION ALL
		SELECT 'alert_deliveries.' || a.attname, p.privilege,
			has_column_privilege('nyktus_console', a.attrelid, a.attnum, p.privilege),
			EXISTS (
				SELECT FROM granted AS g
				WHERE coalesce(g.attname, a.attname) = a.attname AND g.privilege = p.privilege
			)
		FROM pg_catalog.pg_attribute AS a
		CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS p (privilege)
		WHERE a.attrelid = 'public.alert_deliveries'::regclass AND a.attnum > 0 AND NOT a.attisdropped
		UNION ALL
		SELECT 'retry_alert_delivery(uuid)', 'EXECUTE',
			has_function_privilege('nyktus_console', 'public.retry_alert_delivery(uuid)', 'EXECUTE'), true
	)
	SELECT string_agg(object || ': ' || privilege, ', ' ORDER BY object, privilege) FILTER (WHERE wanted AND NOT held),
		string_agg(object || ': ' || privilege, ', ' ORDER BY object, privilege) FILTER (WHERE held AND NOT wanted)
	INTO missing, extra
	FROM privileges;

	IF missing IS NOT NULL THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on the alert deliveries (%); run migrations as the owner of the schema', missing;
	END IF;
	IF extra IS NOT NULL THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on the alert deliveries than granted (%); check the default privileges of the owner', extra;
	END IF;
END
$$;

-- Periodic tasks of the worker, such as removing expired rows. Each task has a
-- row that says when it is due next. A worker takes a due task with
-- SELECT ... FOR UPDATE SKIP LOCKED and moves it to its next run before it
-- runs it, so that several workers share the tasks without coordination and a
-- task runs once per interval, not once per worker. The rows are fixed: the
-- migration creates them, and the worker only records when they ran.
CREATE TABLE public.periodic_tasks (
	name              text PRIMARY KEY,
	next_run_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
	last_started_at   timestamptz,
	last_succeeded_at timestamptz,
	last_failed_at    timestamptz,
	-- The rows that the last successful run removed or changed.
	last_rows         bigint,

	CONSTRAINT periodic_tasks_name_check CHECK (name IN ('delete_expired_sign_in_data')),
	CONSTRAINT periodic_tasks_last_rows_check CHECK (last_rows >= 0)
);

INSERT INTO public.periodic_tasks (name) VALUES ('delete_expired_sign_in_data');

-- Removes expired sign-in data: sessions, challenges of the second factor,
-- unconfirmed TOTP factors, activation and reset links, API keys, sign-ins
-- through the identity provider and setup tokens. The console removes some of
-- them on the way, but only for the account at hand; without this function,
-- data of accounts that never sign in again, and sign-ins that anyone can
-- start, would stay forever.
--
-- The worker reads no accounts, so it calls this function instead of holding
-- privileges on these tables. It removes only what has expired by the rules of
-- the schema, never anything the console would still accept: sessions by the
-- longest idle timeout (24 hours) and lifetime (30 days) that the console can
-- be configured with, and unconfirmed factors after the ten minutes in which
-- they can be confirmed. Shorter settings of the console leave expired
-- sessions a little longer, which nobody can use.
--
-- It removes at most batch rows of each table, skipping rows that another
-- transaction holds, and returns how many it removed, so that the worker calls
-- it again while rows remain and no call holds locks for long. The times are
-- compared with statement_timestamp(), which lets the indexes be used and lies
-- before clock_timestamp(), against which the console checks expiry.
CREATE FUNCTION public.delete_expired_sign_in_data(batch integer) RETURNS integer
	LANGUAGE plpgsql
	SECURITY DEFINER
	SET search_path = ''
	SET lock_timeout = '5s'
AS $$
DECLARE
	removed integer := 0;
	n integer;
	now_at timestamptz := statement_timestamp();
BEGIN
	IF batch IS NULL OR batch NOT BETWEEN 1 AND 10000 THEN
		RAISE EXCEPTION 'batch must be between 1 and 10000, not %', batch USING ERRCODE = 'invalid_parameter_value';
	END IF;

	DELETE FROM public.sessions WHERE id IN (
		SELECT s.id FROM public.sessions AS s
		WHERE s.last_seen_at <= now_at - interval '24 hours' OR s.created_at <= now_at - interval '30 days'
		LIMIT batch FOR UPDATE SKIP LOCKED
	);
	GET DIAGNOSTICS n = ROW_COUNT;
	removed := removed + n;

	DELETE FROM public.sign_in_challenges WHERE token_hash IN (
		SELECT c.token_hash FROM public.sign_in_challenges AS c
		WHERE c.expires_at <= now_at
		LIMIT batch FOR UPDATE SKIP LOCKED
	);
	GET DIAGNOSTICS n = ROW_COUNT;
	removed := removed + n;

	DELETE FROM public.totp_factors WHERE user_id IN (
		SELECT f.user_id FROM public.totp_factors AS f
		WHERE f.confirmed_at IS NULL AND f.created_at <= now_at - interval '10 minutes'
		LIMIT batch FOR UPDATE SKIP LOCKED
	);
	GET DIAGNOSTICS n = ROW_COUNT;
	removed := removed + n;

	DELETE FROM public.account_links WHERE user_id IN (
		SELECT l.user_id FROM public.account_links AS l
		WHERE l.expires_at <= now_at
		LIMIT batch FOR UPDATE SKIP LOCKED
	);
	GET DIAGNOSTICS n = ROW_COUNT;
	removed := removed + n;

	DELETE FROM public.api_keys WHERE id IN (
		SELECT k.id FROM public.api_keys AS k
		WHERE k.expires_at <= now_at
		LIMIT batch FOR UPDATE SKIP LOCKED
	);
	GET DIAGNOSTICS n = ROW_COUNT;
	removed := removed + n;

	DELETE FROM public.oidc_logins WHERE state_hash IN (
		SELECT o.state_hash FROM public.oidc_logins AS o
		WHERE o.expires_at <= now_at
		LIMIT batch FOR UPDATE SKIP LOCKED
	);
	GET DIAGNOSTICS n = ROW_COUNT;
	removed := removed + n;

	DELETE FROM public.setup_tokens WHERE token_hash IN (
		SELECT t.token_hash FROM public.setup_tokens AS t
		WHERE t.expires_at <= now_at
		LIMIT batch FOR UPDATE SKIP LOCKED
	);
	GET DIAGNOSTICS n = ROW_COUNT;
	RETURN removed + n;
END
$$;

REVOKE ALL ON public.periodic_tasks FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.delete_expired_sign_in_data(integer) FROM PUBLIC, nyktus_console;

-- The trigger and the DNS role reach nothing but their function, and the
-- worker nothing but its tables. Everything in the schema is revoked here, at
-- its end, including the table of the migration runner, so that default
-- privileges set by an operator cannot widen them beyond it.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM nyktus_trigger, nyktus_dns, nyktus_worker;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM nyktus_trigger, nyktus_dns, nyktus_worker;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM nyktus_trigger, nyktus_dns, nyktus_worker;
GRANT USAGE ON SCHEMA public TO nyktus_trigger, nyktus_dns, nyktus_worker;
GRANT EXECUTE ON FUNCTION public.record_honeytoken_request(text, text, inet, text, text, text) TO nyktus_trigger;
GRANT EXECUTE ON FUNCTION public.record_dns_query(text, text, text, text, text, inet, interval) TO nyktus_dns;

-- GRANT and REVOKE only warn when the executing role lacks the privilege, so the
-- result is verified instead of assumed, in both directions.
DO $$
DECLARE
	role_name text;
	function_name text;
BEGIN
	FOR role_name, function_name IN VALUES
		('nyktus_trigger', 'public.record_honeytoken_request(text, text, inet, text, text, text)'),
		('nyktus_dns', 'public.record_dns_query(text, text, text, text, text, inet, interval)')
	LOOP
		IF NOT has_schema_privilege(role_name, 'public', 'USAGE')
			OR NOT has_function_privilege(role_name, function_name, 'EXECUTE') THEN
			RAISE EXCEPTION '% lacks privileges on %; run migrations as the owner of the schema', role_name, function_name;
		END IF;

		IF has_schema_privilege(role_name, 'public', 'CREATE')
			OR EXISTS (
				SELECT FROM pg_catalog.pg_class AS c
				WHERE c.relnamespace = 'public'::regnamespace
					AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
					AND CASE c.relkind
						WHEN 'S' THEN has_sequence_privilege(role_name, c.oid, 'USAGE, SELECT, UPDATE')
						ELSE has_table_privilege(role_name, c.oid, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
							OR has_any_column_privilege(role_name, c.oid, 'SELECT, INSERT, UPDATE, REFERENCES')
					END
			)
			OR EXISTS (
				SELECT FROM pg_catalog.pg_proc AS p
				WHERE p.pronamespace = 'public'::regnamespace
					AND p.oid <> function_name::regprocedure
					AND has_function_privilege(role_name, p.oid, 'EXECUTE')
			) THEN
			RAISE EXCEPTION '% has more privileges than granted; check the default privileges of the owner', role_name;
		END IF;
	END LOOP;
END
$$;

-- The worker processes the jobs of events: it reads the event, opens or updates
-- the incident of its resource with its alert, assigns the event to it and
-- deletes the job. It evaluates the checks of the techniques when it writes. It
-- reads no honeytoken: the event holds what the incident needs. It cannot
-- choose the identifier, the status or the opening time of an incident, change
-- an event other than by assigning it, or change an alert once written.
GRANT EXECUTE ON FUNCTION public.attack_technique_ids_valid(text[]) TO nyktus_worker;
GRANT SELECT, DELETE ON public.event_jobs TO nyktus_worker;
GRANT UPDATE (attempts, not_before) ON public.event_jobs TO nyktus_worker;
GRANT SELECT ON public.events TO nyktus_worker;
GRANT UPDATE (incident_id) ON public.events TO nyktus_worker;
GRANT SELECT ON public.incidents TO nyktus_worker;
GRANT INSERT (resource_type, resource_id, severity, techniques, first_event_at, last_event_at)
	ON public.incidents TO nyktus_worker;
GRANT UPDATE (severity, techniques, event_count, first_event_at, last_event_at) ON public.incidents TO nyktus_worker;
GRANT INSERT (incident_id, severity, techniques) ON public.alerts TO nyktus_worker;

-- The worker delivers the alerts. It creates the deliveries of a new alert for
-- the enabled channels, reads the alert and its incident for the message, and
-- the channels with their secrets to send it. It records every attempt on its
-- delivery and encrypts a secret again with the current key. It cannot create
-- or change a channel, change where a delivery goes or delete one.
GRANT SELECT ON public.alerts, public.alert_channels, public.alert_channel_secrets TO nyktus_worker;
GRANT UPDATE (url, header_value) ON public.alert_channel_secrets TO nyktus_worker;
GRANT SELECT ON public.alert_deliveries TO nyktus_worker;
GRANT INSERT (alert_id, channel_id, channel_type, channel_name) ON public.alert_deliveries TO nyktus_worker;
GRANT UPDATE (status, attempts, not_before, last_attempt_at, last_status_code, last_error, last_duration_ms, delivered_at)
	ON public.alert_deliveries TO nyktus_worker;

-- The worker takes the periodic tasks and records when they ran. It cannot
-- add or rename a task. What a task removes, it removes through a function,
-- which decides what has expired.
GRANT SELECT ON public.periodic_tasks TO nyktus_worker;
GRANT UPDATE (next_run_at, last_started_at, last_succeeded_at, last_failed_at, last_rows)
	ON public.periodic_tasks TO nyktus_worker;
GRANT EXECUTE ON FUNCTION public.delete_expired_sign_in_data(integer) TO nyktus_worker;

-- GRANT and REVOKE only warn when the executing role lacks the privilege, so the
-- result is verified instead of assumed, in both directions: every privilege on
-- every table, column, sequence and function of the schema is compared with
-- the grants above.
DO $$
DECLARE
	missing text;
	extra text;
BEGIN
	WITH granted (relname, attname, privilege) AS (
		-- A NULL column stands for the whole table.
		VALUES
			('event_jobs', NULL, 'SELECT'), ('event_jobs', NULL, 'DELETE'),
			('event_jobs', 'attempts', 'UPDATE'), ('event_jobs', 'not_before', 'UPDATE'),
			('events', NULL, 'SELECT'), ('events', 'incident_id', 'UPDATE'),
			('incidents', NULL, 'SELECT'),
			('incidents', 'resource_type', 'INSERT'), ('incidents', 'resource_id', 'INSERT'),
			('incidents', 'severity', 'INSERT'), ('incidents', 'techniques', 'INSERT'),
			('incidents', 'first_event_at', 'INSERT'), ('incidents', 'last_event_at', 'INSERT'),
			('incidents', 'severity', 'UPDATE'), ('incidents', 'techniques', 'UPDATE'),
			('incidents', 'event_count', 'UPDATE'), ('incidents', 'first_event_at', 'UPDATE'),
			('incidents', 'last_event_at', 'UPDATE'),
			('alerts', 'incident_id', 'INSERT'), ('alerts', 'severity', 'INSERT'), ('alerts', 'techniques', 'INSERT'),
			('alerts', NULL, 'SELECT'), ('alert_channels', NULL, 'SELECT'), ('alert_channel_secrets', NULL, 'SELECT'),
			('alert_channel_secrets', 'url', 'UPDATE'), ('alert_channel_secrets', 'header_value', 'UPDATE'),
			('alert_deliveries', NULL, 'SELECT'),
			('alert_deliveries', 'alert_id', 'INSERT'), ('alert_deliveries', 'channel_id', 'INSERT'),
			('alert_deliveries', 'channel_type', 'INSERT'), ('alert_deliveries', 'channel_name', 'INSERT'),
			('alert_deliveries', 'status', 'UPDATE'), ('alert_deliveries', 'attempts', 'UPDATE'),
			('alert_deliveries', 'not_before', 'UPDATE'), ('alert_deliveries', 'last_attempt_at', 'UPDATE'),
			('alert_deliveries', 'last_status_code', 'UPDATE'), ('alert_deliveries', 'last_error', 'UPDATE'),
			('alert_deliveries', 'last_duration_ms', 'UPDATE'), ('alert_deliveries', 'delivered_at', 'UPDATE'),
			('periodic_tasks', NULL, 'SELECT'),
			('periodic_tasks', 'next_run_at', 'UPDATE'), ('periodic_tasks', 'last_started_at', 'UPDATE'),
			('periodic_tasks', 'last_succeeded_at', 'UPDATE'), ('periodic_tasks', 'last_failed_at', 'UPDATE'),
			('periodic_tasks', 'last_rows', 'UPDATE')
	),
	functions (signature) AS (
		VALUES ('public.attack_technique_ids_valid(text[])'), ('public.delete_expired_sign_in_data(integer)')
	),
	privileges (object, privilege, held, wanted) AS (
		SELECT c.relname::text, p.privilege,
			has_table_privilege('nyktus_worker', c.oid, p.privilege),
			EXISTS (
				SELECT FROM granted AS g
				WHERE g.relname = c.relname AND g.attname IS NULL AND g.privilege = p.privilege
			)
		FROM pg_catalog.pg_class AS c
		CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p (privilege)
		WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
		UNION ALL
		SELECT c.relname || '.' || a.attname, p.privilege,
			has_column_privilege('nyktus_worker', c.oid, a.attnum, p.privilege),
			EXISTS (
				SELECT FROM granted AS g
				WHERE g.relname = c.relname AND coalesce(g.attname, a.attname) = a.attname AND g.privilege = p.privilege
			)
		FROM pg_catalog.pg_class AS c
		JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS p (privilege)
		WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
		UNION ALL
		-- The CASE keeps the function from being evaluated on other relations,
		-- for which it fails, before the condition on the kind.
		SELECT c.relname::text, 'USAGE, SELECT, UPDATE',
			CASE WHEN c.relkind = 'S' THEN has_sequence_privilege('nyktus_worker', c.oid, 'USAGE, SELECT, UPDATE') END,
			false
		FROM pg_catalog.pg_class AS c
		WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'S'
		UNION ALL
		SELECT f.oid::regprocedure::text, 'EXECUTE', has_function_privilege('nyktus_worker', f.oid, 'EXECUTE'),
			f.oid IN (SELECT signature::regprocedure FROM functions)
		FROM pg_catalog.pg_proc AS f
		WHERE f.pronamespace = 'public'::regnamespace
		UNION ALL
		SELECT 'schema public', 'USAGE', has_schema_privilege('nyktus_worker', 'public', 'USAGE'), true
		UNION ALL
		SELECT 'schema public', 'CREATE', has_schema_privilege('nyktus_worker', 'public', 'CREATE'), false
	)
	SELECT string_agg(object || ': ' || privilege, ', ' ORDER BY object, privilege) FILTER (WHERE wanted AND NOT held),
		string_agg(object || ': ' || privilege, ', ' ORDER BY object, privilege) FILTER (WHERE held AND NOT wanted)
	INTO missing, extra
	FROM privileges;

	IF missing IS NOT NULL THEN
		RAISE EXCEPTION 'nyktus_worker lacks privileges (%); run migrations as the owner of the schema', missing;
	END IF;
	IF extra IS NOT NULL THEN
		RAISE EXCEPTION 'nyktus_worker has more privileges than granted (%); check the default privileges of the owner', extra;
	END IF;
END
$$;
