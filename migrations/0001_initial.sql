-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- The schema of Nyktus. Until the first release it lives in this one file and is
-- changed in place; released versions add numbered migrations after it.

-- The console, the trigger and the DNS role connect as members of the group roles
-- nyktus_console, nyktus_trigger and nyktus_dns. Operators create the group roles before the
-- first migration, so that the migrating role does not need CREATEROLE. A missing
-- role stops the migration here with a clear message instead of failing at the
-- first GRANT.
DO $$
DECLARE
	role_name text;
BEGIN
	FOREACH role_name IN ARRAY ARRAY['nyktus_console', 'nyktus_trigger', 'nyktus_dns'] LOOP
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
	last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
	-- When the user of an account of the identity provider last signed in there
	-- again for this session. A sensitive action, which a local account
	-- confirms with its password, requires that it was a few minutes ago.
	reauthenticated_at timestamptz,

	CONSTRAINT sessions_token_hash_key UNIQUE (token_hash),
	CONSTRAINT sessions_token_hash_check CHECK (octet_length(token_hash) = 32),
	CONSTRAINT sessions_last_seen_at_check CHECK (last_seen_at >= created_at),
	CONSTRAINT sessions_reauthenticated_at_check CHECK (reauthenticated_at >= created_at)
);

-- Signing in removes the expired sessions of the user, and deleting a user
-- removes all of them.
CREATE INDEX sessions_user_id_idx ON public.sessions (user_id);

-- Default privileges set by an operator could grant more than this migration
-- intends, so everything is revoked before the grants.
REVOKE ALL ON public.sessions FROM PUBLIC, nyktus_console;

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
);

-- Starting a sign-in removes the expired ones.
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
-- transaction, so that no event goes unprocessed.
CREATE TABLE public.event_jobs (
	event_id   uuid PRIMARY KEY REFERENCES public.events (id) ON DELETE CASCADE,
	created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

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

-- The console reads no events yet. Nobody writes them except through the
-- functions above.
REVOKE ALL ON public.events, public.event_jobs FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.honeytoken_event_limit_reached(uuid) FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.record_honeytoken_request(text, text, inet, text, text, text)
	FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.record_dns_query(text, text, text, text, text, inet, interval) FROM PUBLIC, nyktus_console;

-- REVOKE only warns when the executing role lacks the grant option, so the
-- result is verified instead of assumed. An event that the console could write
-- would have no job, or a job no event.
DO $$
BEGIN
	IF has_table_privilege('nyktus_console', 'public.events', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.events', 'SELECT, INSERT, UPDATE, REFERENCES')
		OR has_table_privilege('nyktus_console', 'public.event_jobs', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.event_jobs', 'SELECT, INSERT, UPDATE, REFERENCES')
		OR has_function_privilege('nyktus_console', 'public.honeytoken_event_limit_reached(uuid)', 'EXECUTE')
		OR has_function_privilege('nyktus_console',
			'public.record_honeytoken_request(text, text, inet, text, text, text)', 'EXECUTE')
		OR has_function_privilege('nyktus_console',
			'public.record_dns_query(text, text, text, text, text, inet, interval)', 'EXECUTE') THEN
		RAISE EXCEPTION 'nyktus_console has privileges on events; check the default privileges of the owner';
	END IF;
END
$$;

-- The trigger and the DNS role reach nothing but their function. Everything in
-- the schema is revoked here, at its end, including the table of the migration
-- runner, so that default privileges set by an operator cannot widen them
-- beyond it.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM nyktus_trigger, nyktus_dns;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM nyktus_trigger, nyktus_dns;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM nyktus_trigger, nyktus_dns;
GRANT USAGE ON SCHEMA public TO nyktus_trigger, nyktus_dns;
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
