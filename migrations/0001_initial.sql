-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- The schema of Nyktus. Until the first release it lives in this one file and is
-- changed in place; released versions add numbered migrations after it.

-- The console connects as a member of the group role nyktus_console. Operators
-- create the group roles before the first migration, so that the migrating role
-- does not need CREATEROLE. A missing role stops the migration here with a clear
-- message instead of failing at the first GRANT.
DO $$
BEGIN
	IF to_regrole('nyktus_console') IS NULL THEN
		RAISE EXCEPTION 'database role nyktus_console does not exist; create the server roles with deploy/postgres/roles.sql before running migrations';
	END IF;
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
	CONSTRAINT users_password_check CHECK (
		(status <> 'pending' OR password_hash IS NULL)
		AND (status <> 'active' OR password_hash IS NOT NULL)
	),
	-- Only encoded Argon2id hashes are accepted, so a plain-text password can
	-- never be stored by mistake.
	CONSTRAINT users_password_hash_check CHECK (
		password_hash ~ '^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$'
	),
	CONSTRAINT users_updated_at_check CHECK (updated_at >= created_at)
);

-- Administrators list accounts from the newest to the oldest, a page at a time,
-- continuing after the last account of the previous page. The identifier makes
-- the order total for accounts with the same creation time. The address is not
-- used as the position: it would end up in the query string of the next page,
-- and with it in the logs of proxies.
CREATE INDEX users_created_at_id_idx ON public.users (created_at DESC, id DESC);

CREATE FUNCTION public.users_set_updated_at() RETURNS trigger
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
	FOR EACH ROW EXECUTE FUNCTION public.users_set_updated_at();

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
REVOKE ALL ON FUNCTION public.users_set_updated_at() FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.users_keep_active_admin() FROM PUBLIC, nyktus_console;

-- The console reaches no table without the schema. It is granted with the first
-- table the console uses, because the migration of the schema runs before any
-- server role is checked.
GRANT USAGE ON SCHEMA public TO nyktus_console;
GRANT SELECT, DELETE ON public.users TO nyktus_console;
-- Identifiers, creation times and the lockout counters come from the database
-- when an account is created. The console cannot set them, and it cannot change
-- identifiers, creation times or addresses.
GRANT INSERT (email, display_name, role, status, password_hash) ON public.users TO nyktus_console;
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
			SELECT FROM unnest(ARRAY['email', 'display_name', 'role', 'status', 'password_hash']) AS c (name)
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
		OR has_function_privilege('nyktus_console', 'public.users_set_updated_at()', 'EXECUTE')
		OR has_function_privilege('nyktus_console', 'public.users_keep_active_admin()', 'EXECUTE')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['id', 'created_at', 'updated_at', 'failed_logins', 'locked_until']) AS c (name)
			WHERE has_column_privilege('nyktus_console', 'public.users', c.name, 'INSERT')
		)
		OR EXISTS (
			SELECT FROM unnest(ARRAY['id', 'email', 'created_at']) AS c (name)
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
	-- Keys are deleted when they are revoked and with their user, so there is no
	-- foreign key: the entry that created a key names it with the same
	-- identifier as a resource.
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
	-- An API key acts for the user who owns it, so its entries name that user and
	-- the key. A user who activates their account or resets their password
	-- authenticates with the token of the link, before they have a new password;
	-- requests with an invalid token are not recorded, so anonymous actors never
	-- use those methods. The second step of a sign-in authenticates with a TOTP
	-- code or a recovery code; it always belongs to a known account, because only
	-- the correct password starts it. The command line and background jobs act
	-- as the system.
	CONSTRAINT audit_entries_actor_check CHECK (
		CASE actor_kind
			WHEN 'user' THEN auth_method IN ('password', 'oidc', 'session', 'api_key', 'activation_token', 'password_reset_token',
					'totp', 'recovery_code')
				AND actor_email IS NOT NULL AND actor_display_name IS NOT NULL
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

-- The console lists entries from the newest to the oldest, a page at a time,
-- continuing after the last entry of the previous page. The identifier makes the
-- order total for entries with the same time.
CREATE INDEX audit_entries_occurred_at_id_idx ON public.audit_entries (occurred_at DESC, id DESC);

-- The copies of the actor's address and display name are taken from the account,
-- not from the application, so they always match the account at the time of the
-- entry. Without an account, they are NULL, and the actor check rejects an entry
-- of a user that does not exist.
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

	CONSTRAINT sessions_token_hash_key UNIQUE (token_hash),
	CONSTRAINT sessions_token_hash_check CHECK (octet_length(token_hash) = 32),
	CONSTRAINT sessions_last_seen_at_check CHECK (last_seen_at >= created_at)
);

-- Signing in removes the expired sessions of the user, and deleting a user
-- removes all of them.
CREATE INDEX sessions_user_id_idx ON public.sessions (user_id);

-- Default privileges set by an operator could grant more than this migration
-- intends, so everything is revoked before the grants.
REVOKE ALL ON public.sessions FROM PUBLIC, nyktus_console;

GRANT SELECT, DELETE ON public.sessions TO nyktus_console;
-- Identifiers and times come from the database. The console only records when a
-- session was last used.
GRANT INSERT (token_hash, user_id) ON public.sessions TO nyktus_console;
GRANT UPDATE (last_seen_at) ON public.sessions TO nyktus_console;

-- GRANT and REVOKE only warn when the executing role lacks the privilege, so the
-- result is verified instead of assumed, in both directions.
DO $$
BEGIN
	IF NOT has_table_privilege('nyktus_console', 'public.sessions', 'SELECT')
		OR NOT has_table_privilege('nyktus_console', 'public.sessions', 'DELETE')
		OR NOT has_column_privilege('nyktus_console', 'public.sessions', 'token_hash', 'INSERT')
		OR NOT has_column_privilege('nyktus_console', 'public.sessions', 'user_id', 'INSERT')
		OR NOT has_column_privilege('nyktus_console', 'public.sessions', 'last_seen_at', 'UPDATE') THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.sessions; run migrations as the owner of the schema';
	END IF;

	IF has_table_privilege('nyktus_console', 'public.sessions', 'INSERT')
		OR has_table_privilege('nyktus_console', 'public.sessions', 'UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.sessions', 'REFERENCES')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['id', 'created_at', 'last_seen_at']) AS c (name)
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

-- API keys let integrations call the API on behalf of their user. As with
-- sessions, the database stores only the SHA-256 hash of the secret; the key
-- itself also carries the identifier, which looks the key up, so that the
-- secret is compared in the application in constant time. A key acts with the
-- intersection of its scopes and the current role of its user, so the scopes
-- are only checked for their form here. Revoking a key deletes it.
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
	-- Deleting a user deletes their keys; deactivating one deletes them in the
	-- application, so that reactivating the account does not revive them.
	user_id      uuid NOT NULL CONSTRAINT api_keys_user_id_fkey REFERENCES public.users (id) ON DELETE CASCADE,
	name         text NOT NULL,
	secret_hash  bytea NOT NULL,
	scopes       text[] NOT NULL,
	created_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
	expires_at   timestamptz NOT NULL,
	last_used_at timestamptz,

	CONSTRAINT api_keys_name_check CHECK (char_length(name) BETWEEN 1 AND 64),
	CONSTRAINT api_keys_secret_hash_check CHECK (octet_length(secret_hash) = 32),
	CONSTRAINT api_keys_scopes_check CHECK (public.api_key_scopes_valid(scopes)),
	-- Every key expires within a year. The difference of two times is immutable,
	-- unlike the sum of a time and an interval, which depends on the time zone.
	CONSTRAINT api_keys_expires_at_check CHECK (expires_at > created_at AND expires_at - created_at <= interval '365 days'),
	CONSTRAINT api_keys_last_used_at_check CHECK (last_used_at >= created_at)
);

-- Keys are listed and counted per user, and deleted with the user.
CREATE INDEX api_keys_user_id_idx ON public.api_keys (user_id);

REVOKE ALL ON public.api_keys FROM PUBLIC, nyktus_console;
REVOKE ALL ON FUNCTION public.api_key_scopes_valid(text[]) FROM PUBLIC, nyktus_console;

-- The console evaluates the check of the scopes when it inserts. It issues,
-- lists and deletes keys and records their last use; it cannot change the
-- secret, the scopes, the owner or the expiry of a key, and identifiers and
-- creation times come from the database.
GRANT EXECUTE ON FUNCTION public.api_key_scopes_valid(text[]) TO nyktus_console;
GRANT SELECT, DELETE ON public.api_keys TO nyktus_console;
GRANT INSERT (user_id, name, secret_hash, scopes, expires_at) ON public.api_keys TO nyktus_console;
GRANT UPDATE (last_used_at) ON public.api_keys TO nyktus_console;

DO $$
BEGIN
	IF NOT has_table_privilege('nyktus_console', 'public.api_keys', 'SELECT')
		OR NOT has_table_privilege('nyktus_console', 'public.api_keys', 'DELETE')
		OR NOT has_function_privilege('nyktus_console', 'public.api_key_scopes_valid(text[])', 'EXECUTE')
		OR NOT has_column_privilege('nyktus_console', 'public.api_keys', 'last_used_at', 'UPDATE')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['user_id', 'name', 'secret_hash', 'scopes', 'expires_at']) AS c (name)
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
			SELECT FROM unnest(ARRAY['id', 'user_id', 'name', 'secret_hash', 'scopes', 'created_at', 'expires_at']) AS c (name)
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
