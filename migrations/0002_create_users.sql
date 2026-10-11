-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

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
	CONSTRAINT users_role_check CHECK (role IN ('admin', 'editor', 'viewer')),
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
