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

CREATE TABLE public.users (
	-- Random identifiers reveal neither the number of accounts nor the order in
	-- which they were created.
	id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	email         text NOT NULL,
	display_name  text NOT NULL,
	role          text NOT NULL,
	status        text NOT NULL,
	password_hash text,
	created_at    timestamptz NOT NULL DEFAULT now(),
	updated_at    timestamptz NOT NULL DEFAULT now(),

	-- The application validates addresses and stores them in lower case, so the
	-- unique constraint is case-insensitive. The checks are deliberately simple and
	-- independent of the database locale; they reject what the application never
	-- writes.
	CONSTRAINT users_email_key UNIQUE (email),
	CONSTRAINT users_email_check CHECK (
		octet_length(email) <= 254
		AND email ~ '^[^@]+@[^@]+$'
		AND email !~ '[\x01-\x20\x7f"A-Z]'
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

GRANT USAGE ON SCHEMA public TO nyktus_console;
GRANT SELECT, DELETE ON public.users TO nyktus_console;
-- Identifiers and creation times come from the database. The console cannot set
-- or change them.
GRANT INSERT (email, display_name, role, status, password_hash) ON public.users TO nyktus_console;
GRANT UPDATE (email, display_name, role, status, password_hash, updated_at) ON public.users TO nyktus_console;

-- GRANT only warns when the executing role lacks the privilege to grant, so the
-- result is verified instead of assumed.
DO $$
BEGIN
	IF NOT has_schema_privilege('nyktus_console', 'public', 'USAGE')
		OR NOT has_table_privilege('nyktus_console', 'public.users', 'SELECT')
		OR NOT has_table_privilege('nyktus_console', 'public.users', 'DELETE')
		OR NOT has_column_privilege('nyktus_console', 'public.users', 'updated_at', 'UPDATE')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['email', 'display_name', 'role', 'status', 'password_hash']) AS c (name)
			WHERE NOT has_column_privilege('nyktus_console', 'public.users', c.name, 'INSERT')
				OR NOT has_column_privilege('nyktus_console', 'public.users', c.name, 'UPDATE')
		) THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.users; run migrations as the owner of the schema';
	END IF;
END
$$;
