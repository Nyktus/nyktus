-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Default privileges set by an operator for the owner, for example to give a
-- monitoring role read access, also apply when they name the console's group role.
-- The console would then hold more on public.users than its grants intend, such as
-- TRUNCATE or the right to set identifiers. Everything is revoked and granted
-- again, and the result is verified in both directions.
DO $$
BEGIN
	IF to_regrole('nyktus_console') IS NULL THEN
		RAISE EXCEPTION 'database role nyktus_console does not exist; create the server roles with deploy/postgres/roles.sql before running migrations';
	END IF;
END
$$;

-- Revoking a table privilege also revokes it on every column.
REVOKE ALL ON public.users FROM PUBLIC, nyktus_console;

GRANT SELECT, DELETE ON public.users TO nyktus_console;
-- Identifiers and creation times come from the database. The console cannot set
-- or change them.
GRANT INSERT (email, display_name, role, status, password_hash) ON public.users TO nyktus_console;
GRANT UPDATE (email, display_name, role, status, password_hash, updated_at) ON public.users TO nyktus_console;

DO $$
BEGIN
	IF NOT has_table_privilege('nyktus_console', 'public.users', 'SELECT')
		OR NOT has_table_privilege('nyktus_console', 'public.users', 'DELETE')
		OR NOT has_column_privilege('nyktus_console', 'public.users', 'updated_at', 'UPDATE')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['email', 'display_name', 'role', 'status', 'password_hash']) AS c (name)
			WHERE NOT has_column_privilege('nyktus_console', 'public.users', c.name, 'INSERT')
				OR NOT has_column_privilege('nyktus_console', 'public.users', c.name, 'UPDATE')
		) THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.users; run migrations as the owner of the schema';
	END IF;

	IF has_table_privilege('nyktus_console', 'public.users', 'INSERT')
		OR has_table_privilege('nyktus_console', 'public.users', 'UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.users', 'REFERENCES')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['id', 'created_at', 'updated_at']) AS c (name)
			WHERE has_column_privilege('nyktus_console', 'public.users', c.name, 'INSERT')
		)
		OR EXISTS (
			SELECT FROM unnest(ARRAY['id', 'created_at']) AS c (name)
			WHERE has_column_privilege('nyktus_console', 'public.users', c.name, 'UPDATE')
		) THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on public.users than granted; check the default privileges of the owner';
	END IF;
END
$$;
