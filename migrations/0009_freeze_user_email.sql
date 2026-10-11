-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- The email address is the sign-in name of an account and cannot be changed. An
-- account with another address is a new account, so the console needs no right
-- to change addresses.
DO $$
BEGIN
	IF to_regrole('nyktus_console') IS NULL THEN
		RAISE EXCEPTION 'database role nyktus_console does not exist; create the server roles with deploy/postgres/roles.sql before running migrations';
	END IF;
END
$$;

REVOKE UPDATE (email) ON public.users FROM nyktus_console;

-- REVOKE only warns when the executing role lacks the privilege to revoke, so the
-- result is verified instead of assumed, in both directions.
DO $$
BEGIN
	IF has_column_privilege('nyktus_console', 'public.users', 'email', 'UPDATE') THEN
		RAISE EXCEPTION 'nyktus_console can still change email addresses in public.users; run migrations as the owner of the schema';
	END IF;

	IF EXISTS (
		SELECT FROM unnest(ARRAY['display_name', 'role', 'status', 'password_hash', 'updated_at']) AS c (name)
		WHERE NOT has_column_privilege('nyktus_console', 'public.users', c.name, 'UPDATE')
	) THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.users; run migrations as the owner of the schema';
	END IF;
END
$$;
