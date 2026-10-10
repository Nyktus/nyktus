-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Five failed sign-ins in a row lock an account for 15 minutes. The counters live
-- in the database, so that neither a restart nor a second console process resets
-- them.
DO $$
BEGIN
	IF to_regrole('nyktus_console') IS NULL THEN
		RAISE EXCEPTION 'database role nyktus_console does not exist; create the server roles with deploy/postgres/roles.sql before running migrations';
	END IF;
END
$$;

ALTER TABLE public.users
	-- Failed sign-ins since the last successful one or the last lock. The fifth
	-- locks the account and starts the count again.
	ADD COLUMN failed_logins integer NOT NULL DEFAULT 0
		CONSTRAINT users_failed_logins_check CHECK (failed_logins BETWEEN 0 AND 4),
	ADD COLUMN locked_until timestamptz;

-- The console counts failures and locks accounts. A new account starts with the
-- defaults, so the console cannot insert these columns.
GRANT UPDATE (failed_logins, locked_until) ON public.users TO nyktus_console;

-- GRANT only warns when the executing role lacks the privilege to grant, so the
-- result is verified instead of assumed, in both directions.
DO $$
BEGIN
	IF NOT has_column_privilege('nyktus_console', 'public.users', 'failed_logins', 'UPDATE')
		OR NOT has_column_privilege('nyktus_console', 'public.users', 'locked_until', 'UPDATE') THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.users; run migrations as the owner of the schema';
	END IF;

	IF has_column_privilege('nyktus_console', 'public.users', 'failed_logins', 'INSERT')
		OR has_column_privilege('nyktus_console', 'public.users', 'locked_until', 'INSERT')
		OR has_any_column_privilege('nyktus_console', 'public.users', 'REFERENCES') THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on public.users than granted; check the default privileges of the owner';
	END IF;
END
$$;
