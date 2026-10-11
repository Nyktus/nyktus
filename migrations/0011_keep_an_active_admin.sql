-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- At least one active administrator must remain once one exists. Without one,
-- nobody could manage the installation, and once no account with the role admin
-- is left, the setup of a first administrator opens again with the next start.
-- The console checks this rule before it demotes, deactivates or deletes an
-- account. This trigger is the last line of defense for every other way of
-- changing the table, such as a statement of a compromised console.
DO $$
BEGIN
	IF to_regrole('nyktus_console') IS NULL THEN
		RAISE EXCEPTION 'database role nyktus_console does not exist; create the server roles with deploy/postgres/roles.sql before running migrations';
	END IF;
END
$$;

-- The function locks the other active administrators before it counts them. A
-- plain count would see the state before concurrent transactions commit, so two
-- transactions that each remove a different one of the last two administrators
-- would both pass. With the lock, the second one waits for the first and then
-- sees its result, or one of them fails with a deadlock; either way, one
-- administrator remains. The console locks all active administrators in a fixed
-- order before it changes one, so its own requests wait instead of deadlocking.
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

-- A trigger function runs with the rights of the role that fires the trigger, and
-- needs no grant for it. Nobody calls it directly.
REVOKE ALL ON FUNCTION public.users_keep_active_admin() FROM PUBLIC, nyktus_console;

DO $$
BEGIN
	IF has_function_privilege('nyktus_console', 'public.users_keep_active_admin()', 'EXECUTE') THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on public.users_keep_active_admin() than granted; check the default privileges of the owner';
	END IF;
END
$$;
