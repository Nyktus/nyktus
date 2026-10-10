-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

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
