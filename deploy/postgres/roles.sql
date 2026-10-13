-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Creates the group roles of the Nyktus server roles.
--
-- Run this script as a role with CREATEROLE before the first "nyktus migrate",
-- and again after an upgrade that adds a server role. Migrations grant privileges
-- to these roles but never create them, so the role that runs migrations does not
-- need CREATEROLE. The script can run any number of times.
--
-- Role names are global to the PostgreSQL cluster. Run one Nyktus instance per
-- cluster.
--
--   psql --file=roles.sql

-- Group role of the console. The login role of the console is a member of it.
DO $$
BEGIN
	CREATE ROLE nyktus_console NOLOGIN;
EXCEPTION
	-- The role exists already, or a concurrent run has just created it.
	WHEN duplicate_object OR unique_violation THEN
		NULL;
END
$$;

-- Group role of the trigger, which answers requests from the internet. It can
-- only call the function that records a request; its login role is a member of
-- it.
DO $$
BEGIN
	CREATE ROLE nyktus_trigger NOLOGIN;
EXCEPTION
	WHEN duplicate_object OR unique_violation THEN
		NULL;
END
$$;

-- Group role of the DNS role, which answers queries from the internet. It can
-- only call the function that records a query; its login role is a member of
-- it.
DO $$
BEGIN
	CREATE ROLE nyktus_dns NOLOGIN;
EXCEPTION
	WHEN duplicate_object OR unique_violation THEN
		NULL;
END
$$;
