-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Creates the owner, the database and the logins of the server roles for the
-- development environment, as described in "Database setup" of the operations
-- documentation. The group roles come from deploy/postgres/roles.sql, which the
-- compose file mounts as 00-roles.sql so that it runs first.
--
-- The passwords are public on purpose. The database is published on the loopback
-- address only and holds nothing but development data.

CREATE ROLE nyktus_owner LOGIN PASSWORD 'dev';
CREATE DATABASE nyktus OWNER nyktus_owner ENCODING 'UTF8' TEMPLATE template0;

CREATE ROLE nyktus_console_login LOGIN PASSWORD 'dev' IN ROLE nyktus_console;
CREATE ROLE nyktus_trigger_login LOGIN PASSWORD 'dev' IN ROLE nyktus_trigger;
CREATE ROLE nyktus_dns_login LOGIN PASSWORD 'dev' IN ROLE nyktus_dns;
CREATE ROLE nyktus_worker_login LOGIN PASSWORD 'dev' IN ROLE nyktus_worker;
