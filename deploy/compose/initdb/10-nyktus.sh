#!/bin/sh
# SPDX-FileCopyrightText: The Nyktus Authors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Creates the owner, the database and the logins of the server roles, as
# described in "Database setup" of the operations documentation. The group roles
# come from deploy/postgres/roles.sql, which the compose file mounts as
# 00-roles.sql so that it runs first. The entrypoint of the image runs this
# script on the first start of an empty data directory only.
#
# The passwords arrive in the environment of the container and reach PostgreSQL
# as psql variables, so that the quoting is psql's and no password lands in a
# file.

set -eu

psql --set ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
	--set owner_password="$NYKTUS_OWNER_DB_PASSWORD" \
	--set console_password="$NYKTUS_CONSOLE_DB_PASSWORD" \
	--set trigger_password="$NYKTUS_TRIGGER_DB_PASSWORD" \
	--set dns_password="$NYKTUS_DNS_DB_PASSWORD" \
	--set worker_password="$NYKTUS_WORKER_DB_PASSWORD" <<'SQL'
CREATE ROLE nyktus_owner LOGIN PASSWORD :'owner_password';
CREATE DATABASE nyktus OWNER nyktus_owner ENCODING 'UTF8' TEMPLATE template0;

CREATE ROLE nyktus_console_login LOGIN PASSWORD :'console_password' IN ROLE nyktus_console;
CREATE ROLE nyktus_trigger_login LOGIN PASSWORD :'trigger_password' IN ROLE nyktus_trigger;
CREATE ROLE nyktus_dns_login LOGIN PASSWORD :'dns_password' IN ROLE nyktus_dns;
CREATE ROLE nyktus_worker_login LOGIN PASSWORD :'worker_password' IN ROLE nyktus_worker;
SQL
