#!/bin/sh
# SPDX-FileCopyrightText: The Nyktus Authors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Sets up the PostgreSQL side of a Nyktus installation, as described in
# "Database setup" of the operations documentation: the group roles, the owner,
# the database and one login per server role, each with a random password.
#
# The passwords go to files and nowhere else: not to the terminal, not into the
# arguments of a process. For every login the script writes one file with the
# line "NYKTUS_<ROLE>_DATABASE_URL=...", for the owner "NYKTUS_DATABASE_URL=...",
# and gives it to the owner of the files only.
#
# Run it as a PostgreSQL superuser. The connection comes from the usual libpq
# variables (PGHOST, PGPORT, PGUSER, PGPASSWORD, PGSSLMODE). The script stops
# when the owner or the database exists, so it never changes a password of an
# installation that already runs. Role names are global to the cluster: run one
# Nyktus installation per cluster.
#
#   sh setup.sh --client-host db.internal.example.net --dns

set -eu

usage() {
	cat >&2 <<'EOF'
Usage: setup.sh [options]

  --client-host HOST[:PORT]  Address that the Nyktus hosts use to reach the
                             database. Default: PGHOST and PGPORT.
  --sslmode MODE             sslmode of the connection URLs. One of disable,
                             require, verify-ca, verify-full.
                             Default: verify-full.
  --dns                      Also create the login of the DNS role.
  --out DIRECTORY            Directory for the files with the connection URLs.
                             Must not exist. Default: ./nyktus-database
  --database NAME            Name of the database. Default: nyktus
  --help                     Show this text.
EOF
}

fail() {
	echo "setup.sh: $*" >&2
	exit 1
}

client_host=
sslmode=verify-full
dns=no
out=./nyktus-database
database=nyktus

while [ $# -gt 0 ]; do
	case $1 in
	--client-host)
		[ $# -ge 2 ] || fail "--client-host needs a value"
		client_host=$2
		shift 2
		;;
	--sslmode)
		[ $# -ge 2 ] || fail "--sslmode needs a value"
		sslmode=$2
		shift 2
		;;
	--dns)
		dns=yes
		shift
		;;
	--out)
		[ $# -ge 2 ] || fail "--out needs a value"
		out=$2
		shift 2
		;;
	--database)
		[ $# -ge 2 ] || fail "--database needs a value"
		database=$2
		shift 2
		;;
	--help | -h)
		usage
		exit 0
		;;
	*)
		usage
		fail "unknown option: $1"
		;;
	esac
done

case $sslmode in
disable | require | verify-ca | verify-full) ;;
*) fail "--sslmode must be disable, require, verify-ca or verify-full" ;;
esac

# The name goes into SQL and into a URL without quoting, so keep it plain.
case $database in
'' | *[!a-z0-9_]* | [0-9]*) fail "--database must consist of the characters a-z, 0-9 and _ and not start with a digit" ;;
esac

if [ -z "$client_host" ]; then
	case ${PGHOST:-localhost} in
	/*) fail "PGHOST is a socket directory: pass --client-host" ;;
	esac
	client_host=${PGHOST:-localhost}
	if [ -n "${PGPORT:-}" ]; then
		client_host=$client_host:$PGPORT
	fi
fi
case $client_host in
*[!A-Za-z0-9.:_-]*) fail "--client-host must be a host name or address with an optional port" ;;
esac

command -v psql >/dev/null 2>&1 || fail "psql not found: install the PostgreSQL client"
command -v openssl >/dev/null 2>&1 || fail "openssl not found"

here=$(cd "$(dirname "$0")" && pwd)
[ -r "$here/roles.sql" ] || fail "roles.sql not found next to setup.sh"
[ ! -e "$out" ] || fail "$out exists: remove it or choose another --out"

run_sql() {
	psql --no-psqlrc --quiet --set ON_ERROR_STOP=1 --dbname postgres "$@"
}

# The query prints t or f. Refuse to go on when the database is partly set up,
# because creating the logins again would change their passwords.
taken=$(run_sql --no-align --tuples-only --command \
	"SELECT EXISTS (SELECT FROM pg_roles WHERE rolname LIKE 'nyktus\_%\_login' OR rolname = 'nyktus_owner')
	    OR EXISTS (SELECT FROM pg_database WHERE datname = '$database')") ||
	fail "cannot connect to PostgreSQL as a superuser"
[ "$taken" = f ] || fail "a Nyktus role or the database $database exists already; remove it first or set up the logins by hand (see Database setup)"

# 192 bits of randomness as hex: safe in a URL and in SQL without quoting.
password() {
	openssl rand -hex 24
}

roles="console trigger worker"
if [ "$dns" = yes ]; then
	roles="$roles dns"
fi

umask 077
mkdir "$out"
# A failed run leaves no half-written file with a password behind.
trap 'rm -rf "$out"' EXIT

owner_password=$(password)
sql="CREATE ROLE nyktus_owner LOGIN PASSWORD '$owner_password';
CREATE DATABASE $database OWNER nyktus_owner ENCODING 'UTF8' TEMPLATE template0;
"
printf 'NYKTUS_DATABASE_URL=postgres://nyktus_owner:%s@%s/%s?sslmode=%s\n' \
	"$owner_password" "$client_host" "$database" "$sslmode" >"$out/owner.db.env"

for role in $roles; do
	login_password=$(password)
	sql="${sql}CREATE ROLE nyktus_${role}_login LOGIN PASSWORD '$login_password' IN ROLE nyktus_$role;
"
	upper=$(printf '%s' "$role" | tr a-z A-Z)
	printf 'NYKTUS_%s_DATABASE_URL=postgres://nyktus_%s_login:%s@%s/%s?sslmode=%s\n' \
		"$upper" "$role" "$login_password" "$client_host" "$database" "$sslmode" >"$out/$role.db.env"
done

run_sql --file "$here/roles.sql"
printf '%s' "$sql" | run_sql

trap - EXIT
echo "Created the database $database and the logins of: owner $roles"
echo "The connection URLs are in $out/, one file per login. They hold the passwords."
echo "Next: apply the migrations with the URL of the owner (see Database setup)."
