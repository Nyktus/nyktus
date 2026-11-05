## Story

Attach the trigger to your backup itself. An intruder who steals a dump of your database restores it on a machine of their own, where a restore script that only points at your host would never run. Both files are SQL for your database, with a DNS honeytoken as the host. You run them once, and every dump you take afterwards carries the objects. Neither file creates a table with data, and neither changes data.

- `restore-hook.sql` creates the function `refresh_catalog_stats` and the materialized view `catalog_stats`, which calls it. A dump holds the view without its contents and refreshes it when it is restored, in the custom and the directory format as well as in a plain dump. The refresh calls the function, and its connection attempt with `dblink` looks up the host name, which raises an event.
- `foreign-table.sql` creates a foreign table `customer_payment_tokens` that points to a remote database. It is part of the schema, survives every dump format and looks up the host name only when someone queries the table, for example while searching for tables with valuable names.

## Setup

1. Create the DNS honeytoken "Database host". Replace `Honeytoken-Domain` in both files with its name.
2. Check that the extensions are available: `dblink` for `restore-hook.sql` and `postgres_fdw` for `foreign-table.sql`. They ship with PostgreSQL, in the package `postgresql-contrib` or with the server itself, depending on the distribution.
3. Replace the names `refresh_catalog_stats`, `catalog_stats` and `customer_payment_tokens` with names that fit your schema. Choose a table name that an intruder wants to read. The names appear in the dump.
4. Run each file in your database: `psql -d DATABASE -f restore-hook.sql` and `psql -d DATABASE -f foreign-table.sql`. The role needs the right to create an extension and objects in the schema `public`. Creating the view runs the function once, which raises an incident; close it.
5. Use one deception for each database or backup set, so that an incident tells you which data was stolen.
6. Record in the notes of the scenario which database holds the objects.

## Testing

Take a dump with `pg_dump DATABASE > dump.sql` and restore it into an empty database on a computer with access to the internet: `psql -d TEST -f dump.sql`. Within a minute, the scenario shows an incident. Then query the foreign table with `SELECT * FROM customer_payment_tokens` for a second incident. Close the incidents after the test.

To check only the name resolution, run `nslookup Honeytoken-Domain`, with the name of the honeytoken.

## Limits

- A test restore by your own database administrators on a computer with access to the internet raises an event as well, so tell them.
- A restore in a network that cannot resolve names on the internet does not reach the DNS role. That holds for every beacon in a backup: it catches the intruder who restores your backup on a machine of their own, not one who works in an isolated laboratory.
- Whoever searches the dump for host names, or looks at the objects of the restored database, can find the name unusual.
- The restore needs the extension `dblink` on the machine of the intruder. Without it the dump reports an error for the extension and the function does not run.
- Keep the schema name `public.` in front of `dblink_connect` in the function: a restore runs with an empty search path, and without the name the function fails before the lookup.
