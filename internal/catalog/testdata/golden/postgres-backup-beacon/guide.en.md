# PostgreSQL objects that travel with every backup

The deception attaches the trigger to your backup itself. An intruder who steals a dump of your database restores it on a machine of their own, where a restore script that only points at your host would never run. Both files are SQL for your database, with the DNS honeytoken host `databaseq3xwz7a2kfm4ub6tyc5nre.d.example.net`. You run them once; every dump you take afterwards carries the objects. Neither file creates a table with data, and neither changes data.

## The object that fires on restore

`restore-hook.sql` creates the function `refresh_catalog_stats` and the materialized view `catalog_stats`, which calls it. A dump holds the view without its contents and refreshes it when it is restored, in the custom and the directory format as well as in a plain dump. The refresh calls the function, and its connection attempt with `dblink` resolves the host name, which raises an event. Creating the view in your own database runs the function once, so the file tests itself.

1. Check that the extension `dblink` is available: it ships with PostgreSQL in the package `postgresql-contrib` or with the server itself, depending on the distribution. The function names `public.dblink_connect`, because a restore runs with an empty search path.
2. Run the file in your database: `psql -d DATABASE -f restore-hook.sql`. The role needs the right to create an extension and objects in the schema `public`.
3. Choose `FunctionName` and `ViewName` when you apply the deception, so that they fit your schema. Both appear in the dump.

## The object that fires on a query

`foreign-table.sql` creates a foreign table `customer_payment_tokens` that points to a remote database. It is part of the schema, survives every dump format and resolves the host name only when someone queries the table, for example while searching for tables with valuable names.

1. Check that the extension `postgres_fdw` is available.
2. Run the file in your database. Choose a name for the table that an intruder wants to read.

## Testing

Take a dump with `pg_dump DATABASE > dump.sql` and restore it into an empty database on a computer with access to the internet: `psql -d TEST -f dump.sql`. Within a minute, the scenario shows an incident. Then query the foreign table with `SELECT * FROM customer_payment_tokens` for a second one. Close the incidents after the test. Use one deception for each database or backup set, so that an incident tells you which data was stolen. Tell your database administrators: a test restore on a machine with internet access raises an event as well.

## Limits

- A restore in a network that cannot resolve names on the internet does not reach the DNS role. That holds for every beacon in a backup: it catches the intruder who restores your backup on a machine of their own, not one who works in an isolated laboratory.
- Whoever searches the dump for host names, or looks at the objects of the restored database, can find the name unusual.
- The restore needs the extension `dblink` on the machine of the intruder. Without it the dump reports an error for the extension and the function does not run.
