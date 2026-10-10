# Database setup

Nyktus stores all state in PostgreSQL 16 or later. Each server role connects with its own database role, which holds only the privileges that role needs. Migrations run with a separate owner role.

## Roles

| Role | Kind | Purpose |
|---|---|---|
| `nyktus_owner` (any name) | Login | Owns the database and the `public` schema. Runs `nyktus migrate`. Never used by a running server. |
| `nyktus_console` | Group, created by the setup script | Receives the privileges of the console role through migrations. |
| Console login (any name) | Login, member of `nyktus_console` | The console connects with it through `NYKTUS_CONSOLE_DATABASE_URL`. |

Migrations grant privileges to the group roles but never create roles, so the owner does not need `CREATEROLE`. A migration that needs a group role that does not exist stops with an error that names the role.

Role names are global to a PostgreSQL cluster. Run one Nyktus instance per cluster.

## Setup

Run the following as a superuser, such as `postgres`. Choose your own passwords.

Creating a database owned by another role needs more than `CREATEROLE`: it requires `CREATEDB` and, since PostgreSQL 16, the right to `SET ROLE` to the owner. If a superuser is not available for the whole setup, step 1 alone runs with a role that has only `CREATEROLE`.

1. Create the group roles with [`deploy/postgres/roles.sql`](../../deploy/postgres/roles.sql). The script can run any number of times. Run it again after an upgrade that adds a server role.

   ```sh
   psql --file=deploy/postgres/roles.sql
   ```

2. Create the owner and the database:

   ```sql
   CREATE ROLE nyktus_owner LOGIN PASSWORD '...';
   CREATE DATABASE nyktus OWNER nyktus_owner ENCODING 'UTF8';
   ```

   The database must use the `UTF8` encoding; migrations stop otherwise. If the default encoding of your cluster differs, add `TEMPLATE template0` to the statement.

   The `public` schema of a new database belongs to the database owner. In a cluster that was upgraded from PostgreSQL 14 or earlier, the template database can still assign it to the bootstrap superuser. Transfer it explicitly in that case:

   ```sql
   \connect nyktus
   ALTER SCHEMA public OWNER TO nyktus_owner;
   ```

3. Create the login role of the console as a member of its group role:

   ```sql
   CREATE ROLE nyktus_console_login LOGIN PASSWORD '...' IN ROLE nyktus_console;
   ```

   The login role receives its privileges by inheriting them from the group role. Do not create it with `NOINHERIT`.

4. Apply the migrations as the owner:

   ```sh
   NYKTUS_DATABASE_URL='postgres://nyktus_owner:...@db/nyktus' nyktus migrate
   ```

5. Start the console with its login role:

   ```sh
   NYKTUS_CONSOLE_DATABASE_URL='postgres://nyktus_console_login:...@db/nyktus' \
   NYKTUS_CONSOLE_URL='https://nyktus.example.com' \
     nyktus serve --roles=console
   ```

   `NYKTUS_CONSOLE_URL` is the address under which users reach the console. See [Configuration](configuration.md).

   On the first start, the console prints a URL for creating the first administrator. See [First start](first-start.md).

## Privilege check

Outside development, the server refuses to start if a role's login can bypass the privilege separation: if it is a superuser, can bypass row-level security, can create roles or databases, can start replication, is a member of `pg_read_all_data`, `pg_write_all_data`, `pg_read_server_files`, `pg_write_server_files` or `pg_execute_server_program`, or owns the database or the schema. Use the login roles from the setup above, not the owner.
