# Database setup

Nyktus stores all state in PostgreSQL 16 or later. Each server role connects with its own database role, which holds only the privileges that role needs. Migrations run with a separate owner role.

## Roles

| Role | Kind | Purpose |
|---|---|---|
| `nyktus_owner` (any name) | Login | Owns the database and the `public` schema. Runs `nyktus migrate`. Never used by a running server. |
| `nyktus_console` | Group, created by the setup script | Receives the privileges of the console role through migrations. |
| Console login (any name) | Login, member of `nyktus_console` | The console connects with it through `NYKTUS_CONSOLE_DATABASE_URL`. |
| `nyktus_trigger` | Group, created by the setup script | Receives the privileges of the trigger role through migrations: it can call the one function that records a request, and read or write no table. |
| Trigger login (any name) | Login, member of `nyktus_trigger` | The trigger connects with it through `NYKTUS_TRIGGER_DATABASE_URL`. |
| `nyktus_dns` | Group, created by the setup script | Receives the privileges of the DNS role through migrations: it can call the one function that records a query, and read or write no table. |
| DNS login (any name) | Login, member of `nyktus_dns` | The [DNS role](dns.md) connects with it through `NYKTUS_DNS_DATABASE_URL`. |
| `nyktus_worker` | Group, created by the setup script | Receives the privileges of the worker through migrations: it reads events and writes incidents and their alerts, but reads no honeytokens, accounts or audit entries. |
| Worker login (any name) | Login, member of `nyktus_worker` | The worker connects with it through `NYKTUS_WORKER_DATABASE_URL`. |

The trigger and the DNS role are reached from the internet. Their roles cannot read honeytokens: each hands one requested value at a time to a database function of its own, which records the request or query and returns only what the answer and the log need. Whoever takes over the host of the trigger or of the DNS role can test a URL or name they already know, but cannot list the decoys. Each role can only call its own function, so a login of the trigger cannot record DNS queries, and the other way around.

The worker correlates events into [incidents](incidents.md). It needs no honeytoken to do so: every event holds the type and the techniques of its honeytoken. Its role can read events and assign them to incidents, open and update incidents and write their alerts, but cannot change what an event recorded, change the triage of an incident, change an alert once written, or delete anything other than the processing jobs of events.

The console manages [alert channels](alerting.md) and writes their secrets, the URL and the value of a header, but its role cannot read them back: whoever takes over the console's login does not obtain the channels. The secrets are stored encrypted in a table of their own, `alert_channel_secrets`.

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

3. Create the login roles of the console, the trigger, the DNS role and the worker as members of their group roles:

   ```sql
   CREATE ROLE nyktus_console_login LOGIN PASSWORD '...' IN ROLE nyktus_console;
   CREATE ROLE nyktus_trigger_login LOGIN PASSWORD '...' IN ROLE nyktus_trigger;
   CREATE ROLE nyktus_dns_login LOGIN PASSWORD '...' IN ROLE nyktus_dns;
   CREATE ROLE nyktus_worker_login LOGIN PASSWORD '...' IN ROLE nyktus_worker;
   ```

   Create only the logins of the roles you run.

   The login roles receive their privileges by inheriting them from the group roles. Do not create them with `NOINHERIT`.

4. Apply the migrations as the owner:

   ```sh
   NYKTUS_DATABASE_URL='postgres://nyktus_owner:...@db/nyktus' nyktus migrate
   ```

5. Start the console with its login role:

   ```sh
   NYKTUS_CONSOLE_DATABASE_URL='postgres://nyktus_console_login:...@db/nyktus' \
   NYKTUS_CONSOLE_URL='https://nyktus.example.com' \
   NYKTUS_TRIGGER_URL='https://t.example.net' \
   NYKTUS_ENCRYPTION_KEYS_FILE=/run/secrets/nyktus-keys \
     nyktus serve --roles=console
   ```

   `NYKTUS_CONSOLE_URL` is the address under which users reach the console, `NYKTUS_TRIGGER_URL` the public address of the trigger, with which the URLs of [honeytokens](honeytokens.md) start. The file named by `NYKTUS_ENCRYPTION_KEYS_FILE` holds the [encryption keys](configuration.md#encryption-keys). See [Configuration](configuration.md).

   On the first start, the console prints a URL for creating the first administrator. See [First start](first-start.md).

6. Start the trigger with its login role:

   ```sh
   NYKTUS_TRIGGER_DATABASE_URL='postgres://nyktus_trigger_login:...@db/nyktus' \
   NYKTUS_TRIGGER_DEFAULT_REDIRECT='https://www.example.com/' \
     nyktus serve --roles=trigger
   ```

   When the trigger runs on a host of its own, for example in a DMZ, allow the database connections from that host only for the trigger's login role, over TLS.

7. Start the DNS role with its login role, if you use [DNS honeytokens](dns.md):

   ```sh
   NYKTUS_DNS_DATABASE_URL='postgres://nyktus_dns_login:...@db/nyktus' \
   NYKTUS_DNS_ZONES='d.example.net' \
   NYKTUS_DNS_NAMESERVERS='ns1.example.net' \
     nyktus serve --roles=dns
   ```

   The same applies as for the trigger: from its host, allow database connections only for the DNS role's login, over TLS.

8. Start the worker with its login role:

   ```sh
   NYKTUS_WORKER_DATABASE_URL='postgres://nyktus_worker_login:...@db/nyktus' \
     nyktus serve --roles=worker
   ```

   The worker correlates events into [incidents](incidents.md). It listens on no port. Without a worker, events are recorded but never assigned to incidents.

## Privilege check

Outside development, the server refuses to start if a role's login can bypass the privilege separation: if it is a superuser, can bypass row-level security, can create roles or databases, can start replication, is a member of `pg_read_all_data`, `pg_write_all_data`, `pg_read_server_files`, `pg_write_server_files` or `pg_execute_server_program`, or owns the database or the schema. Use the login roles from the setup above, not the owner.

The trigger and the DNS role additionally refuse to start unless their login can execute their recording function and do nothing else: it must not access any table, execute another function, create objects in the schema, or be a member of a role other than `nyktus_trigger` or `nyktus_dns`, even without inheriting from it. This catches, for example, a `NYKTUS_TRIGGER_DATABASE_URL` or `NYKTUS_DNS_DATABASE_URL` that names the login of the console by mistake.

The worker refuses to start unless its login stays within its tables (`events`, `event_jobs`, `incidents` and `alerts`): it must not access any other table, execute a function other than the one that checks technique identifiers, create objects in the schema, or be a member of a role other than `nyktus_worker`. Neither may it hold a privilege that `nyktus_worker` lacks, such as one granted to the login directly. This applies to the trigger and the DNS role as well.
