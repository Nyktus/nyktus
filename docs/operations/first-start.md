# First start

A new installation has no accounts. The first administrator is created through a setup URL that only the operator of the server can see. There is no public registration: without the URL, whoever reached a fresh installation first could claim it.

## Before you start

1. Set up the database and apply the migrations as described in [Database setup](database.md).
2. Set `NYKTUS_CONSOLE_URL` to the address under which users reach the console, such as `https://nyktus.example.com`. The setup URL starts with it. See [Configuration](configuration.md).
3. Set `NYKTUS_TRIGGER_URL` to the public address of the trigger, such as `https://t.example.net`. The URLs of [honeytokens](honeytokens.md) start with it.
4. Generate the [encryption keys](configuration.md#encryption-keys) and set `NYKTUS_ENCRYPTION_KEYS` or `NYKTUS_ENCRYPTION_KEYS_FILE`.
5. For the trigger, which answers the URLs of honeytokens, set `NYKTUS_TRIGGER_DATABASE_URL` and `NYKTUS_TRIGGER_DEFAULT_REDIRECT`. See [Configuration](configuration.md#role-trigger).
6. Optionally, for DNS honeytokens, delegate a zone to Nyktus and set `NYKTUS_DNS_ZONES` for the console and the DNS role. See [DNS honeytokens](dns.md).

`nyktus serve` needs `--roles`, a comma-separated list of the roles to run: `console`, `trigger`, `dns` and `worker`. The steps below start the console alone with `--roles=console`. `--roles=console,worker` runs the console and the [worker](incidents.md), which correlates events into incidents, in one process; start the trigger and the DNS role alone, with `--roles=trigger` and `--roles=dns`, where they run on a host of their own.

## Create the first administrator

1. Start the console:

   ```sh
   nyktus serve --roles=console
   ```

   As long as no administrator exists, the console prints a setup URL to standard output every time it starts, once it is listening for requests:

   ```
   Nyktus has no administrator yet. Create the first one with the setup token in the
   following URL, as described in "First start" in the operations documentation.
   The token is valid until 2026-10-10T19:00:00Z. Restart Nyktus to get a new one.

       https://nyktus.example.com/setup#token=...
   ```

   The log, which goes to standard error, only records `console: setup pending` with the expiry time, never the URL. In a container, both streams usually end up in the container log, for example in `docker logs`.

2. Create the administrator with the token from the URL, the part after `#token=`. Send a request to the setup endpoint of the console API. Put the request into a file that only you can read, so that the password does not appear in your shell history:

   ```json
   {
     "token": "<token from the setup URL>",
     "email": "admin@example.com",
     "display_name": "Ada Admin",
     "password": "<at least 12 characters>"
   }
   ```

   ```sh
   curl --fail-with-body https://nyktus.example.com/api/v1/setup \
     --header 'Content-Type: application/json' \
     --data @setup.json
   rm setup.json
   ```

   A successful request answers with `201 Created` and the new account. The administrator is active and [signs in](sign-in.md) with the email address and the password. Further accounts are created by administrators, see [Managing accounts](users.md).

The password must have between 12 and 128 characters. The email address is stored in lower case.

## How the setup is protected

- **One hour, once.** A setup URL is valid for one hour and can be used once. If it expires, restart the console to get a new one.
- **Several console processes.** Every console process issues its own URL when it starts. Each of them works until it expires, so the setup also works behind a load balancer. Concurrent requests never create more than one administrator.
- **Closed for good.** Once an administrator exists, the console issues no more setup URLs, and the setup endpoint answers every request with the same response as a route that does not exist, also after a restart. The last active administrator cannot be demoted, deactivated or deleted, so the setup does not open again.
- **Nothing to learn without the token.** A well-formed request with an unknown, expired or used token receives the same answer as a route that does not exist. The fields of the request are only checked for a valid token.
- **The token stays out of logs.** It is placed in the fragment of the URL, the part after `#`. Browsers never send the fragment to a server, so it does not appear in the access logs of the console or of a reverse proxy. The database stores only a SHA-256 hash of the token.
- **Audit.** The creation of the administrator is recorded in the [audit log](audit-log.md) with the client address and the setup token as the means of authentication.

Treat the setup URL like a password until it has been used or has expired. Anyone who can read the standard output of the console in that time, for example through a central log collection, can use it.
