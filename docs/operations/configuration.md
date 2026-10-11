# Configuration

Nyktus reads its configuration from environment variables once at startup and refuses to start if a value is invalid. It reports every problem at once, so that you can fix the configuration in one pass.

Every variable that holds a secret can instead be read from a file: set the same name with the suffix `_FILE` to the path of the file, for example `NYKTUS_CONSOLE_DATABASE_URL_FILE=/run/secrets/console-db`. A trailing line break in the file is ignored. Setting both forms is an error.

Settings of a server role are only read when the role runs. A process started with `--roles=console` does not need the settings of other roles.

## All commands

| Variable | Default | Description |
|---|---|---|
| `NYKTUS_ENV` | `production` | `production` or `development`. Development relaxes checks that protect a production installation, such as the privilege check of the database roles. Never use it for an installation that holds real data. |
| `NYKTUS_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. Logs are written as JSON to standard error. |

## `nyktus migrate`

| Variable | Default | Description |
|---|---|---|
| `NYKTUS_DATABASE_URL` | required, secret | Connection URL of the owner role that applies migrations. See [Database setup](database.md). |

## `nyktus serve`

| Variable | Default | Description |
|---|---|---|
| `NYKTUS_TRUSTED_PROXIES` | empty | Comma-separated address ranges of your reverse proxies in CIDR notation, such as `10.0.0.0/8,2001:db8::/48`. A single address stands for itself. See [Client addresses](#client-addresses). |

### Role `console`

| Variable | Default | Description |
|---|---|---|
| `NYKTUS_CONSOLE_ADDR` | `127.0.0.1:8080` | Address and port the console listens on. |
| `NYKTUS_CONSOLE_URL` | required; in development `http://` and the listen address | Address under which users reach the console, usually through your reverse proxy, such as `https://nyktus.example.com`. Links that the console hands out, such as the [setup URL](first-start.md) and [activation and password reset links](users.md), start with it. Scheme, host and port only: `https` is required, `http` is allowed in development. |
| `NYKTUS_CONSOLE_DATABASE_URL` | required, secret | Connection URL of the console's login role. See [Database setup](database.md). |
| `NYKTUS_SESSION_IDLE_TIMEOUT` | `1h` | A session ends after this long without a request. Between `5m` and `24h`. See [Sign-in and sessions](sign-in.md). |
| `NYKTUS_SESSION_MAX_AGE` | `12h` | A session ends this long after sign-in, however active it is. Between the idle timeout and `720h` (30 days). |

## `nyktus admin`

The admin commands, such as [`nyktus admin reset-password`](users.md#when-no-administrator-can-sign-in), use the settings of the console: `NYKTUS_CONSOLE_DATABASE_URL` and `NYKTUS_CONSOLE_URL`, and `NYKTUS_CONSOLE_ADDR` for the default of the URL in development.

## Client addresses

Nyktus records the address of the client in the audit log. By default, it uses the address of the connection. Behind a reverse proxy, that is the address of the proxy.

List the addresses of your reverse proxies in `NYKTUS_TRUSTED_PROXIES`. For a connection from one of these addresses, Nyktus reads the `X-Forwarded-For` header from right to left, skips the addresses of trusted proxies and takes the first other address as the client. A chain of several proxies works as long as all of them are listed. Entries may carry a port, such as `192.0.2.1:4711` or `[2001:db8::1]:4711`. `X-Real-IP` is ignored.

- Configure each proxy to append the address it received the request from to `X-Forwarded-For`, which most proxies do by default. A proxy that replaces the header instead also works.
- List only proxies that you operate. A client that connects directly, bypassing the proxy, cannot set its own address, because Nyktus only reads the header from trusted addresses.
- Ranges must be written in their canonical form: `10.0.0.0/8`, not `10.0.0.1/8`. Write IPv4 ranges in IPv4 notation, not as `::ffff:10.0.0.0/104`.
