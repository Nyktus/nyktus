# Configuration

Nyktus reads its configuration from environment variables once at startup and refuses to start if a value is invalid. It reports every problem at once, so that you can fix the configuration in one pass.

Every variable that holds a secret can instead be read from a file: set the same name with the suffix `_FILE` to the path of the file, for example `NYKTUS_CONSOLE_DATABASE_URL_FILE=/run/secrets/console-db`. A trailing line break in the file is ignored. Setting both forms is an error.

Settings of a server role are only read when the role runs. A process started with `--roles=console` does not need the settings of other roles. `nyktus serve` without `--roles` runs every role, `console` and `trigger`, and needs the settings of both.

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
| `NYKTUS_ENCRYPTION_KEYS` | required with the role `console`, secret, also in development | Keys that encrypt secrets stored in the database. See [Encryption keys](#encryption-keys). |

### Role `console`

| Variable | Default | Description |
|---|---|---|
| `NYKTUS_CONSOLE_ADDR` | `127.0.0.1:8080` | Address and port the console listens on. |
| `NYKTUS_CONSOLE_URL` | required; in development `http://` and the listen address | Address under which users reach the console, usually through your reverse proxy, such as `https://nyktus.example.com`. Links that the console hands out, such as the [setup URL](first-start.md) and [activation and password reset links](users.md), start with it. Scheme, host and port only: `https` is required, `http` is allowed in development. |
| `NYKTUS_CONSOLE_DATABASE_URL` | required, secret | Connection URL of the console's login role. See [Database setup](database.md). |
| `NYKTUS_TRIGGER_URL` | required, also in development | Public address of the trigger, such as `https://t.example.net`. The URL of a [honeytoken](honeytokens.md) is this address followed by its trigger value, so it is what an attacker sees. Scheme, host and port only: `https` is required, `http` is allowed in development. Its host must differ from that of `NYKTUS_CONSOLE_URL`; in development, a different port suffices. See [Choosing the address of the trigger](honeytokens.md#choosing-the-address-of-the-trigger). |
| `NYKTUS_SESSION_IDLE_TIMEOUT` | `1h` | A session ends after this long without a request. Between `5m` and `24h`. See [Sign-in and sessions](sign-in.md). |
| `NYKTUS_SESSION_MAX_AGE` | `12h` | A session ends this long after sign-in, however active it is. Between the idle timeout and `720h` (30 days). |
| `NYKTUS_LOCAL_LOGIN` | `admins` with an identity provider, `all` otherwise | Which accounts sign in with a password: `all`, `admins` or `off`. `admins` and `off` require an identity provider. See [Sign-in and sessions](sign-in.md#password-sign-in-with-an-identity-provider). |

### Role `trigger`

The trigger answers the URLs of [honeytokens](honeytokens.md) and records their requests. It is reached from the internet, usually through your reverse proxy. Its public address, `NYKTUS_TRIGGER_URL`, is a setting of the console, which hands out the URLs; the trigger answers every host name.

| Variable | Default | Description |
|---|---|---|
| `NYKTUS_TRIGGER_ADDR` | `127.0.0.1:8081` | Address and port the trigger listens on. |
| `NYKTUS_TRIGGER_DATABASE_URL` | required, secret | Connection URL of the trigger's login role. See [Database setup](database.md). |
| `NYKTUS_TRIGGER_DEFAULT_REDIRECT` | required | Where the trigger sends a client that it does not send to the `redirect_url` of a honeytoken, such as `https://www.example.com/`: requests of unknown URLs, of `/` and other paths, and requests it failed to record. The same rules as for `redirect_url` apply: a host name, not an IP address, no user information, at most 2048 characters. `https` is required, `http` is allowed in development. There is no default, because a target built into Nyktus would be the same in every installation and give the trigger away. Choose a public page outside Nyktus: a target on the host of the trigger would redirect in a loop, and one on the host of the console would lead every visitor of the trigger to it. See [What the trigger answers](honeytokens.md#what-the-trigger-answers). |

### Sign-in through an identity provider

`NYKTUS_OIDC_ISSUER` enables the sign-in through an OpenID Connect provider. The other settings are rejected without it. See [Sign-in and sessions](sign-in.md#identity-provider).

| Variable | Default | Description |
|---|---|---|
| `NYKTUS_OIDC_ISSUER` | empty | URL of the provider, exactly as its tokens name it in the claim `iss`, such as `https://sso.example.com/realms/example`. Nyktus appends `/.well-known/openid-configuration` to find its endpoints. `https` is required, `http` is allowed in development. |
| `NYKTUS_OIDC_CLIENT_ID` | required with the issuer | Client ID of Nyktus at the provider. |
| `NYKTUS_OIDC_CLIENT_SECRET` | required with the issuer, secret | Client secret of Nyktus at the provider. |
| `NYKTUS_OIDC_SCOPES` | `openid email profile` | Space-separated scopes. `openid` is always requested. |
| `NYKTUS_OIDC_GROUPS_CLAIM` | `groups` | Claim of the ID token that lists the groups of the user. |
| `NYKTUS_OIDC_ADMIN_GROUPS` | empty | Comma-separated groups whose members are administrators. |
| `NYKTUS_OIDC_USER_GROUPS` | empty | Comma-separated groups whose members have the role `user`. |
| `NYKTUS_OIDC_VIEWER_GROUPS` | empty | Comma-separated groups whose members are viewers. At least one of the three lists is required. |

The redirect URI is `NYKTUS_CONSOLE_URL` followed by `/api/v1/oidc/callback`. Group names are compared exactly, including case; spaces around the commas are ignored.

## `nyktus admin`

The admin commands, such as [`nyktus admin reset-password`](users.md#when-no-administrator-can-sign-in), use the settings of the console: `NYKTUS_CONSOLE_DATABASE_URL` and `NYKTUS_CONSOLE_URL`, and `NYKTUS_CONSOLE_ADDR` for the default of the URL in development. They do not need the encryption keys.

## Encryption keys

Secrets that Nyktus must read back, such as the secrets of second factors, are stored encrypted with AES-256-GCM. The keys never reach the database, so a copy of the database alone does not reveal the secrets. Keep a copy of the keys in your secret store: without them, the encrypted secrets are lost.

`NYKTUS_ENCRYPTION_KEYS` holds a comma-separated list of keys, each written as `<id>:<key>`. The ID is a number from 1 to 255 that is stored with every encrypted value. The key is 32 random bytes in standard base64. Generate one with:

```sh
echo "1:$(openssl rand -base64 32)"
```

The keys are required in development as well. Nyktus neither derives a key from another secret nor generates one at startup, because either would make the stored secrets unreadable once that secret or the process changes.

To replace a key, put a new key with an unused ID first and keep the old one behind it, such as `2:<new key>,1:<old key>`. The first key encrypts new values; every listed key decrypts. The secret of a second factor is encrypted again with the first key the next time its user enters a code. Keep the old key listed: a value encrypted with a key that is no longer listed cannot be decrypted, so the console refuses to start while the database holds such a value, and names the ID of the missing key. To retire an old key that some accounts still use, remove their second factor, and let them set it up again.

## Client addresses

Nyktus records the address of the client in the audit log and in the events of honeytokens. By default, it uses the address of the connection. Behind a reverse proxy, that is the address of the proxy.

List the addresses of your reverse proxies in `NYKTUS_TRUSTED_PROXIES`. For a connection from one of these addresses, Nyktus reads the `X-Forwarded-For` header from right to left, skips the addresses of trusted proxies and takes the first other address as the client. A chain of several proxies works as long as all of them are listed. Entries may carry a port, such as `192.0.2.1:4711` or `[2001:db8::1]:4711`. `X-Real-IP` is ignored.

- Configure each proxy to append the address it received the request from to `X-Forwarded-For`, which most proxies do by default. A proxy that replaces the header instead also works.
- List only proxies that you operate. A client that connects directly, bypassing the proxy, cannot set its own address, because Nyktus only reads the header from trusted addresses.
- Ranges must be written in their canonical form: `10.0.0.0/8`, not `10.0.0.1/8`. Write IPv4 ranges in IPv4 notation, not as `::ffff:10.0.0.0/104`.
