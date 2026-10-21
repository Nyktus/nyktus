# Configuration

Nyktus reads its configuration from environment variables once at startup and refuses to start if a value is invalid. It reports every problem at once, so that you can fix the configuration in one pass.

Every variable that holds a secret can instead be read from a file: set the same name with the suffix `_FILE` to the path of the file, for example `NYKTUS_CONSOLE_DATABASE_URL_FILE=/run/secrets/console-db`. A trailing line break in the file is ignored. Setting both forms is an error.

Settings of a server role are only read when the role runs. A process started with `--roles=console` does not need the settings of other roles. `nyktus serve` requires `--roles`, a comma-separated list of `console`, `trigger`, `dns` and `worker`: some roles listen on the internet, so a process never starts a role that nobody asked for. A process that runs several roles needs the settings of each.

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
| `NYKTUS_ENCRYPTION_KEYS` | required with the roles `console` and `worker`, secret, also in development | Keys that encrypt secrets stored in the database. Set the same keys for both roles. See [Encryption keys](#encryption-keys). |
| `NYKTUS_ALERTING_ALLOWED_NETWORKS` | empty | Comma-separated internal networks in CIDR notation, such as `10.20.0.0/16`, that [alert channels](alerting.md#allowed-targets) may reach in addition to public addresses. Loopback, link-local and cloud metadata addresses stay blocked. Read by the console, which checks the targets of channels, and the worker, which connects to them; set the same list for both. |

### Role `console`

| Variable | Default | Description |
|---|---|---|
| `NYKTUS_CONSOLE_ADDR` | `127.0.0.1:8080` | Address and port the console listens on. |
| `NYKTUS_CONSOLE_URL` | required; in development `http://` and the listen address | Address under which users reach the console, usually through your reverse proxy, such as `https://nyktus.example.com`. Links that the console hands out, such as the [setup URL](first-start.md) and [activation and password reset links](users.md), start with it. Scheme, host and port only: `https` is required, `http` is allowed in development. |
| `NYKTUS_CONSOLE_DATABASE_URL` | required, secret | Connection URL of the console's login role. See [Database setup](database.md). |
| `NYKTUS_TRIGGER_URL` | required, also in development | Public address of the trigger, such as `https://t.example.net`. The URL of a [honeytoken](honeytokens.md) is this address followed by its trigger value, so it is what an attacker sees. Scheme, host and port only: `https` is required, `http` is allowed in development. Its host must differ from that of `NYKTUS_CONSOLE_URL`; in development, a different port suffices. See [Choosing the address of the trigger](honeytokens.md#choosing-the-address-of-the-trigger). |
| `NYKTUS_DNS_ZONES` | empty | The zones of the [DNS role](dns.md), as for the role `dns`. The console shows the names of DNS honeytokens under them; without zones, it refuses to create DNS honeytokens. No zone may hold the host of `NYKTUS_CONSOLE_URL` or `NYKTUS_TRIGGER_URL`. |
| `NYKTUS_SESSION_IDLE_TIMEOUT` | `1h` | A session ends after this long without a request. Between `5m` and `24h`. See [Sign-in and sessions](sign-in.md). |
| `NYKTUS_SESSION_MAX_AGE` | `12h` | A session ends this long after sign-in, however active it is. Between the idle timeout and `720h` (30 days). |
| `NYKTUS_LOCAL_LOGIN` | `admins` with an identity provider, `all` otherwise | Which accounts sign in with a password: `all`, `admins` or `off`. `admins` and `off` require an identity provider. See [Sign-in and sessions](sign-in.md#password-sign-in-with-an-identity-provider). |

### Role `trigger`

The trigger answers the URLs of [honeytokens](honeytokens.md) and records their requests. It also accepts the [reports](honeypots.md#how-a-sensor-reports) of sensors, a `POST` to `/` with the secret of a honeypot, and answers them like every other request. It is reached from the internet, usually through your reverse proxy, and sensors reach it from the monitored networks over TLS. Its public address, `NYKTUS_TRIGGER_URL`, is a setting of the console, which hands out the URLs; the trigger answers every host name. The sensor is configured with a file of its own, not with these variables; see [Sensor](sensor.md#configuration).

| Variable | Default | Description |
|---|---|---|
| `NYKTUS_TRIGGER_ADDR` | `127.0.0.1:8081` | Address and port the trigger listens on. |
| `NYKTUS_TRIGGER_DATABASE_URL` | required, secret | Connection URL of the trigger's login role. See [Database setup](database.md). |
| `NYKTUS_TRIGGER_DEFAULT_REDIRECT` | required | Where the trigger sends a client that it does not send to the `redirect_url` of a honeytoken, such as `https://www.example.com/`: requests of unknown URLs, of `/` and other paths, and requests it failed to record. The same rules as for `redirect_url` apply: a host name, not an IP address, no user information, at most 2048 characters. `https` is required, `http` is allowed in development. There is no default, because a target built into Nyktus would be the same in every installation and give the trigger away. Choose a public page outside Nyktus: a target on the host of the trigger would redirect in a loop, and one on the host of the console would lead every visitor of the trigger to it. See [What the trigger answers](honeytokens.md#what-the-trigger-answers). |

### Role `dns`

The DNS role answers the zones delegated to it as an authoritative name server and records the queries of [DNS honeytokens](dns.md). It is reached from the internet on port 53, usually through a port mapping of the container.

| Variable | Default | Description |
|---|---|---|
| `NYKTUS_DNS_ADDR` | `127.0.0.1:8053` | Address and port the DNS role listens on, over UDP and TCP. |
| `NYKTUS_DNS_DATABASE_URL` | required, secret | Connection URL of the DNS role's login role. See [Database setup](database.md). |
| `NYKTUS_DNS_DATABASE_MAX_CONNS` | `10` | Connections of the DNS role to the database, between 1 and 100, and with them the queries it records at a time. The DNS role answers first and queues up to 1024 queries for recording. Raise it only if the log shows `dns: queries not recorded` with `reason` `queue_full` without a flood, and allow the connections in PostgreSQL. |
| `NYKTUS_DNS_ZONES` | required | Comma-separated zones to answer, such as `d.example.net,cdn-assets.example.org`. A DNS honeytoken has its trigger value as a name under each of them. A zone must not contain another. Set the same list for the console. See [Zones](dns.md#zones). |
| `NYKTUS_DNS_NAMESERVERS` | required | Comma-separated host names of the name servers of the zones, at most 8, such as `ns1.example.net`. The answers name them in NS and SOA records. They must lie outside the zones. |
| `NYKTUS_DNS_ANSWER_IPV4` | none | The IPv4 address with which every name of the zones resolves. Without it, names have no IPv4 address. There is no default, because an address built into Nyktus would identify it. |
| `NYKTUS_DNS_ANSWER_IPV6` | none | The IPv6 address with which every name of the zones resolves. |
| `NYKTUS_DNS_TTL` | `1m` | How long resolvers may cache an answer, also a negative one, in whole seconds between `0s` and `1h`. See [Caching](dns.md#caching). |

### Role `worker`

The worker correlates the events of honeytokens into [incidents](incidents.md) and delivers their [alerts](alerting.md). It listens on no port; it connects to the database and to the receivers of the alert channels. Run at least one worker; several workers share the work without further setup.

| Variable | Default | Description |
|---|---|---|
| `NYKTUS_WORKER_DATABASE_URL` | required, secret | Connection URL of the worker's login role. See [Database setup](database.md). |
| `NYKTUS_WORKER_CONCURRENCY` | `4` | Events that the worker processes at a time, between 1 and 32. Each holds a connection to the database while it is processed. |
| `NYKTUS_WORKER_DELIVERY_CONCURRENCY` | `4` | Alerts that the worker delivers at a time, between 1 and 32. A delivery holds a connection to the database only while it records an attempt, not while it waits for the receiver. The worker opens up to both values together of connections. |
| `NYKTUS_CONSOLE_URL` | required; in development `http://127.0.0.1:8080` | The address of the console, as for the role `console`. Alerts link their incident under it. |
| `NYKTUS_AUDIT_RETENTION_DAYS` | `365` | Days that the [audit log](audit-log.md#retention) keeps an entry, between 90 and 3650. |
| `NYKTUS_INCIDENT_AUTO_CLOSE_DAYS` | `14` | Days without a new event after which the worker [closes an incident](incidents.md#closing-inactive-incidents), between 1 and 365, or `0` to close incidents only by triage. |
| `NYKTUS_EVENT_RETENTION_DAYS` | `180` | Days that [events](incidents.md#retention) are kept after they were recorded, and closed incidents with their alerts and deliveries after they closed, between 30 and 3650. |

### Mail

`NYKTUS_SMTP_HOST` enables the SMTP server through which the worker sends the mail of [alert channels of the type `email`](alerting.md#mail). The other settings are rejected without it. Only the worker reads them; the console accepts channels of the type `email` without them, and their deliveries are dead until the worker has a server.

| Variable | Default | Description |
|---|---|---|
| `NYKTUS_SMTP_HOST` | empty | Host name or IP address of the SMTP server, such as `smtp.example.com`. An internal relay may have a name of a single label. |
| `NYKTUS_SMTP_TLS` | `starttls` | `starttls` connects in plain text and switches to TLS before anything else is sent, `tls` speaks TLS from the start. `none` sends in plain text and is allowed in development only, for a local mail catcher. |
| `NYKTUS_SMTP_PORT` | `587` with `starttls`, `465` with `tls`, `25` with `none` | Port of the server. |
| `NYKTUS_SMTP_USERNAME` | empty | User with which the worker authenticates, with `AUTH PLAIN` or, where the server offers only that, `AUTH LOGIN`. Leave it empty for a relay that admits the worker without authentication. |
| `NYKTUS_SMTP_PASSWORD` | required with the username, secret | Password of the user. |
| `NYKTUS_SMTP_FROM` | required with the host | Address that the mail is sent from, such as `nyktus@example.com`, without display name. Its domain also completes the `Message-ID` of every mail. |

The worker greets the server with the name of its host. It verifies the certificate of the server against the roots of the system, with TLS 1.2 or later; there is no setting to turn the check off. For a server with a certificate of a private authority, add the authority with the variables `SSL_CERT_FILE` or `SSL_CERT_DIR` of Go. The server is chosen by the operator and is often internal, so the worker reaches it without the checks of [allowed targets](alerting.md#allowed-targets) and `NYKTUS_ALERTING_ALLOWED_NETWORKS`, and ignores `HTTP_PROXY` and `HTTPS_PROXY`.

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

Secrets that Nyktus must read back, such as the secrets of second factors and the URLs of [alert channels](alerting.md), are stored encrypted with AES-256-GCM. The keys never reach the database, so a copy of the database alone does not reveal the secrets. Keep a copy of the keys in your secret store: without them, the encrypted secrets are lost.

`NYKTUS_ENCRYPTION_KEYS` holds a comma-separated list of keys, each written as `<id>:<key>`. The ID is a number from 1 to 255 that is stored with every encrypted value. The key is 32 random bytes in standard base64. Generate one with:

```sh
echo "1:$(openssl rand -base64 32)"
```

The keys are required in development as well. Nyktus neither derives a key from another secret nor generates one at startup, because either would make the stored secrets unreadable once that secret or the process changes.

To replace a key, put a new key with an unused ID first and keep the old one behind it, such as `2:<new key>,1:<old key>`. The first key encrypts new values; every listed key decrypts. The secret of a second factor is encrypted again with the first key the next time its user enters a code, and the secrets of an [alert channel](alerting.md#encryption-keys) the next time the worker delivers to it. Keep the old key listed: a value encrypted with a key that is no longer listed cannot be decrypted, so the console and the worker refuse to start while the database holds such a value, and name the ID of the missing key. To retire an old key that some accounts still use, remove their second factor, and let them set it up again.

## Client addresses

Nyktus records the address of the client in the audit log and in the events of honeytokens. By default, it uses the address of the connection. Behind a reverse proxy, that is the address of the proxy.

List the addresses of your reverse proxies in `NYKTUS_TRUSTED_PROXIES`. For a connection from one of these addresses, Nyktus reads the `X-Forwarded-For` header from right to left, skips the addresses of trusted proxies and takes the first other address as the client. A chain of several proxies works as long as all of them are listed. Entries may carry a port, such as `192.0.2.1:4711` or `[2001:db8::1]:4711`. `X-Real-IP` is ignored.

- Configure each proxy to append the address it received the request from to `X-Forwarded-For`, which most proxies do by default. A proxy that replaces the header instead also works.
- List only proxies that you operate. A client that connects directly, bypassing the proxy, cannot set its own address, because Nyktus only reads the header from trusted addresses.
- Ranges must be written in their canonical form: `10.0.0.0/8`, not `10.0.0.1/8`. Write IPv4 ranges in IPv4 notation, not as `::ffff:10.0.0.0/104`.
