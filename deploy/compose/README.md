# Reference installation with Docker Compose

This directory runs Nyktus on one host: PostgreSQL, the migrations, the server roles and an nginx that serves the console over HTTPS. It is a starting point for an installation that holds real data, unlike `deploy/dev`, whose passwords are public. The [operations documentation](https://docs.nyktus.org) explains every setting.

| Service | Role |
|---|---|
| `db` | PostgreSQL 16. No published port. |
| `migrate` | Applies the migrations, then ends. Runs again with every `up`. |
| `console` | API and web console. Reached through `proxy` only. |
| `worker` | Incidents and alerts. A process of its own, so that none holds the database logins of two roles. |
| `trigger` | Answers the URLs of honeytokens. Published on `127.0.0.1:8081`. |
| `dns` | Name server for DNS honeytokens (profile `dns`). |
| `proxy` | nginx, HTTPS for the console. |
| `trigger-proxy` | nginx, HTTPS for the trigger (profile `trigger-proxy`). |

The sensor does not belong here, it runs in the networks that Nyktus watches. See `sensor.compose.yaml`.

Every Nyktus service runs as a user without root, with a read-only file system, without capabilities and with `no-new-privileges`. Each server role connects to the database with a login of its own.

## Start

1. Copy `.env.example` to `.env`, set the host names and addresses, and fill in the secrets. The file names a command for each. Keep `.env` readable by your administrator only.
2. Create the directories for the certificates and the ACME challenge:

   ```sh
   mkdir -p certs/console certs/trigger acme
   ```

3. Put the certificate chain and the key of each host name into `certs/<service>/fullchain.pem` and `privkey.pem`, see [Certificates](#certificates).
4. Start:

   ```sh
   docker compose up --detach
   ```

5. Open the setup URL that the console printed and create the first administrator. It carries its token in the fragment, so it appears in the logs of the container, never in a request:

   ```sh
   docker compose logs console | grep -o 'https://[^ ]*/setup#token=[^ ]*'
   ```

   Treat it like a password until you have used it.

## Certificates

The proxies read `certs/console/` and `certs/trigger/` read-only. `fullchain.pem` holds the certificate and the intermediates, `privkey.pem` the key. The user of the proxy has the ID 101: make the key readable for the group 101 and for no one else, for example `sudo chown root:101 privkey.pem && sudo chmod 0640 privkey.pem`.

There is no ACME client in this file, to keep the installation small. Use one of these:

- **Certbot on the host**, with the webroot method. Both proxies answer `/.well-known/acme-challenge/` on port 80 from `./acme`:

  ```sh
  certbot certonly --webroot --webroot-path "$PWD/acme" --domain nyktus.example.com
  ```

  Copy or link the files of `/etc/letsencrypt/live/<name>/` to `certs/console/`, and reload the proxy after each renewal with `docker compose exec proxy nginx -s reload`. The challenge needs the port 80 of the host name to reach the proxy, which the console does not allow from the internet. For an internal console, use the DNS method of your ACME client, or the certificate of your own authority.
- **A certificate of your own authority**, in the same two files.
- **For a test, a self-signed certificate:**

  ```sh
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
    -keyout certs/console/privkey.pem -out certs/console/fullchain.pem \
    -subj "/CN=nyktus.example.com" -addext "subjectAltName=DNS:nyktus.example.com"
  curl --cacert certs/console/fullchain.pem --resolve nyktus.example.com:443:127.0.0.1 https://nyktus.example.com/livez
  ```

TLS 1.2 and 1.3 only, with the ECDHE suites of the "intermediate" profile of the [Mozilla server-side TLS guidelines](https://wiki.mozilla.org/Security/Server_Side_TLS), HTTP/2, no session tickets. Browsers are told to use HTTPS for a year (`Strict-Transport-Security` without `includeSubDomains` and `preload`: the first would bind every other host under the domain, the second is hard to undo).

## The console

`NYKTUS_CONSOLE_URL` must be exactly the address that users open in the browser. The console keeps your administrators out of the internet: set `NYKTUS_CONSOLE_BIND` to an internal address of the host.

The proxy limits the sign-in routes to 10 requests a minute per client address (burst 5), and everything else to 30 requests a second. It sets `X-Forwarded-For` to the address of the connection and removes the other forwarding headers that a client sent, so a client cannot choose its address in the audit log. If another load balancer sits in front, it must append its client to the header instead, and you must list it in `NYKTUS_TRUSTED_PROXIES` of `compose.yaml`. The console sets its security headers itself (content security policy and the rest), the proxy only adds HSTS. The access log holds the path of a request, never its query string.

## The trigger

The trigger is the role that the internet reaches. Choose one:

- **A proxy of your own.** The trigger listens on `127.0.0.1:8081`.
- **`trigger-proxy`.** Add the profile (`COMPOSE_PROFILES=trigger-proxy` in `.env`), set `NYKTUS_TRIGGER_HOST` and `NYKTUS_TRIGGER_PROXY_BIND` to an address of the host that the proxy of the console does not use, and put the certificate of the trigger host into `certs/trigger/`.

This proxy must not give the trigger away. It logs nothing about requests, because the path of a request is the value of a honeytoken. Where it answers on its own, it answers as the trigger would: a trigger that does not respond leads to the redirect of `NYKTUS_TRIGGER_DEFAULT_REDIRECT` with an empty body; a `POST` that is too large to buffer is passed on; a malformed request gets the plain text of Go. What stays different: nginx adds `Server: nginx` and cannot be told not to without a module that stock nginx lacks, and the reason phrase of the status line of an HTTP/1.1 answer is that of nginx (`Moved Temporarily`).

## DNS honeytokens

Add the profile `dns` (`COMPOSE_PROFILES=dns`), set the zones, name servers and the answer address in `.env`, and delegate the zone to the host as the documentation describes. The role listens on port 8053 in the container, so it needs no capability, and Docker publishes port 53 for UDP and TCP. Do not put a resolver or a load balancer in front that changes the source address: the event records the address that sent the query.

## Alert channels by mail

Add the `NYKTUS_SMTP_*` settings of the documentation to the `environment` of the `worker`.

## Upgrade

```sh
docker compose pull          # after changing NYKTUS_VERSION in .env
docker compose up --detach   # migrate runs first
```

A migration never edits an applied one. Back up before an upgrade.

## Backup

The database holds everything, and `.env` holds the key that decrypts the stored secrets. Keep a copy of the key elsewhere.

```sh
docker compose exec -T db pg_dump --username postgres --format custom nyktus > nyktus-$(date +%F).dump
```

To restore into an empty installation, start only `db`, then `docker compose exec -T db pg_restore --username postgres --clean --if-exists --dbname nyktus < nyktus-<date>.dump`, and start the rest.

## Check the images

Releases are signed by the release workflow with its identity, without a key to manage (cosign, keyless):

```sh
cosign verify ghcr.io/nyktus/nyktus:0.1.0 \
  --certificate-identity-regexp '^https://github.com/Nyktus/nyktus/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

For the sensor, the identity ends with `@refs/tags/sensor/v`. Pin the digest that it prints in your copy of the compose file (`image: ghcr.io/nyktus/nyktus:0.1.0@sha256:…`).

## Logs

The containers log to standard output and standard error as JSON, and Docker keeps five files of 10 MB each per container. The console prints the setup URL, which holds a token, until the first administrator exists; the logs of the container therefore need the care of a secret until then.
