# Sign-in and sessions

Users sign in to the console with their email address and password. A successful sign-in starts a session, which the browser keeps in a cookie.

To sign in without the web console, for example to check the installation, send the address and password to the API and keep the cookie:

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/session \
  --header 'Content-Type: application/json' \
  --data @credentials.json \
  --cookie-jar cookies.txt
```

## Sessions

- A session ends after a period without requests (`NYKTUS_SESSION_IDLE_TIMEOUT`, default one hour) and at the latest after its maximum age (`NYKTUS_SESSION_MAX_AGE`, default 12 hours), and when the user signs out. See [Configuration](configuration.md).
- The cookie `__Host-nyktus_session` is `Secure`, `HttpOnly` and `SameSite=Strict`. The console must therefore be reached over HTTPS. Browsers also accept the cookie on `http://localhost` and `http://127.0.0.1` during development.
- The database stores only a hash of the session token. Signing in again ends the session that the browser held before.
- Deactivating an account or changing its role ends its sessions. See [Managing accounts](users.md).

## Reverse proxy

- `NYKTUS_CONSOLE_URL` must be exactly the address that users open in the browser, including the port if it is not the default. Requests that change state, such as a sign-in, are rejected with `403` if the browser reports another origin. This protects sessions against requests from other sites, including pages on other subdomains of your domain.
- Pass the `Origin` header to the console unchanged.
- Rate-limit the sign-in endpoint `POST /api/v1/session` and the activation endpoint `POST /api/v1/activation` at the proxy, per client address.

## Failed sign-ins

- A failed sign-in never tells whether the account exists: unknown addresses, wrong passwords and accounts that may not sign in all receive the same answer.
- Five failed sign-ins in a row lock the account for 15 minutes. Only a sign-in with the correct password learns about the lock, and when it ends. Failures during the lock do not extend it.
- Anyone who can reach the sign-in can lock an account, including the only administrator, for 15 minutes at a time. Keep the console off the public internet and rate-limit sign-ins at the proxy to make this harder.
- Every sign-in, successful or not, and every sign-out is recorded in the [audit log](audit-log.md) with the client address. A failure for an unknown address does not record the address.

## When the server is busy

Password hashing needs 64 MiB of memory per operation, so the number of concurrent operations is limited. A sign-in or setup request that cannot be served within 10 seconds receives `503 Service Unavailable` with a `Retry-After` header.
