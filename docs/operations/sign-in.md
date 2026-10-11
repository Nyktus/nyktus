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
- Changing or resetting the password, deactivating the account or changing its role ends its sessions. See [Managing accounts](users.md).

## Reverse proxy

- `NYKTUS_CONSOLE_URL` must be exactly the address that users open in the browser, including the port if it is not the default. Requests that change state, such as a sign-in, are rejected with `403` if the browser reports another origin. This protects sessions against requests from other sites, including pages on other subdomains of your domain.
- Pass the `Origin` header to the console unchanged.
- Rate-limit the sign-in endpoint `POST /api/v1/session` and the endpoints `POST /api/v1/activation` and `POST /api/v1/password-reset` at the proxy, per client address.

## Changing the password

Signed-in users change their own password with the current one. Write both into a file, so that they do not end up in the shell history:

```json
{"current_password": "<the current password>", "new_password": "<12 to 128 characters>"}
```

```sh
curl --fail-with-body --request PUT https://nyktus.example.com/api/v1/session/password \
  --header 'Content-Type: application/json' \
  --data @password.json \
  --cookie cookies.txt --cookie-jar cookies.txt
rm password.json
```

- The change ends every session of the account. The answer sets a new session cookie for the session that made the change, so the user stays signed in.
- A wrong current password receives `403` with the code `wrong_password` and counts as a failed sign-in. While the account is locked, the change is refused; only a request with the correct current password learns about the lock.
- Only a session can change the password.

A user who forgot the password receives a reset link from an administrator, see [Managing accounts](users.md#resetting-a-password).

## Failed sign-ins

- A failed sign-in never tells whether the account exists: unknown addresses, wrong passwords and accounts that may not sign in all receive the same answer.
- Five failed sign-ins in a row lock the account for 15 minutes. A wrong current password when changing the password counts as well. A lock blocks the sign-in, not existing sessions. Only a sign-in with the correct password learns about the lock, and when it ends. Failures during the lock do not extend it.
- Anyone who can reach the sign-in can lock an account, including the only administrator, for 15 minutes at a time. Keep the console off the public internet and rate-limit sign-ins at the proxy to make this harder.
- Every sign-in and change of password, successful or not, and every sign-out is recorded in the [audit log](audit-log.md) with the client address. A failure for an unknown address does not record the address.

## When the server is busy

Password hashing needs 64 MiB of memory per operation, so the number of concurrent operations is limited. A request that hashes a password, such as a sign-in, setup, activation, password change or reset, and cannot be served within 10 seconds receives `503 Service Unavailable` with a `Retry-After` header.
