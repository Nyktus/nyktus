# Sign-in and sessions

Users sign in to the console with their email address and password, and with a code if they set up a [second factor](#second-factor). A successful sign-in starts a session, which the browser keeps in a cookie.

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
- Changing or resetting the password, enabling or removing the second factor, deactivating the account or changing its role ends its sessions. See [Managing accounts](users.md).
- Integrations use [API keys](api-keys.md) instead of sessions.

## Reverse proxy

- `NYKTUS_CONSOLE_URL` must be exactly the address that users open in the browser, including the port if it is not the default. Requests that change state, such as a sign-in, are rejected with `403` if the browser reports another origin. This protects sessions against requests from other sites, including pages on other subdomains of your domain.
- Pass the `Origin` header to the console unchanged.
- Rate-limit the sign-in endpoints `POST /api/v1/session` and `POST /api/v1/session/second-factor` and the endpoints `POST /api/v1/activation` and `POST /api/v1/password-reset` at the proxy, per client address.

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
- An open password reset link of the account stops working.
- A wrong current password receives `403` with the code `wrong_password` and counts as a failed sign-in. While the account is locked, the change is refused; only a request with the correct current password learns about the lock.
- Only a session can change the password.

A user who forgot the password receives a reset link from an administrator, see [Managing accounts](users.md#resetting-a-password).

## Second factor

Every account can add a second factor: a time-based one-time password (TOTP, RFC 6238) from an authenticator app, such as those of password managers or phones. It is optional, but recommended for every account and in particular for administrators.

### Setting it up

1. Start the setup with the password, written into a file as for the change of password (`{"password": "..."}`):

   ```sh
   curl --fail-with-body https://nyktus.example.com/api/v1/session/totp \
     --header 'Content-Type: application/json' \
     --data @password.json --cookie cookies.txt
   ```

   The answer contains the secret in base32 and an `otpauth://` URI, which the web console shows as a QR code. Add one of them to the authenticator app. They are shown only once.
2. Confirm within ten minutes with the code that the app shows:

   ```sh
   curl --fail-with-body https://nyktus.example.com/api/v1/session/totp/confirmation \
     --header 'Content-Type: application/json' \
     --data '{"code": "123456"}' \
     --cookie cookies.txt --cookie-jar cookies.txt
   ```

   A wrong code answers `403` with the code `wrong_code` and counts as a failed sign-in. The answer contains ten **recovery codes**, such as `abcd-efgh-ijkl-mnop`. Each one signs in once in place of a code. They are shown only once: store them outside the device of the authenticator app, for example in a password manager or on paper.

Confirming the factor ends every other session of the account, which began without it, and sets a new session cookie for the session that confirmed it.

### Signing in

With a second factor, the correct password answers `202` instead of starting a session, and sets the cookie `__Host-nyktus_challenge`. The sign-in is completed within five minutes with a code or a recovery code:

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/session/second-factor \
  --header 'Content-Type: application/json' \
  --data '{"code": "123456"}' \
  --cookie cookies.txt --cookie-jar cookies.txt
```

- A code is accepted from 30 seconds before until 30 seconds after the period in which the app shows it, so that a clock that is slightly off still works. Each code works only once, and so does each recovery code. Keep the clock of the server synchronized, for example with NTP; codes are checked against the clock of the database.
- A wrong code answers `401` with the code `invalid_code`, and the user can try again. An expired or used challenge answers `401` with the code `invalid_challenge`, and the user signs in again with the password.
- A change of password, a reset, the removal of the factor, a change of role and the deactivation end every sign-in that waits for its code.

### Recovery codes and removal

- `POST /api/v1/session/totp/recovery-codes` replaces the recovery codes with ten new ones. It takes the password and a code or a recovery code, as `{"password": "...", "code": "123456"}` or `{"password": "...", "recovery_code": "..."}`.
- `DELETE /api/v1/session/totp` with the same body removes the factor and the recovery codes. Every session of the account ends; the answer sets a new session cookie for the session that removed it.
- A wrong password answers `403` with the code `wrong_password`, a wrong code `403` with the code `wrong_code`. Both count as failed sign-ins.
- Only a session can manage the second factor.

A user who lost the authenticator and the recovery codes asks an administrator to remove the factor, see [Managing accounts](users.md#removing-a-second-factor).

### Encryption of the secrets

The database stores the secrets of the factors encrypted with the [encryption keys](configuration.md#encryption-keys) and the recovery codes only as hashes. Keep the keys in your secret store: without them, every user with a second factor has to have it removed and set up again.

## Failed sign-ins

- A failed sign-in never tells whether the account exists: unknown addresses, wrong passwords and accounts that may not sign in all receive the same answer.
- Five failed sign-ins in a row lock the account for 15 minutes. Wrong codes of the second factor count as well, and so do a wrong current password when changing the password and a wrong password or code when managing the second factor. The count starts again only after a complete sign-in: the correct password alone does not reset it while the code is missing. A lock blocks the sign-in, not existing sessions. Only a sign-in with the correct password learns about the lock, and when it ends. A lock that a wrong code triggers ends the sign-in that waits for the code. Failures during the lock do not extend it.
- The lock limits how fast codes can be guessed, but does not end the guessing: whoever knows the password can try five codes every 15 minutes. Watch the [audit log](audit-log.md) for repeated failures of `session.create` with the method `totp`, and change the password of an account that shows them.
- Anyone who can reach the sign-in can lock an account, including the only administrator, for 15 minutes at a time. Keep the console off the public internet and rate-limit sign-ins at the proxy to make this harder.
- Every sign-in and change of password, successful or not, and every sign-out is recorded in the [audit log](audit-log.md) with the client address. A failure for an unknown address does not record the address. With a second factor, the correct password is recorded as `sign_in_challenge.create`, and the second step as `session.create` with the method `totp` or `recovery_code`. The setup, confirmation and removal of a factor and new recovery codes are recorded as `user.totp_enroll`, `user.totp_enable`, `user.totp_disable` and `user.recovery_codes_create`.

## When the server is busy

Password hashing needs 64 MiB of memory per operation, so the number of concurrent operations is limited. A request that hashes a password, such as a sign-in, setup, activation, password change or reset, and cannot be served within 10 seconds receives `503 Service Unavailable` with a `Retry-After` header.
