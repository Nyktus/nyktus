# Sign-in and sessions

Users sign in to the console with their email address and password, and with a code if they set up a [second factor](#second-factor), or through your [identity provider](#identity-provider) with OpenID Connect. A successful sign-in starts a session, which the browser keeps in a cookie.

## The web console

The server serves the web console at the address of `NYKTUS_CONSOLE_URL`; open that address in a browser. The sign-in page offers what the server is set up for, see [What the sign-in page offers](#what-the-sign-in-page-offers): the form for the email address and password, with a second step for the code of an authenticator app or a recovery code, and the button for the identity provider. The language of the console follows the browser, German or English, and can be changed in the header. The pages for the [first start](first-start.md), for the [activation of an account and for the reset of a password](users.md) are part of it as well. The console keeps nothing but the choice of language in the browser; the session is a cookie that scripts cannot read. When the server does not answer as the console asks whether you are signed in, the console does not send you to the sign-in page, because that says nothing about your session: it says so and offers to ask again.

If a page tells you that it was opened at an address other than the one the server expects, open the console at the address of `NYKTUS_CONSOLE_URL`, see [Reverse proxy](#reverse-proxy).

A binary that was built without the web console, as `go build` does, serves the API only and logs a warning when it starts. The releases contain the web console.

To sign in without the web console, for example to check the installation, send the address and password to the API and keep the cookie:

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/session \
  --header 'Content-Type: application/json' \
  --data @credentials.json \
  --cookie-jar cookies.txt
```

## Identity provider

Users can sign in through an OpenID Connect provider, such as Keycloak, Microsoft Entra ID, Okta or Authentik. Nyktus then creates their accounts and takes their roles from their groups at the provider. Set it up as follows:

1. Register Nyktus at the provider as a confidential client with the authorization code flow. Use `https://nyktus.example.com/api/v1/oidc/callback` as redirect URI, with the address of `NYKTUS_CONSOLE_URL`.
2. Let the provider put the groups of the user into the ID token, as a list of strings in the claim `groups` or another one that `NYKTUS_OIDC_GROUPS_CLAIM` names. Nyktus reads claims only from the ID token.
3. Set `NYKTUS_OIDC_ISSUER`, `NYKTUS_OIDC_CLIENT_ID`, `NYKTUS_OIDC_CLIENT_SECRET` and the groups of each role, see [Configuration](configuration.md#sign-in-through-an-identity-provider).
4. Complete the [first start](first-start.md) as usual. The first administrator signs in with a password; the provider cannot create it.

The web console sends the browser to `GET /api/v1/oidc/authorize`, which forwards it to the provider. The provider sends it back to the callback, which starts the session and forwards the browser to the console. A failed sign-in ends on the sign-in page; the reason is written to the log and, if the provider confirmed the user, to the [audit log](audit-log.md).

### Accounts and roles

- An account is created when its user signs in for the first time. It is named by the issuer and the subject of the provider, never by its email address. An account is never linked to an existing one by its address: if another account already has the address of the user, the sign-in is rejected. Delete the other account first if it belongs to the same person.
- The provider must report an email address in the claim `email` and confirm it with `email_verified: true`. Some providers send `email_verified` only when asked to, or not at all; configure the provider to send it. The address is kept as it was at the first sign-in; the display name follows the claim `name` with every sign-in.
- The role follows the groups with every sign-in: the highest role among the groups of the user wins. A change of role ends the other sessions of the account. Administrators cannot change the role of such an account in Nyktus.
- A user in none of the configured groups cannot sign in, and their account is deactivated, which ends its sessions. Nyktus learns of a removal from the groups only when the user signs in through the provider again: until then, open sessions continue, at most for `NYKTUS_SESSION_MAX_AGE`. To lock a user out at once, deactivate the account in Nyktus as well.
- Deleting an account does not lock its user out: the next sign-in creates it again. To lock a user out, deactivate the account, or remove the user from the groups. A deactivated account stays locked out until an administrator reactivates it, even if the user is added to a group again.
- The groups can neither demote nor deactivate the last active administrator. Such a sign-in is rejected, and the account stays as it is.
- Accounts of the provider have no password and no second factor in Nyktus; the provider handles both. Their users cannot change a password or set up a second factor, and administrators cannot issue password reset links for them.
- Administrators of the provider confirm the actions that a local administrator confirms with the password by [signing in at the provider again](#confirming-sensitive-actions).

### Confirming sensitive actions

Creating an [API key](api-keys.md), removing the second factor of another account, and creating an [alert channel](alerting.md#changing-and-deleting-a-channel) or changing it other than by renaming it require a fresh authentication, because a taken-over session must not be able to do any of them. A local administrator gives the password with the request, in the console in a dialog that asks for it and does not keep it. An administrator of the provider leaves it out and signs in at the provider again first: the web console sends the browser to `GET /api/v1/oidc/reauthenticate?return_to=<page>`, the provider asks for the credentials again, and the browser returns to the page. For the next five minutes, that session may perform these actions; afterwards, or in another session, they receive `403` with the code `reauthentication_required`.

The confirmation fails, and the browser returns with `#error=reauthentication`, if the provider confirms another user, does not report that it asked for the credentials again (claim `auth_time`, which the provider must send when asked with `max_age`), or reports groups that no longer give the role of the account; the user then signs in again. Clocks of Nyktus and the provider may differ by up to a minute. Every attempt is recorded in the [audit log](audit-log.md) as `session.reauthenticate`.

### Password sign-in with an identity provider

With a provider, only administrators sign in with a password by default (`NYKTUS_LOCAL_LOGIN=admins`). Keep at least one local administrator as emergency access for when the provider is unreachable, and give it a [second factor](#second-factor): a local administrator without one bypasses the multi-factor authentication of your provider. Other accounts with a password receive the same answer as a wrong password. Set `NYKTUS_LOCAL_LOGIN=all` to let every account sign in with its password as well, or `off` to let nobody, which leaves no access while the provider is unreachable.

### Availability and sign-out

- If the provider is unreachable when the console starts, the console starts anyway, logs a warning and tries again every 30 seconds, then less often, up to every 5 minutes. Until it reaches the provider, `GET /api/v1/oidc/authorize` answers `503`, and local administrators sign in with their password. Signing keys that the provider rotates are fetched again when a token needs them.
- A sign-in must be completed within ten minutes. The cookie `__Host-nyktus_oidc` binds it to the browser that started it; it is `Secure`, `HttpOnly` and `SameSite=Lax`, because the provider sends the browser back from another site.
- Signing out ends the session in Nyktus only, not the session at the provider. The next sign-in may therefore complete without a password prompt.
- The requests to the provider bypass the protection against requests to internal addresses that other outgoing requests receive, because the provider is often only reachable internally. They use HTTPS, which is required outside development.

## What the sign-in page offers

The sign-in page asks `GET /api/v1/sign-in-options`, which needs no sign-in, which forms of sign-in to offer: the form for the email address and password (`password`), and the button for the identity provider (`oidc`). The answer describes the instance and nothing about an account, so it is the same for every caller.

- `password` is `false` only with `NYKTUS_LOCAL_LOGIN=off`. With `admins` it is `true`: the page does not tell which accounts may sign in with a password.
- `oidc` is `off` without an identity provider, `available` once the console has reached the provider, and `unavailable` until then. The page shows the button disabled in that case instead of sending the browser to an error.

## Sessions

- A session ends after a period without requests (`NYKTUS_SESSION_IDLE_TIMEOUT`, default one hour) and at the latest after its maximum age (`NYKTUS_SESSION_MAX_AGE`, default 12 hours), and when the user signs out. See [Configuration](configuration.md).
- The cookie `__Host-nyktus_session` is `Secure`, `HttpOnly` and `SameSite=Strict`. The console must therefore be reached over HTTPS. Browsers also accept the cookie on `http://localhost` and `http://127.0.0.1` during development.
- The database stores only a hash of the session token. Signing in again ends the session that the browser held before.
- The [worker](database.md#periodic-tasks) removes expired sessions from the database.
- Changing or resetting the password, enabling or removing the second factor, deactivating the account or changing its role ends its sessions. See [Managing accounts](users.md).
- Integrations use [API keys](api-keys.md) instead of sessions.

## Reverse proxy

- `NYKTUS_CONSOLE_URL` must be exactly the address that users open in the browser, including the port if it is not the default. Requests that change state, such as a sign-in, are rejected with `403` if the browser reports another origin. This protects sessions against requests from other sites, including pages on other subdomains of your domain.
  The answer carries the code `cross_origin`, which the web console shows as a notice that the address in the browser differs from the configured one.
- Pass the `Origin` header to the console unchanged.
- Rate-limit the sign-in endpoints `POST /api/v1/session`, `POST /api/v1/session/second-factor`, `GET /api/v1/oidc/authorize` and `GET /api/v1/oidc/callback` and the endpoints `POST /api/v1/activation` and `POST /api/v1/password-reset` at the proxy, per client address. Each request to `GET /api/v1/oidc/authorize` stores a sign-in for ten minutes, which the [worker](database.md#periodic-tasks) removes within five minutes after it expires.

## Changing the password

In the web console, choose your name in the header to open your account: the form asks for the current password and the new one twice, and empties its fields once the request is answered. The other sessions of the account end, and you stay signed in. Through the API:

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

In the console, your account page has a button Set up a second factor. It asks for your password, then shows a QR code and the key as text, valid for ten minutes; enter the code that your app shows, and the page shows the ten recovery codes once, to copy or save as a text file. If the time runs out, the page says so and you start again. Through the API:

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

In the console, the account page replaces the recovery codes and removes the factor; both ask for your password and a code of the app or a recovery code, in a dialog that keeps neither. Through the API:

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
- Every sign-in and change of password, successful or not, and every sign-out is recorded in the [audit log](audit-log.md) with the client address. A sign-in through the provider is recorded as `session.create` with the method `oidc`; a sign-in that does not prove an identity, such as an expired one, is only logged. A failure for an unknown address does not record the address. With a second factor, the correct password is recorded as `sign_in_challenge.create`, and the second step as `session.create` with the method `totp` or `recovery_code`. The setup, confirmation and removal of a factor and new recovery codes are recorded as `user.totp_enroll`, `user.totp_enable`, `user.totp_disable` and `user.recovery_codes_create`.

## When the server is busy

Password hashing needs 64 MiB of memory per operation, so the number of concurrent operations is limited. A request that hashes a password, such as a sign-in, setup, activation, password change or reset, and cannot be served within 10 seconds receives `503 Service Unavailable` with a `Retry-After` header.
