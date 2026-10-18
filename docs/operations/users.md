# Managing accounts

Administrators create and manage the accounts of the console. There is no public registration. Every account has an email address, which is its sign-in name and cannot be changed, a display name and a role. With an [identity provider](sign-in.md#identity-provider), the accounts of its users are created when they first sign in, and their roles follow their groups there; the field `sign_in_method` of an account is then `oidc` instead of `password`.

| Role | Purpose |
|---|---|
| `admin` | Manages the installation, its accounts, [API keys](api-keys.md), [alert channels](alerting.md) and settings, reads the audit log, and does everything a `user` does. |
| `user` | Configures honeypots, [honeytokens](honeytokens.md), [scenarios](scenarios.md) and [artifacts](artifacts.md) and works with incidents. |
| `viewer` | Reads decoys, scenarios, artifacts, incidents, events and the [deception catalog](catalog.md), but does not triage incidents and does not read the audit log. |

Decoys, scenarios and API keys belong to the team, not to the account that created them.

The examples below call the API with the session cookie of an administrator, as described in [Sign-in and sessions](sign-in.md).

## Creating an account

Create the account with its address, display name and role:

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/users \
  --header 'Content-Type: application/json' \
  --data '{"email": "jane@example.com", "display_name": "Jane Doe", "role": "user"}' \
  --cookie cookies.txt
```

The answer contains the new account, which is `pending`, and an activation link:

```json
{
  "user": {"id": "...", "email": "jane@example.com", "display_name": "Jane Doe", "role": "user", "status": "pending", "totp_enabled": false, "sign_in_method": "password"},
  "activation": {"url": "https://nyktus.example.com/activate#token=...", "expires_at": "..."}
}
```

## Passing on the activation link

The new user sets their own password through the activation link. Administrators never set or see the password of another user.

- **The link is shown once.** Nyktus stores only a hash of its token, so no later answer can show it again. Copy it from the answer.
- **Pass it on over a channel you trust** to reach only the new user, such as a direct message or a call. Whoever opens the link first chooses the password of the account.
- **The link is valid for 72 hours and works once.** If it has expired or got lost, create a new one. The previous link stops working:

  ```sh
  curl --fail-with-body --request POST \
    https://nyktus.example.com/api/v1/users/<id>/activation-link --cookie cookies.txt
  ```

- The token is in the fragment of the URL (after `#`). Browsers never send the fragment to a server, so the token does not reach the logs of the console or of your reverse proxy.

Until the web console is available, the new user activates the account through the API, with the token from the link and a password of 12 to 128 characters. Write both into a file, so that the password does not end up in the shell history:

```json
{"token": "<the part of the link after #token=>", "password": "<the new password>"}
```

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/activation \
  --header 'Content-Type: application/json' \
  --data @activation.json
rm activation.json
```

The activation does not sign in, and it ends a lock after failed sign-ins that someone may have caused before. Afterwards, the user signs in with the address and the new password. An unknown, expired or used token receives `404`, like a page that does not exist.

## Changing an account

`PATCH /api/v1/users/<id>` changes the display name, the role or the status, or removes the second factor, alone or together:

```sh
curl --fail-with-body --request PATCH https://nyktus.example.com/api/v1/users/<id> \
  --header 'Content-Type: application/json' \
  --data '{"role": "viewer"}' \
  --cookie cookies.txt
```

- **Role.** A new role ends every session of the account and applies immediately.
- **Deactivating** (`"status": "deactivated"`) blocks the sign-in, ends every session and removes an open activation or password reset link. The password is kept.
- **Reactivating** (`"status": "active"`) lets the user sign in again with their password and ends a lock after failed sign-ins. An account that never set a password returns to `pending` and needs a new activation link. An account of the identity provider becomes active and signs in through the provider again.
- **Accounts of the identity provider.** Their role follows their groups at the provider and cannot be changed here (`409` with the code `oidc_account`). They have no password, so they receive no password reset link (`409`). To lock such a user out, deactivate the account: deleting it does not help, because the next sign-in creates it again.
- **Second factor** (`"totp_enabled": false`), see [Removing a second factor](#removing-a-second-factor).

The field `totp_enabled` of an account tells whether it has a [second factor](sign-in.md#second-factor).

`DELETE /api/v1/users/<id>` deletes an account with its sessions and its open link. [API keys](api-keys.md) that the account created belong to the team and stay valid. Entries of the account in the [audit log](audit-log.md) keep a copy of its address and display name.

## Resetting a password

Users change their own password while signed in, see [Sign-in and sessions](sign-in.md#changing-the-password). A user who forgot it receives a password reset link from an administrator. There is no public "forgot password" page. As with the activation, the administrator never sets or sees the new password.

```sh
curl --fail-with-body --request POST \
  https://nyktus.example.com/api/v1/users/<id>/password-reset-link --cookie cookies.txt
```

```json
{"url": "https://nyktus.example.com/reset-password#token=...", "expires_at": "..."}
```

- Only active accounts receive a reset link, also accounts that are locked after failed sign-ins.
- The link follows the rules of the activation link: it is shown once, valid for 72 hours and works once, and you pass it on over a channel you trust. A new link replaces the previous one. An account has at most one open link.
- **Creating the link changes nothing else.** The current password and the sessions stay valid until the link is used. To lock someone out at once, deactivate the account.
- If the user changes the password themselves before using the link, the link stops working.

The user sets the new password with the token from the link, in a file as for the activation:

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/password-reset \
  --header 'Content-Type: application/json' \
  --data @reset.json
rm reset.json
```

The reset ends every session of the account and a lock after failed sign-ins. It does not sign in. An unknown, expired or used token receives `404`, and so does the token of an activation link.

A reset leaves the second factor in place: whoever gets hold of the link still needs a code. If the user lost the second factor as well, remove it too.

An administrator can reset the password of another administrator and then act as that administrator. The audit log shows who created the link.

## Removing a second factor

A user who lost both the authenticator and the recovery codes cannot sign in. An administrator removes the factor and confirms it with their own password. Write the request into a file, so that the password does not end up in the shell history:

```json
{"totp_enabled": false, "password": "<your password>"}
```

```sh
curl --fail-with-body --request PATCH https://nyktus.example.com/api/v1/users/<id> \
  --header 'Content-Type: application/json' \
  --data @remove.json \
  --cookie cookies.txt
rm remove.json
```

The password confirms that you, and not someone who took over your session, remove the factor. A wrong one receives `403` with the code `wrong_password` and counts as a failed sign-in of your account. The removal deletes the factor and the recovery codes and ends every session of the account. The user then signs in with the password alone and should set up a new factor right away. Make sure that the request really comes from the user, for example by calling them back: the factor protects against someone who knows the password. Only a signed-in session can remove a factor, not an API key. Administrators of the identity provider leave the password out and [sign in at the provider again](sign-in.md#confirming-sensitive-actions) within the five minutes before. Administrators remove their own factor themselves, with their password and a code, see [Sign-in and sessions](sign-in.md#recovery-codes-and-removal). Only users enable a factor; `"totp_enabled": true` is rejected.

## When no administrator can sign in

If no administrator can sign in, for example because the only one forgot the password, print a password reset link on the server:

```sh
nyktus admin reset-password ada@example.com
```

The command reads the configuration of the console (`NYKTUS_CONSOLE_DATABASE_URL` and `NYKTUS_CONSOLE_URL`) and prints the link on standard output. It works only for active administrators who sign in with a password; other accounts are reset by an administrator. The link follows the rules above. The audit log records the command line as the creator of the link.

If the administrator lost the second factor and the recovery codes, remove the factor on the server as well:

```sh
nyktus admin remove-totp ada@example.com
```

It removes the factor and the recovery codes of an active administrator and ends every session of the account, with the same configuration and rules as `reset-password`. It does not need the encryption keys. The audit log records the command line as the actor.

## At least one administrator

At least one active administrator always remains. Nyktus rejects every change that would demote, deactivate or delete the last one, also when two administrators try it at the same time. Administrators cannot demote, deactivate or delete their own account; another administrator has to do it. To hand over the installation, create an account for the new administrator, and let the new administrator remove the old account.

## Audit

The audit log records every creation, change, deletion, new activation link and activation of an account, every new password reset link, whether from an administrator or the command line, every password reset and change, and every removal of a second factor (`user.totp_disable`). Changes name the changed fields, not their values. Reads of accounts are recorded at most once per administrator and minute, because accounts contain personal data.

## Reverse proxy

Rate-limit `POST /api/v1/activation` and `POST /api/v1/password-reset` at the proxy per client address, like the sign-in.
