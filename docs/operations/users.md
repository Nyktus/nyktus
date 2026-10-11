# Managing accounts

Administrators create and manage the accounts of the console. There is no public registration. Every account has an email address, which is its sign-in name and cannot be changed, a display name and a role:

| Role | Purpose |
|---|---|
| `admin` | Manages the installation, its accounts and the audit log. |
| `editor` | Works with decoys and incidents. |
| `viewer` | Reads decoys and incidents. |

The examples below call the API with the session cookie of an administrator, as described in [Sign-in and sessions](sign-in.md).

## Creating an account

Create the account with its address, display name and role:

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/users \
  --header 'Content-Type: application/json' \
  --data '{"email": "jane@example.com", "display_name": "Jane Doe", "role": "editor"}' \
  --cookie cookies.txt
```

The answer contains the new account, which is `pending`, and an activation link:

```json
{
  "user": {"id": "...", "email": "jane@example.com", "display_name": "Jane Doe", "role": "editor", "status": "pending"},
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

`PATCH /api/v1/users/<id>` changes the display name, the role or the status, alone or together:

```sh
curl --fail-with-body --request PATCH https://nyktus.example.com/api/v1/users/<id> \
  --header 'Content-Type: application/json' \
  --data '{"role": "viewer"}' \
  --cookie cookies.txt
```

- **Role.** A new role ends every session of the account and applies immediately.
- **Deactivating** (`"status": "deactivated"`) blocks the sign-in, ends every session and removes an open activation or password reset link. The password is kept.
- **Reactivating** (`"status": "active"`) lets the user sign in again with their password and ends a lock after failed sign-ins. An account that never set a password returns to `pending` and needs a new activation link.

`DELETE /api/v1/users/<id>` deletes an account with its sessions and its open link. Entries of the account in the [audit log](audit-log.md) keep a copy of its address and display name.

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

The user sets the new password with the token from the link, in a file as for the activation:

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/password-reset \
  --header 'Content-Type: application/json' \
  --data @reset.json
rm reset.json
```

The reset ends every session of the account and a lock after failed sign-ins. It does not sign in. An unknown, expired or used token receives `404`, and so does the token of an activation link.

An administrator can reset the password of another administrator and then act as that administrator. The audit log shows who created the link.

## When no administrator can sign in

If no administrator can sign in, for example because the only one forgot the password, print a password reset link on the server:

```sh
nyktus admin reset-password ada@example.com
```

The command reads the configuration of the console (`NYKTUS_CONSOLE_DATABASE_URL` and `NYKTUS_CONSOLE_URL`) and prints the link on standard output. It works only for active administrators; other accounts are reset by an administrator. The link follows the rules above. The audit log records the command line as the creator of the link.

## At least one administrator

At least one active administrator always remains. Nyktus rejects every change that would demote, deactivate or delete the last one, also when two administrators try it at the same time. Administrators cannot demote, deactivate or delete their own account; another administrator has to do it. To hand over the installation, create an account for the new administrator, and let the new administrator remove the old account.

## Audit

The audit log records every creation, change, deletion, new activation link and activation of an account, every new password reset link, whether from an administrator or the command line, and every password reset and change. Changes name the changed fields, not their values. Reads of accounts are recorded at most once per administrator and minute, because accounts contain personal data.

## Reverse proxy

Rate-limit `POST /api/v1/activation` and `POST /api/v1/password-reset` at the proxy per client address, like the sign-in.
