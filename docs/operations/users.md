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

Until the web console is available, the new user activates the account through the API, with the token from the link and a password of 12 to 128 characters:

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/activation \
  --header 'Content-Type: application/json' \
  --data @activation.json
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
- **Deactivating** (`"status": "deactivated"`) blocks the sign-in, ends every session and removes an open activation link. The password is kept.
- **Reactivating** (`"status": "active"`) lets the user sign in again with their password and ends a lock after failed sign-ins. An account that never set a password returns to `pending` and needs a new activation link.

`DELETE /api/v1/users/<id>` deletes an account with its sessions and its activation link. Entries of the account in the [audit log](audit-log.md) keep a copy of its address and display name.

## At least one administrator

At least one active administrator always remains. Nyktus rejects every change that would demote, deactivate or delete the last one, also when two administrators try it at the same time. Administrators cannot demote, deactivate or delete their own account; another administrator has to do it. To hand over the installation, create an account for the new administrator, and let the new administrator remove the old account.

## Audit

The audit log records every creation, change, deletion, new activation link and activation of an account. Changes name the changed fields, not their values. Reads of accounts are recorded at most once per administrator and minute, because accounts contain personal data.

## Reverse proxy

Rate-limit `POST /api/v1/activation` at the proxy per client address, like the sign-in.
