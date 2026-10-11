# API keys

Integrations such as a SIEM call the API with an API key instead of a session. A key acts for the user who created it, with the intersection of its scopes and the current role of that user.

## Creating a key

Users create their own keys while signed in with a session, and confirm the request with their password, because a key outlives the session:

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/session/api-keys \
  --header 'Content-Type: application/json' \
  --data @api-key.json \
  --cookie cookies.txt
```

with `api-key.json`:

```json
{
  "name": "SIEM export",
  "scopes": ["audit:read"],
  "expires_at": "2027-01-31T00:00:00Z",
  "password": "…"
}
```

- **The key is shown only in this response.** Nyktus keeps only a hash of its secret. A lost key cannot be recovered; revoke it and create a new one.
- **Scopes.** Keys currently carry only `audit:read`, for reading the [audit log](audit-log.md). A key can only carry scopes that the role of the user grants. Keys never manage accounts, not even by reading them.
- **Expiry.** Every key expires, at the latest 365 days after it is created. There is no default; choose the shortest period that suits the integration. Nyktus does not yet remind anyone before a key expires.
- **Limit.** A user has at most 20 keys that have not expired. Creating a key deletes the expired keys of the user.
- **Password.** A wrong password counts as a failed sign-in, as with a change of password.

`GET /api/v1/session/api-keys` lists the keys of the caller with their scopes, expiry and last use, never their secrets. The last use is exact to a minute.

## Using a key

Send the key in the `Authorization` header:

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/audit-entries \
  --header "Authorization: Bearer $NYKTUS_API_KEY"
```

- A request with the header authenticates with the key alone, even if it carries a session cookie.
- An expired, revoked or unknown key, and a key of a deactivated account, receives `401`, like a request without credentials.
- The key holds a permission only if its scopes and the current role of its user both grant it. Demoting the user restricts the key with the next request.
- Keys cannot sign the user out, change the password or the second factor, or manage keys. Those requests receive `403`.

Keys start with `nyk_`, followed by 84 characters, which include the identifier of the key and a checksum. Secret scanners can recognize leaked keys by the prefix. Store keys like passwords, for example in the secret store of the integration, never in a repository or a URL.

## Revoking a key

`DELETE /api/v1/session/api-keys/<id>` revokes a key of the caller. It stops working with the next request.

Administrators see and revoke the keys of every account, for example after a key leaked:

- `GET /api/v1/users/<id>/api-keys` lists the keys of an account.
- `DELETE /api/v1/users/<id>/api-keys/<key-id>` revokes one.

The list shows the name, creation time and last use of each key. If you cannot tell which key leaked, revoke every key of the account. Administrators cannot create keys for other users.

Deactivating an account revokes all of its keys, and reactivating it does not bring them back. Deleting an account deletes its keys. A change of role keeps the keys, which then hold only what the new role grants. Changing or resetting the password and removing the second factor keep the keys as well: after an account was taken over, check its keys and revoke those you do not know.

## Audit

Every request made with a key is recorded in the [audit log](audit-log.md) like a request of its user, with the method `api_key` and the identifier of the key. The creation of a key, successful or not, is recorded as `api_key.create`, a revocation by the user or an administrator as `api_key.revoke`. Requests with an invalid key are not recorded; the [access log](logs.md) records them.
