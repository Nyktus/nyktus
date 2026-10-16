# API keys

Integrations such as a SIEM call the API with an API key instead of a session. Keys belong to the team, not to the administrator who created them: a key acts with its scopes alone and stays valid when the account of its creator is changed, deactivated or deleted. Only administrators create, list and revoke keys.

## Creating a key

An administrator creates a key while signed in with a session, and confirms the request with their password, because a key outlives the session. Administrators who sign in through the [identity provider](sign-in.md#identity-provider) have no password: they leave it out and [sign in at the provider again](sign-in.md#confirming-sensitive-actions) within the five minutes before.

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/api-keys \
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
- **Scopes.** Keys carry these scopes:

  | Scope | Allows |
  |---|---|
  | `audit:read` | reading the [audit log](audit-log.md) |
  | `incidents:read`, `incidents:write` | reading and triaging [incidents](incidents.md), for example from a ticket system |
  | `events:read` | reading [events](incidents.md#reading-incidents-and-events), which contain personal data such as client addresses |
  | `honeytokens:read`, `honeytokens:write` | reading and managing [honeytokens](honeytokens.md), for example to roll them out by script |
  | `metrics:read` | reading the [metrics](metrics.md), for a monitoring system |

  A scope to write requires the scope to read the same resource, because a key that changes a resource receives it in the responses. Honeytokens are part of the inventory: give integrations that only follow incidents or read the audit log, such as a SIEM, keys without the honeytoken scopes, and integrations that do not need client addresses keys without `events:read`. Keys never manage accounts, keys or [alert channels](alerting.md), not even by reading them: a key with access to the channels could redirect or stop the alerts.
- **Expiry.** Every key expires, at the latest three years after it is created. There is no default; choose a period that suits the integration and your rotation policy. Nyktus does not yet remind anyone before a key expires.
- **Limit.** The team has at most 50 keys that have not expired. Creating a key deletes the expired keys, and the [worker](database.md#periodic-tasks) deletes them within five minutes after they expire.
- **Password.** A wrong password counts as a failed sign-in, as with a change of password.

`GET /api/v1/api-keys` lists the keys of the team with their scopes, creator, expiry and last use, never their secrets. The last use is exact to a minute.

## Using a key

Send the key in the `Authorization` header:

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/audit-entries \
  --header "Authorization: Bearer $NYKTUS_API_KEY"
```

- A request with a key authenticates with the key alone, even if it carries a session cookie. Other credentials in the `Authorization` header, such as the Basic credentials of a reverse proxy or the bearer token of an identity-aware proxy, are ignored.
- An expired, revoked or unknown key receives `401`, like a request without credentials.
- A key holds its scopes and nothing else, regardless of any role.
- Keys cannot sign anyone out, change a password or a second factor, or manage keys. Those requests receive `403` with a message saying that they need a session.

Keys start with `nyk_`, followed by 84 characters, which include the identifier of the key and a checksum. Secret scanners can recognize leaked keys by the prefix. Store keys like passwords, for example in the secret store of the integration, never in a repository or a URL.

## Revoking a key

`DELETE /api/v1/api-keys/<id>` revokes a key, for example after it leaked or when an integration is retired. It stops working with the next request. The list shows the name, creator, creation time and last use of each key; if you cannot tell which key leaked, revoke every key that might be affected.

Keys stay valid when the administrator who created them leaves. Review the keys of the team when people leave or integrations change, and revoke those that are no longer needed.

## Audit

A key is an actor of its own in the [audit log](audit-log.md), with the method `api_key`, its identifier and a copy of its name, which stays readable after the key is revoked. Reads and requests denied for a missing permission are recorded at most once per minute and key. Requests rejected because the route admits only sessions, such as an attempt to change a password with a key, are not recorded there; the [access log](logs.md) records every request with the identifier of its key. The creation of a key and every attempt with a wrong password or for a locked account are recorded as `api_key.create`, with the administrator as the actor, a revocation as `api_key.revoke`. Requests with an invalid key are not recorded; the access log records them.
