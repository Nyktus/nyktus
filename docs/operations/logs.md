# Logs

Nyktus writes its log as JSON, one record per line, to standard error. `NYKTUS_LOG_LEVEL` sets the minimum level (see [Configuration](configuration.md)). Standard output is reserved for messages to the operator, such as the [setup URL](first-start.md), which never appear in the log.

## Access log

The console writes one record with the message `http: request` per request:

| Field | Content |
|---|---|
| `method` | HTTP method. |
| `route` | The matched route pattern, such as `POST /api/v1/setup`, never the requested path. Values in paths do not reach the log. Requests that match no route have an empty `route`. |
| `status` | Status code of the response. |
| `duration` | Time to answer, in nanoseconds. |
| `client_ip` | Address of the client, determined as described in [Client addresses](configuration.md#client-addresses). |
| `request_id` | The ID that the response carries in `X-Request-ID`. Every other record of the same request, and the audit log, carries it as well. |
| `auth_method` | How the request authenticated, such as `session` or `api_key`. Only for authenticated requests; every later record of the request carries it, and the two fields below, as well. |
| `user_id` | The account that sent the request, for requests made with a session. |
| `api_key_id` | The identifier of the [API key](api-keys.md), for requests made with one. |

Requests without valid credentials, such as a failed setup attempt or a request without a session, are recorded only here, not in the [audit log](audit-log.md). The access log is the place to look for them.

## Sign-in through an identity provider

With an [identity provider](sign-in.md#identity-provider), the console writes these records:

| Message | Level | Content |
|---|---|---|
| `oidc: identity provider unreachable; sign-ins through it fail until it is discovered` | warn | The provider could not be reached at startup. `issuer`, `retry_in` until the next attempt, and `error`. |
| `oidc: identity provider discovered` | info | The provider was reached; sign-ins through it work from now on. |
| `oidc: reauthenticated` | info | A user of the provider signed in there again to confirm sensitive actions. `session` names the session and its account. |
| `oidc: sign-in rejected` | warn | The provider confirmed the user, but the sign-in or reauthentication was rejected. `rejection` holds the `reason`, such as a user in none of the configured groups, and the `issuer` and `subject` of the user at the provider. |
| `oidc: invalid sign-in` | info | The sign-in proves no identity, for example because it expired, was used before, was started in another browser or the provider did not confirm the code or token. `error` names the cause. |
| `oidc: the identity provider returned an error` | info | The user declined or the provider refused. `error` holds the registered error code, or `unregistered`. |

## Personal data

The access log contains client addresses and account identifiers, which are personal data. The records of rejected sign-ins through the identity provider contain the subject of the user at the provider. Keep it only as long as you need it to investigate incidents, and restrict access to it like access to the [audit log](audit-log.md).
