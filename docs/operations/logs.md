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
| `user_id`, `auth_method` | The account that sent the request and how it authenticated, such as `session`. Only for authenticated requests; every later record of the request carries them as well. |

Requests without valid credentials, such as a failed setup attempt or a request without a session, are recorded only here, not in the audit log. The access log is the place to look for them.

## Personal data

The access log contains client addresses and account identifiers, which are personal data. Keep it only as long as you need it to investigate incidents, and restrict access to it like access to the audit log.
