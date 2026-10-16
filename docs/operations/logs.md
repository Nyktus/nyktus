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

## Trigger

The trigger writes one record with the message `trigger: request` per request. It never logs the requested path, because the path holds the value of a honeytoken.

| Field | Content |
|---|---|
| `method` | HTTP method. |
| `outcome` | `recorded` (an event was stored), `unknown` (the value belongs to no honeytoken), `disabled`, `limited` (the honeytoken reached its limit of events), `failed` (recording failed; see the error record before it), or `not_looked_up` (the path holds no value, or the method is not recorded). |
| `honeytoken_id` | The identifier of the honeytoken, unless its value is unknown. |
| `status` | `302` or `200`. |
| `duration` | Time to answer, in nanoseconds. |
| `client_ip` | Address of the client. |

The trigger answers a failed request like any other, so the log is the only place where a failure shows:

| Message | Level | Content |
|---|---|---|
| `trigger: recording failed` | error | The database could not record the request, for example because it was unreachable or slower than two seconds. `error` names the cause. |
| `trigger: handler panicked` | error | A programming error; `panic` and `stack` describe it. The client still receives the regular answer. |
| `trigger: requests not recorded` | warn | Requests of the honeytoken `honeytoken_id` beyond its [limit of events](honeytokens.md#events) in the last minute; `requests` is their number. |

## DNS

The DNS role writes one record with the message `dns: query` per query of a name that holds a trigger value, once the query is recorded. It never logs the queried name, because the name holds the value of a honeytoken.

| Field | Content |
|---|---|
| `outcome` | `recorded`, `unknown`, `disabled`, `limited` or `failed`, as for the trigger. |
| `honeytoken_id` | The identifier of the honeytoken, unless its value is unknown. |
| `qtype` | The type of the query, such as `A` or `TYPE65280`. |
| `transport` | `udp` or `tcp`. |
| `resolver_ip` | The address that sent the query, usually a resolver that asks on behalf of its clients, not the attacker. |
| `duration` | Time to record, in nanoseconds. The answer was sent before. |

Other queries, such as those of names without a value or outside the zones, are logged at level `debug` only, with `rcode`, `transport` and `resolver_ip`.

| Message | Level | Content |
|---|---|---|
| `dns: recording failed` | error | The database could not record the query, for example because it was unreachable or slower than two seconds. `error` names the cause. |
| `dns: handler panicked` | error | A programming error; `panic` and `stack` describe it. |
| `dns: queries not recorded` | warn | Logged once a minute. With `reason` `limit`: queries of the honeytoken `honeytoken_id` beyond its [limit of events](honeytokens.md#events). With `reason` `queue_full`: queries that arrived while too many others were waiting to be recorded, for example during a flood. With `reason` `stale`: queries that waited more than five minutes to be recorded, for example while the database was unreachable. `queries` is their number. |

## Worker

The [worker](incidents.md) logs what became of the events it processed, of the [alerts](alerting.md) it delivered and of its [periodic tasks](database.md#periodic-tasks). Records of deliveries name the delivery, its channel and the incident by their identifiers, never the URL of the channel or the response of the receiver.

| Message | Level | Content |
|---|---|---|
| `worker: started` | info | The worker looks for events to process, alerts to deliver and periodic tasks that are due; `concurrency` and `delivery_concurrency` are the numbers of events and alerts it handles at a time, `audit_retention_days` and `event_retention_days` the [retention](database.md#periodic-tasks). |
| `worker: stopped` | info | The worker processed its last event and stopped. |
| `incident: opened` | info | An event opened an incident and raised its alert. `incident` holds `incident_id`, `event_id`, `resource_type`, `resource_id` and `severity`; `deliveries` counts the channels the alert goes to. |
| `alerting: no enabled channel` | warn | An incident opened while no alert channel was enabled, so its alert reaches nobody. `incident_id` names it. |
| `alerting: alert delivered` | info | The receiver accepted an alert or test. `delivery` holds `id`, `channel_id`, `channel_type` and, for an alert, `incident_id`; `attempt`, `status_code` and `duration` describe the attempt. |
| `alerting: delivery failed` | warn | An attempt failed and is tried again after `retry_in`. `failure` is its class, such as `http_status`, `timeout` or `network`, `status_code` the answer of the receiver, if there was one. See [Retries](alerting.md#retries). |
| `alerting: delivery dead` | error | A delivery failed for the last time, or in a way no retry can mend, such as `blocked` or `invalid_channel`. If the secrets of the channel could not be decrypted, for example after their key was removed, `error` names the cause, never the secret. An administrator can [retry it](alerting.md#dead-deliveries). |
| `alerting: delivery canceled` | info | The channel of a delivery was disabled or deleted before it was sent. |
| `alerting: attempt not recorded` | warn | The outcome of an attempt was not recorded, because the delivery was claimed again or settled meanwhile; the later state stands. |
| `incident: event assigned` | debug | An event was added to an open incident. Same fields as above. |
| `incident: event not processed` | error | An event could not be assigned to an incident. It stays and is tried again at `retry_at`; `attempts` counts the failed attempts, `error` names the cause. The event is not lost, but it raises no alert until it is processed. |
| `worker: periodic task completed` | info | A [periodic task](database.md#periodic-tasks) `task` ran to its end and removed `rows` rows. A run that removed nothing is logged at debug. |
| `worker: job failed` | error | The worker could not reach the database or complete a transaction. `error` names the cause. Unless `claimed` is `true`, the worker waits before it tries again, longer after every failure in a row, up to 30 seconds, or 5 minutes when it looks for periodic tasks. A delivery that could not be claimed is postponed by its backoff, without counting an attempt, so that the deliveries behind it go out. A periodic task that failed starts again within a minute. |

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

The access logs of the console and the trigger and the records of the DNS role contain client and resolver addresses, and the access log of the console account identifiers, which are personal data. The records of rejected sign-ins through the identity provider contain the subject of the user at the provider. Keep it only as long as you need it to investigate incidents, and restrict access to it like access to the [audit log](audit-log.md).
