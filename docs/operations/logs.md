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

The trigger writes one record with the message `trigger: request` per request. It never logs the requested path, because the path holds the value of a honeytoken, and never the secret of a [sensor](honeypots.md#how-a-sensor-reports) or anything that a sensor or an attacker chose, such as user names or search filters.

| Field | Content |
|---|---|
| `method` | HTTP method. |
| `outcome` | `recorded` (an event was stored, or a heartbeat accepted), `unknown` (the value belongs to no honeytoken, or the secret to no honeypot), `disabled`, `limited` (the honeytoken or honeypot reached its limit of events), `duplicate` (a session had been recorded before), `rejected` (a report that the trigger does not accept; see `reason`), `failed` (recording failed; see the error record before it), or `not_looked_up` (the path holds no value, or the method is not recorded; a `POST` to `/` without a secret of the form of one). |
| `honeytoken_id` | The identifier of the honeytoken, unless its value is unknown. |
| `report` | `session` or `heartbeat`, for a report of a sensor that the trigger read. |
| `honeypot_id` | The identifier of the honeypot, unless its secret is unknown. |
| `service` | The service of the honeypot, such as `ssh`. |
| `event_type` | The highest stage that a reported session reached: `connection`, `login_attempt` or `directory_query`. |
| `reason` | Why a report was `rejected`: `unsupported_version` (the report names a version that this server does not know, usually because the sensor is newer: update the server first) or `invalid_report` (not JSON of the expected form, too large, or a value outside its limits, or a session that does not fit the service of the honeypot). |
| `status` | `302` or `200`. |
| `duration` | Time to answer, in nanoseconds. |
| `client_ip` | Address of the client. |

The trigger answers a failed request like any other, so the log is the only place where a failure shows:

| Message | Level | Content |
|---|---|---|
| `trigger: recording failed` | error | The database could not record the request, for example because it was unreachable or slower than two seconds. `error` names the cause. |
| `trigger: handler panicked` | error | A programming error; `panic` and `stack` describe it. The client still receives the regular answer. |
| `trigger: requests not recorded` | warn | Requests of the honeytoken `honeytoken_id` beyond its [limit of events](honeytokens.md#events) in the last minute; `requests` is their number. |
| `trigger: reports not recorded` | warn | Sessions of the honeypot `honeypot_id` beyond its [limit of events](honeypots.md#limits) in the last minute; `reports` is their number. |

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
| `worker: started` | info | The worker looks for events to process, alerts to deliver and periodic tasks that are due; `concurrency` and `delivery_concurrency` are the numbers of events and alerts it handles at a time, `audit_retention_days` and `event_retention_days` the [retention](database.md#periodic-tasks), `incident_auto_close_days` the [inactivity](incidents.md#closing-inactive-incidents) after which it closes incidents, and `smtp` whether an [SMTP server](configuration.md#mail) is configured. |
| `worker: email channels without smtp server` | warn | `channels` [alert channels of the type `email`](alerting.md#mail) are enabled, but no SMTP server is configured; their deliveries are dead with the class `not_configured`. Set `NYKTUS_SMTP_HOST`, then [retry](alerting.md#dead-deliveries) the dead deliveries. |
| `worker: stopped` | info | The worker processed its last event and stopped. |
| `incident: opened` | info | An event opened an incident and raised its alert. `incident` holds `incident_id`, `event_id`, `resource_type`, `resource_id` and `severity`; `deliveries` counts the channels the alert goes to. |
| `alerting: no enabled channel` | warn | An incident opened while no alert channel was enabled, so its alert reaches nobody. `incident_id` names it. |
| `alerting: alert delivered` | info | The receiver accepted an alert or test. `delivery` holds `id`, `channel_id`, `channel_type` and, for an alert, `incident_id`; `attempt`, `status_code` and `duration` describe the attempt. |
| `alerting: delivery failed` | warn | An attempt failed and is tried again after `retry_in`. `failure` is its class, such as `http_status`, `smtp_status`, `timeout` or `network`, `status_code` the answer of the receiver or the reply code of the SMTP server, if there was one. See [Retries](alerting.md#retries). |
| `alerting: delivery dead` | error | A delivery failed for the last time, or in a way no retry can mend, such as `blocked`, `invalid_channel` or `not_configured`. If the secrets of the channel could not be decrypted, for example after their key was removed, `error` names the cause, never the secret. An administrator can [retry it](alerting.md#dead-deliveries). |
| `alerting: delivery canceled` | info | The channel of a delivery was disabled or deleted before it was sent. |
| `alerting: attempt not recorded` | warn | The outcome of an attempt was not recorded, because the delivery was claimed again or settled meanwhile; the later state stands. |
| `incident: closed` | info | The worker [closed an incident](incidents.md#closing-inactive-incidents) `incident_id` whose last event lies beyond `NYKTUS_INCIDENT_AUTO_CLOSE_DAYS`; `reason` is `inactive`. |
| `incident: event assigned` | debug | An event was added to an open incident. Same fields as above. |
| `incident: event not processed` | error | An event could not be assigned to an incident. It stays and is tried again at `retry_at`; `attempts` counts the failed attempts, `error` names the cause. The event is not lost, but it raises no alert until it is processed. |
| `worker: periodic task completed` | info | A [periodic task](database.md#periodic-tasks) `task` ran to its end and removed `rows` rows. A run that removed nothing is logged at debug. |
| `worker: job failed` | error | The worker could not reach the database or complete a transaction. `error` names the cause. Unless `claimed` is `true`, the worker waits before it tries again, longer after every failure in a row, up to 30 seconds, or 5 minutes when it looks for periodic tasks. A delivery that could not be claimed is postponed by its backoff, without counting an attempt, so that the deliveries behind it go out. A periodic task that failed starts again within a minute. |

## Sensor

The [sensor](sensor.md) writes JSON to its standard error as well, one record per line, with the level set by `log_level` of its configuration. Its records name a honeypot by `honeypot_id`, the identifier from the console, and `service`. They hold counts and never the secret of a honeypot, a user name, a password, the fingerprint of a key, the version of a client or anything else that an attacker typed or sent. What an attacker can cause at will, such as connections that are refused or sessions that are dropped, is counted and written once a minute, not once for each occurrence.

| Message | Level | Content |
|---|---|---|
| `sensor: honeypot listening` | info | A honeypot is bound. `listen` is the address it listens on. |
| `sensor: started` | info | Every honeypot listens. `version` is the version of the sensor and `honeypots` their number. |
| `sensor: stopped` | info | The sensor delivered what it could and ended. |
| `sensor: failed` | error | The sensor did not start, for example because a port is taken. `error` names the honeypot and the cause; the exit code is 1. |
| `sensor: heartbeat not delivered` | warn | The trigger could not be reached for the heartbeat of `honeypot_id`, after three repetitions. `error` is the failure of the transport, such as a connection that was refused, a certificate that was not accepted or a gateway failure with its status. This is how a wrong `trigger_url` or a missing private authority shows. The sensor keeps trying every five minutes. |
| `sensor: reports not sent` | warn | Logged once a minute while there is something to count: `overflow` sessions that found the share of their honeypot in the queue full, `expired` sessions older than five minutes when their turn came, `failed` sessions that the transport failed for on every attempt and `shutdown` sessions that the stopping sensor could not deliver in time. |
| `sensor: connections refused` | warn | Logged once a minute for each honeypot with refused connections: `too_many` because the honeypot had its most connections open, `too_many_from_source` because their source had. |
| `sensor: accepting connections failed` | warn | `errors` accepts of the honeypot failed in the last minute, for example because the process ran out of file descriptors. |
| `sensor: sessions ended by a failure of the service` | error | A programming error: `sessions` sessions of the honeypot ended with a panic. Their reports were sent. `panic` is the failure of the first one in the last minute (the text of a runtime error such as `assignment to entry in nil map`, otherwise only the type of the value, because its text could hold what a client sent) and `stack` the first 2 KiB of its stack, which names the place of the fault. |
| `sensor: session not started` | error | The random source failed. |

At level `debug` the sensor also writes `sensor: session reported` for each session that the trigger answered, with the `event_type` that the server will derive (`connection` or `login_attempt`) and the number of `attempts`, and `sensor: report request failed` for each failed request with its `attempt` and `error`. An attacker causes one record of the first kind for each session, so keep this level for debugging.

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
