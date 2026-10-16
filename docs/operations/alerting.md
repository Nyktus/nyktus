# Alerting

An [incident](incidents.md) raises a single alert when it opens. Nyktus delivers each alert to every enabled alert channel.

> This version delivers to webhooks. Deliveries to Slack and Teams fail as `invalid_channel` until their formats follow.

## Alert channels

A channel is a URL that receives an HTTP `POST` for every alert. Its type chooses the format of the request body:

| Type | Receiver |
|---|---|
| `webhook` | Any receiver of JSON, such as a SOAR platform, a SIEM or an automation tool. It can send one additional header, for receivers that expect a token in a header. |
| `slack` | An [incoming webhook](https://api.slack.com/messaging/webhooks) of Slack. |
| `teams` | A workflow of Microsoft Teams that posts to a channel ("Post to a channel when a webhook request is received"). The retired Office 365 connectors are not supported. |

Only administrators manage channels, and only with a session: API keys never manage channels, because a leaked key could redirect the alerts or stop them.

### The URL is a secret

Whoever knows the URL of a Slack or Teams webhook can post into the channel, and many receivers of webhooks accept requests by a token in the URL. Nyktus therefore treats the whole URL, with its path and query, as a secret, and so the value of the header of a webhook:

- They are stored encrypted with the [encryption keys](configuration.md#encryption-keys), bound to their channel, and never logged.
- They are never returned, also not in the response that creates the channel. A channel shows only `target`, the scheme, host and port of its URL, and the name of its header.
- The console can write them, but its database role cannot read them back. To change one, enter it again.

Keep a copy in your secret store if you need it elsewhere.

### Allowed targets

Every URL must use `https` and point to a host that resolves to public addresses only. Nyktus checks this when a channel is saved and again whenever it connects, so that a name that resolves to an internal address later is still refused. It rejects loopback, private, link-local and cloud metadata addresses, and names that are internal by convention, such as `localhost`, single labels and names under `.local` or `.internal`. A target that is not allowed receives `422` with the code `target_not_allowed`, which does not tell an internal target from one that does not resolve.

To deliver to a receiver in one of your internal networks, such as a self-hosted SOAR platform, allow its network with [`NYKTUS_ALERTING_ALLOWED_NETWORKS`](configuration.md#nyktus-serve). This never opens loopback, link-local or metadata addresses. Names under `.local`, `.internal` and the like, and single labels, are accepted then.

Any port is allowed, because self-hosted receivers often listen on one of their own, such as `8088` for the HTTP Event Collector of Splunk. An administrator could thereby make Nyktus connect to an arbitrary port of a public host. This is accepted: the request carries only the alert, Nyktus follows no redirect and never shows the response.

### Creating a channel

Creating a channel is confirmed with the password of the administrator, as is every change other than renaming it. Write the request into a file, so that the URL and the password do not end up in the shell history:

```json
{
  "name": "SOAR",
  "type": "webhook",
  "url": "https://soar.example.com/hooks/nyktus",
  "header": {"name": "Authorization", "value": "Bearer <token>"},
  "password": "<your password>"
}
```

```sh
curl --json @channel.json -b cookies.txt https://nyktus.example.com/api/v1/alert-channels
```

An administrator of the identity provider leaves out the password and [signs in there again](sign-in.md#confirming-sensitive-actions) first.

- **Names** have 1 to 64 characters and are unique.
- **Header** only for a `webhook`. Its name may be any header name other than those that the client sets itself or that change how the request is transferred (`Host`, `Content-Length`, `Content-Type`, `Content-Encoding`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade`, `Expect` and `Proxy-*`). Its value has at most 1024 printable ASCII characters.
- **Limit.** An installation has at most 20 channels.

### Changing and deleting a channel

`PATCH /api/v1/alert-channels/{id}` changes `name`, `enabled`, `url` or `header`; `"header": null` removes the header. The type never changes; create a new channel instead.

Every change other than a new `name` decides where alerts go, what authenticates them, or whether they go at all, so it needs the `password`, as on creation; a missing password counts as a wrong one. This includes enabling a channel again: its URL may have changed hands since it was disabled, for example with a lapsed domain. A taken-over session can therefore neither silence nor redirect the alerts without the password.

Only a disabled channel can be deleted (`DELETE /api/v1/alert-channels/{id}`); an enabled one receives `409` with the code `alert_channel_enabled`.

### Audit

Every creation, change and deletion of a channel is recorded in the [audit log](audit-log.md) as `alert_channel.create`, `alert_channel.update` and `alert_channel.delete`. Changes name the changed fields; a new URL or header always counts as changed, because the stored one cannot be read to compare. A wrong password, and a correct one for a locked account, are recorded as failures of the action and count as failed sign-ins.

## Delivery

The [worker](configuration.md#role-worker) delivers the alerts. When an incident opens, it creates a delivery of its alert for every enabled channel, in the same transaction, so that an alert is never left without its deliveries. A channel that is created or enabled later does not receive alerts of incidents that opened before. If no channel is enabled, the worker logs `alerting: no enabled channel`; the incident is still in the API.

Each delivery is attempted on its own: a channel that fails or answers slowly never holds up the others, and the worker delivers up to `NYKTUS_WORKER_DELIVERY_CONCURRENCY` alerts at a time, apart from the events it correlates. Every request:

- is a `POST` with the body of the channel's type, sent through the SSRF guard, which checks every address it connects to,
- follows no redirect, and ignores `HTTP_PROXY` and `HTTPS_PROXY`,
- ends after 10 seconds,
- counts as delivered if the receiver answers with `2xx`. The response itself is read and discarded, never stored or logged.

### Message of a webhook

A webhook receives JSON:

```json
{
  "version": 1,
  "type": "alert",
  "delivery_id": "6f1d2c1e-8f0a-4f5b-9a4e-1c2b3d4e5f60",
  "incident": {
    "id": "0b9e7a52-3c1d-4e8f-a6b2-7d4c5e6f7a8b",
    "url": "https://nyktus.example.com/incidents/0b9e7a52-3c1d-4e8f-a6b2-7d4c5e6f7a8b",
    "severity": "medium",
    "techniques": ["T1078"],
    "resource_type": "honeytoken",
    "resource_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    "opened_at": "2026-10-15T10:00:01Z",
    "first_event_at": "2026-10-15T10:00:00Z"
  }
}
```

- `version` changes only when a member changes its meaning or disappears; new members may appear within a version, so ignore members you do not know.
- `severity` and `techniques` are those of the incident when it opened, as the alert keeps them.
- The message names the honeytoken by its identifier only. It holds neither its name nor its notes, which belong to the inventory, nor anything of the events, such as client addresses, because messages often go to services of third parties. Fetch the details through the API, for example with an [API key](api-keys.md) with `incidents:read` and `events:read`: `GET /api/v1/incidents/{id}` and `GET /api/v1/events?incident_id={id}`.
- A test sends `{"version": 1, "type": "test", "delivery_id": "…"}`.

### Authenticating the messages

Nyktus does not sign messages. A receiver tells messages of Nyktus from others by a secret it chose: a token in the URL, as with Slack, Teams and most automation tools, or in the header of the webhook, such as `Authorization: Bearer <token>`. HTTPS keeps it from third parties on the way. A signature would protect only the receiver, against forged alerts, which a token prevents as well, and most receivers check a token, not a signature.

### At least once

A delivery reaches its receiver at least once. If the worker stops or loses the database after the receiver accepted a message but before it recorded that, it sends the message again later. Receivers that act on alerts, such as a SOAR platform, should ignore a `delivery_id` they have seen.

### Retries

| Outcome of an attempt | What follows |
|---|---|
| `2xx` | Delivered. |
| Other `5xx`, `408`, a timeout, a failed connection or TLS handshake | Tried again: after 30 seconds, then after twice the previous wait, up to an hour. |
| `429`, `503` | Tried again, as above, or after the wait of `Retry-After` if the receiver names a longer one, at most an hour. |
| Any other `4xx`, a redirect, a target that resolves to a blocked address, a secret that cannot be decrypted | Dead at once: no retry can mend it. |

After 10 attempts, the last about three hours after the first, a delivery is dead. The worker logs every failed attempt as `alerting: delivery failed` and a dead delivery as `alerting: delivery dead`, with the class of the failure and the status code, never the URL or the response. See [Logs](logs.md#worker).

A delivery whose channel was disabled or deleted before it was sent is `canceled`.

### Dead deliveries

Once the receiver is fixed, an administrator delivers a dead alert again:

```sh
curl -X POST -b cookies.txt https://nyktus.example.com/api/v1/alert-deliveries/<id>/retry
```

It starts again with a new count of attempts. The retry is recorded in the audit log as `alert_delivery.retry`.

### Reading deliveries

`GET /api/v1/incidents/{id}/deliveries` lists the deliveries of the alert of an incident, for every user who reads incidents and for API keys with `incidents:read`. Each names its channel, its `status` (`pending`, `delivered`, `dead` or `canceled`), the number of `attempts`, `next_attempt_at` while it is pending, and the last attempt: when it was, the `last_status_code` of the response, if there was one, the class of its failure in `last_error` and how long it took. Administrators read a single delivery with `GET /api/v1/alert-deliveries/{id}`.

### Testing a channel

`POST /api/v1/alert-channels/{id}/test` asks the worker to send a test message to the channel, also to a disabled one, so that it can be tried before it receives alerts. The response (`202`) names the delivery; read its outcome with `GET /api/v1/alert-deliveries/{id}` a few seconds later. A test is attempted once. A channel has at most one test waiting (`409`, code `test_pending`). The worker sends the test, not the console, so that only the worker needs to reach the receivers, and the answer of the console reveals nothing about the network. Tests are recorded in the audit log as `alert_channel.test`.

### Encryption keys

The worker decrypts the secrets of the channels with the [encryption keys](configuration.md#encryption-keys) and refuses to start if a secret was encrypted with a key that is not listed. After a new key was put first, it encrypts the secrets of a channel again with it the next time it delivers to it. To retire the old key sooner, enter the URL and header of the remaining channels again.
