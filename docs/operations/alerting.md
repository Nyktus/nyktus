# Alerting

An [incident](incidents.md) raises a single alert when it opens. Nyktus delivers each alert to every enabled alert channel.

## Alert channels

Most channels are a URL that receives an HTTP `POST` for every alert, and a channel of the type `email` sends mail to its recipients. The type chooses how the alert is sent:

| Type | Receiver |
|---|---|
| `webhook` | Any receiver of JSON, such as a SOAR platform, a SIEM or an automation tool. It can send one additional header, for receivers that expect a token in a header. |
| `slack` | An [incoming webhook](https://api.slack.com/messaging/webhooks) of Slack. |
| `teams` | A workflow of Microsoft Teams that posts to a channel ("Post to a channel when a webhook request is received"). The retired Office 365 connectors are not supported. |
| `email` | Up to 10 addresses, such as the mailbox of a security team, through the [SMTP server](configuration.md#mail) of the operator. See [Mail](#mail). |

Only administrators manage channels, and only with a session: API keys never manage channels, because a leaked key could redirect the alerts or stop them.

### The URL is a secret

Whoever knows the URL of a Slack or Teams webhook can post into the channel, and many receivers of webhooks accept requests by a token in the URL. Nyktus therefore treats the whole URL, with its path and query, as a secret, and so the value of the header of a webhook:

- They are stored encrypted with the [encryption keys](configuration.md#encryption-keys), bound to their channel, and never logged.
- They are never returned, also not in the response that creates the channel. A channel shows only `target`, the scheme, host and port of its URL, and the name of its header.
- The console can write them, but its database role cannot read them back. To change one, enter it again.

Keep a copy in your secret store if you need it elsewhere.

### Mail

A channel of the type `email` has `recipients` instead of a URL: 1 to 10 addresses of the form `local@domain` in ASCII, without display name, comment or quoting, none twice; write an internationalized domain in its ASCII form (`xn--…`). Addresses grant nothing to whoever knows them, unlike the URL of a webhook, so they are no secret: they are stored as they are, returned in the API and may appear in the [log](logs.md) of the worker. A channel shows them in `recipients`; its `target` is `null`.

Addresses that name a person are personal data. Prefer the address of a team or a distribution list, which also keeps the alerts flowing when people leave; administrators see the recipients of every channel.

The worker sends the mail through the SMTP server that the operator configures with [`NYKTUS_SMTP_HOST`](configuration.md#mail). The console accepts channels of the type `email` without it, because it does not know the configuration of the worker; their deliveries are then dead with the class `not_configured`, and the worker warns with `worker: email channels without smtp server` when it starts. Send a [test](#testing-a-channel) after you created a channel.

Whether the mail reaches the inbox is the business of the mail server: it signs the mail (DKIM), and the domain of `NYKTUS_SMTP_FROM` must allow it to send (SPF, DMARC). Use an address of its own as the sender, so that receivers can filter on it, and make sure that the mail of Nyktus is not held in a quarantine for spam.

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

A channel of the type `email` has recipients instead of a URL:

```json
{
  "name": "SOC mailbox",
  "type": "email",
  "recipients": ["soc@example.com"],
  "password": "<your password>"
}
```

An administrator of the identity provider leaves out the password and [signs in there again](sign-in.md#confirming-sensitive-actions) first.

- **Names** have 1 to 64 characters and are unique.
- **URL** for every type but `email`, **recipients** only for `email` (`422`, codes `url_not_allowed` and `recipients_not_allowed`).
- **Header** only for a `webhook`. Its name may be any header name other than those that the client sets itself or that change how the request is transferred (`Host`, `Content-Length`, `Content-Type`, `Content-Encoding`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade`, `Expect` and `Proxy-*`). Its value has at most 1024 printable ASCII characters.
- **Limit.** An installation has at most 20 channels.

### Changing and deleting a channel

`PATCH /api/v1/alert-channels/{id}` changes `name`, `enabled`, `url`, `header` or `recipients`; `"header": null` removes the header, and `recipients` replaces the list. The type never changes; create a new channel instead.

Every change other than a new `name` decides where alerts go, what authenticates them, or whether they go at all, so it needs the `password`, as on creation; a missing password counts as a wrong one. This includes new recipients, and enabling a channel again: its URL or the domain of its recipients may have changed hands since it was disabled, for example with a lapsed domain. A taken-over session can therefore neither silence nor redirect the alerts without the password.

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

Mail goes to the SMTP server of the operator, in a conversation of its own for every delivery:

- The worker connects with TLS, as [configured](configuration.md#mail), and verifies the certificate of the server. With STARTTLS, a server that does not offer it receives nothing but the greeting. The password goes only over TLS.
- The server must accept every recipient; if it refuses one, the worker sends nothing, so that a mail never reaches only some of them.
- A mail counts as delivered once the server has accepted it. What happens afterwards, such as the delivery into the mailbox, is beyond the sight of Nyktus.
- The connection must stand within 10 seconds, and the conversation ends after 20 seconds at the latest, the time that the worker gives a delivery. The replies of the server are read up to 64 KiB, never stored or logged; a refusal keeps only its reply code.

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

### Messages to Slack and Teams

Slack and Teams receive a message for people: the title "Nyktus: incident opened", the severity, the techniques, the honeytoken by its identifier, the time of the first event, the identifier of the delivery and a link to the incident in the console. As for webhooks, the message holds no inventory and no personal data. A test posts "Nyktus: test message".

- **Slack:** create an [incoming webhook](https://api.slack.com/messaging/webhooks) for the channel and use its URL, `https://hooks.slack.com/services/…`. The message uses blocks, with a text that notifications show.
- **Teams:** in the channel, create a workflow from the template "Post to a channel when a webhook request is received" and use the URL that it shows. The message is an adaptive card (version 1.4) with a button that opens the incident.

### Mail of a channel of the type email

A channel of the type `email` receives plain text in ASCII, with the subject "Nyktus: incident opened (severity)":

```text
An incident opened in Nyktus.

Severity:    medium
Techniques:  T1078
Resource:    honeytoken 9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d
First event: 2026-10-15T10:00:00Z

Open the incident: https://nyktus.example.com/incidents/0b9e7a52-3c1d-4e8f-a6b2-7d4c5e6f7a8b

Delivery 6f1d2c1e-8f0a-4f5b-9a4e-1c2b3d4e5f60
```

It holds what a chat message holds, and no more: no inventory, no personal data and not the name of the channel. `To` names every recipient of the channel. The `Message-ID` is the identifier of the delivery at the domain of the sender, such as `<6f1d2c1e-…@example.com>`, so that a mail sent twice can be recognized, and `Auto-Submitted: auto-generated` keeps automatic replies, such as out-of-office notes, from answering it. A test sends "Nyktus: test message".

### Authenticating the messages

Nyktus does not sign messages. A receiver tells messages of Nyktus from others by a secret it chose: a token in the URL, as with Slack, Teams and most automation tools, or in the header of the webhook, such as `Authorization: Bearer <token>`. HTTPS keeps it from third parties on the way. A signature would protect only the receiver, against forged alerts, which a token prevents as well, and most receivers check a token, not a signature.

### At least once

A delivery reaches its receiver at least once. If the worker stops or loses the database after the receiver accepted a message but before it recorded that, it sends the message again later. Receivers that act on alerts, such as a SOAR platform, should ignore a `delivery_id` they have seen. A mail sent again has the same `Message-ID`.

### Retries

| Outcome of an attempt | What follows |
|---|---|
| `2xx` | Delivered. |
| Other `5xx`, `408`, a timeout, a failed connection or TLS handshake | Tried again: after 30 seconds, then after twice the previous wait, up to an hour. |
| `429`, `503` | Tried again, as above, or after the wait of `Retry-After` if the receiver names a longer one, at most an hour. |
| Any other `4xx`, a redirect, a target that resolves to a blocked address, a secret that cannot be decrypted | Dead at once: no retry can mend it. |
| Mail: a reply `4xx` of the SMTP server, a server without STARTTLS | Tried again, as above. |
| Mail: a reply `5xx`, such as a refused recipient or a failed authentication (`535`), no configured SMTP server, a server that offers no authentication although a username is configured | Dead at once. |

After 10 attempts, the last about three hours after the first, a delivery is dead. The worker logs every failed attempt as `alerting: delivery failed` and a dead delivery as `alerting: delivery dead`, with the class of the failure and the status code, never the URL, the response or the password of the SMTP server. See [Logs](logs.md#worker).

A delivery whose channel was disabled or deleted before it was sent is `canceled`.

### Dead deliveries

Once the receiver is fixed, an administrator delivers a dead alert again:

```sh
curl -X POST -b cookies.txt https://nyktus.example.com/api/v1/alert-deliveries/<id>/retry
```

It starts again with a new count of attempts. The retry is recorded in the audit log as `alert_delivery.retry`.

### Reading deliveries

`GET /api/v1/incidents/{id}/deliveries` lists the deliveries of the alert of an incident, for every user who reads incidents and for API keys with `incidents:read`. Each names its channel, its `status` (`pending`, `delivered`, `dead` or `canceled`), the number of `attempts`, `next_attempt_at` while it is pending, and the last attempt: when it was, the `last_status_code` of the response or, for mail, the reply code of a refusal, if there was one, the class of its failure in `last_error` and how long it took. Administrators read a single delivery with `GET /api/v1/alert-deliveries/{id}`. Deliveries are kept as receipts: the deliveries of an alert as long as its incident, which the worker deletes after the [retention](incidents.md#retention) of closed incidents, and tests of channels for the same number of days after they were requested, once they are no longer waiting.

### Testing a channel

`POST /api/v1/alert-channels/{id}/test` asks the worker to send a test message to the channel, also to a disabled one, so that it can be tried before it receives alerts. The response (`202`) names the delivery; read its outcome with `GET /api/v1/alert-deliveries/{id}` a few seconds later. A test is attempted once. A channel has at most one test waiting (`409`, code `test_pending`). The worker sends the test, not the console, so that only the worker needs to reach the receivers, and the answer of the console reveals nothing about the network. Tests are recorded in the audit log as `alert_channel.test`.

### Encryption keys

Channels of the type `email` have no secrets. The worker decrypts the secrets of the other channels with the [encryption keys](configuration.md#encryption-keys) and refuses to start if a secret was encrypted with a key that is not listed. After a new key was put first, it encrypts the secrets of a channel again with it the next time it delivers to it. To retire the old key sooner, enter the URL and header of the remaining channels again.
