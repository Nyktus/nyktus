# Alerting

An [incident](incidents.md) raises a single alert when it opens. Nyktus delivers each alert to every enabled alert channel.

> This version manages alert channels, but does not deliver alerts yet.

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
