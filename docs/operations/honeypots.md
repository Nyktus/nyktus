# Honeypots

A honeypot is a network service that nobody has a reason to connect to, such as an SSH server on a host that the team never uses or a directory server that no application knows. The sensor `nyktus-sensor` emulates it inside the monitored network: it answers like the real service, but offers nothing behind the login, and reports every session to the trigger.

This page covers the management of honeypots in the console and what the trigger accepts from a sensor. Installing, configuring and running the sensor is described in [Sensor](sensor.md); this version of the sensor emulates all four services. A honeypot that no sensor runs has the [status](#status) `never`.

## Services

| Service | Emulates | Typical placement |
|---|---|---|
| `ssh` | an SSH server | a jump host or a server that admins would try with stolen credentials |
| `telnet` | a Telnet login, as on network devices and old servers | a switch, a printer or an appliance in a management network |
| `postgres` | a PostgreSQL server | a database host named in a configuration file or a connection string |
| `ldap` | a directory server | a domain controller or a directory that tools look for when they map the network |

A honeypot is one service on one address. To emulate several services of one host, create a honeypot for each and add them to the same [scenario](#scenarios), so that their events become one incident. A honeypot has no port in the console: the sensor reports the port it was reached on.

## Creating a honeypot

In the web console, open Honeypots and choose New honeypot. After you create it, the page shows the secret and the entry for the configuration of the sensor, with a button to copy each. They are shown once: the page forgets them when you confirm that you copied them or leave it, and keeps them nowhere in the browser. To replace the secret, choose Replace the secret on the page of the honeypot; the console asks first, because a sensor that still uses the old secret is shut out.

Administrators and users with the role `user` create honeypots, with a session or with an [API key](api-keys.md) that carries the scope `honeypots:write`:

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/honeypots \
  --header 'Content-Type: application/json' \
  --data @honeypot.json \
  --cookie cookies.txt
```

with `honeypot.json`:

```json
{
  "service": "ssh",
  "name": "Jump host in the admin network",
  "notes": "VLAN 20, rack 4, address 10.20.0.15; DNS name jump02",
  "techniques": ["T1078"]
}
```

| Field | Rules |
|---|---|
| `service` | Required. `ssh`, `telnet`, `postgres` or `ldap`. It cannot be changed later, because the sensor is configured for it. |
| `name` | Required. 1 to 100 printable characters without leading or trailing spaces. |
| `notes` | Optional. Where the honeypot runs and why, up to 2000 characters; line breaks and tabs are allowed. |
| `enabled` | Optional, `true` by default. |
| `techniques` | Optional. Up to 20 distinct identifiers of MITRE ATT&CK techniques that a session with the honeypot suggests, such as `T1078`. See [Techniques](honeytokens.md#techniques). |
| `severity` | Optional. `low`, `medium`, `high` or `critical`; `medium` by default. See [Severity](#severity). |

The answer is the new honeypot with its secret and status `201`:

```json
{
  "id": "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d",
  "service": "ssh",
  "name": "Jump host in the admin network",
  "notes": "VLAN 20, rack 4, address 10.20.0.15; DNS name jump02",
  "enabled": true,
  "techniques": ["T1078"],
  "severity": "medium",
  "scenario_id": null,
  "status": "never",
  "last_seen_at": null,
  "sensor_version": null,
  "created_at": "2026-10-19T09:30:00Z",
  "updated_at": "2026-10-19T09:30:00Z",
  "secret": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "sensor_config": "- id: \"7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d\"\n  service: \"ssh\"\n  # Address and port to listen on. Ports below 1024 need CAP_NET_BIND_SERVICE.\n  listen: \":22\"\n  # The private key of the server. Create it once, without a passphrase, with\n  # ssh-keygen -t ed25519 -N '' -f and the path below, and keep it: a host key\n  # that changes would identify the honeypot, and one that two honeypots share\n  # would tie them together. The path is relative to this file.\n  host_key_file: \"ssh_host_key_7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d\"\n  secret: \"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\"\n"
}
```

`sensor_config` is the entry of the honeypot for the [configuration file of the sensor](sensor.md#setting-up-a-sensor): a list item for `honeypots:` with the identifier, the service, the usual port of the service as the address to listen on, and the secret; for `ssh` also the file of the host key, which you create yourself (see [SSH honeypots](sensor.md#ssh-honeypots)). It holds the secret, so it is shown once with it. It holds neither the name nor the notes of the honeypot, which have no place on the host of a sensor. The entry of a `postgres` or `ldap` honeypot has the same keys and takes no `banner` (see [Sensor](sensor.md)).

## The secret

The sensor authenticates to the trigger with the `secret` of the honeypot: 256 random bits, 43 characters without a prefix, so that nothing on the host of the sensor marks it as a decoy. **The secret is shown only in this response** and is sent with `Cache-Control: no-store`. Nyktus keeps only a SHA-256 hash of it; no later response, log or audit entry contains it. Store it where the sensor reads it: in the configuration file or in a [secret file](sensor.md#secrets-in-files) that only the user of the sensor can read.

Every honeypot has a secret of its own. A secret that an attacker takes from the host of a sensor reveals only the honeypots configured there.

### Replacing the secret

`POST /api/v1/honeypots/<id>/secret` gives a honeypot a new secret, for example when the old one was lost, exposed or left on a host that was decommissioned. The answer is the honeypot with the new `secret`, as when it was created, and the same applies: it is shown once.

The old secret stops working at once. A sensor that still uses it is shut out until you configure it with the new one. The honeypot forgets what its sensor last reported: its `status` is `never` until a sensor reports with the new secret, so you can see when the replacement has reached the sensor. The new `sensor_config` holds the new secret; put it into the configuration of the sensor and [restart the sensor](sensor.md#replacing-a-secret).

## Status

The console shows whether a sensor reports for a honeypot, from the time of its last report.

| `status` | Meaning |
|---|---|
| `never` | No sensor has reported with the current secret: the honeypot is new, its secret was replaced, or the sensor does not reach the trigger. |
| `online` | A sensor reported within the last 15 minutes. |
| `offline` | The last report is older than 15 minutes: the sensor stopped, lost its connection to the trigger or no longer runs this honeypot. |

`last_seen_at` is the time of the last report, and `sensor_version` the version that the sensor named. A [heartbeat](#heartbeat) or a [session](#session) that was accepted sets them, at most once a minute; the console cannot. The status is evaluated against the clock of the database when you read the honeypot. An offline honeypot raises no alert: alerts belong to incidents, which only attacker activity opens. The [metric](metrics.md) `nyktus_honeypots` counts the honeypots by status, so that your monitoring can tell you when a sensor stops.

## Listing, changing and deleting

- `GET /api/v1/honeypots` lists honeypots from the newest to the oldest, 50 per page by default and at most 200 (`limit`). To read the next page, pass the `next_cursor` of the response as `cursor`, with the same filters. `service=<service>`, `enabled=true` or `enabled=false` and `scenario_id=<scenario>` narrow the list.
- `GET /api/v1/honeypots/<id>` returns one honeypot.
- `PATCH /api/v1/honeypots/<id>` changes `name`, `notes`, `enabled`, `techniques` or `severity`. Members that you leave out stay unchanged; `"techniques": []` removes the techniques. The service and the secret cannot be changed this way.
- `DELETE /api/v1/honeypots/<id>` deletes a honeypot. Its secret stops working. Stop the honeypot on the sensor as well, so that a service without a honeypot in the console does not mislead your own team.

Every role reads honeypots; viewers cannot change them.

## Severity

Every event of a honeypot receives the severity of the honeypot, whatever the attacker did, and an [incident](incidents.md#severity) takes the highest severity of its events. A new honeypot has `medium` for every service: a honeypot answers whoever connects, including the vulnerability scanners and inventory tools of your own team. Choose a higher severity for a honeypot that nothing in your network should ever reach, and exclude the addresses of honeypots from your own scanners where you can. A change applies to later events only. `info` is not a severity of a honeypot.

## Scenarios

A honeypot can belong to a [scenario](scenarios.md), like a honeytoken. Its `scenario_id` names the scenario, or is `null` for a honeypot that stands alone. A new honeypot stands alone; `PUT /api/v1/honeypots/<id>/scenario` with `{"scenario_id": "<scenario>"}` adds it to a scenario, and `DELETE /api/v1/honeypots/<id>/scenario` removes it:

- Assigning a honeypot to the scenario it belongs to changes nothing.
- A honeypot that belongs to another scenario receives `409` with the code `honeypot_in_scenario`. Remove it from that scenario first, so that nothing takes a honeypot from a scenario by mistake.
- A scenario that does not exist receives `422` with the code `scenario_not_found`.

Changing the scenario of a honeypot needs the permission `honeypots:write` only. Deleting a scenario keeps its honeypots unless you ask to delete them, which needs `honeypots:write` as well; see [Listing, changing and deleting](scenarios.md#listing-changing-and-deleting) of scenarios.

## How a sensor reports

A sensor reports to the [trigger](configuration.md#role-trigger), the same internet-facing address that serves the URLs of honeytokens, with a `POST` to `/`. It authenticates with the [secret](#the-secret) of the honeypot as a bearer token and sends one JSON document with a `version` and a `type`:

```http
POST / HTTP/1.1
Authorization: Bearer <secret>
Content-Type: application/json
```

Use TLS: the secret travels in the header. The sensor verifies the certificate of the trigger in every case, and accepts a private authority through `SSL_CERT_FILE`; see [TLS and a private authority](sensor.md#tls-and-a-private-authority).

### Session

The sensor sends a session once, when it ends or after a short maximum delay, so that the first event of an incident describes what the attacker did, not only the handshake.

```json
{
  "version": 1,
  "type": "session",
  "session_id": "0123456789abcdef0123456789abcdef",
  "age_ms": 1500,
  "duration_ms": 4200,
  "client_ip": "203.0.113.9",
  "port": 22,
  "client_version": "SSH-2.0-OpenSSH_9.6",
  "attempts": [
    { "username": "root", "password_length": 8 },
    { "username": "admin", "key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }
  ]
}
```

| Field | Rules |
|---|---|
| `version` | Required. `1`. |
| `type` | Required. `session`. |
| `session_id` | Required. 128 random bits as 32 lowercase hexadecimal digits, chosen by the sensor for each session. A session that reaches the trigger twice, for example because the sensor repeated a request, is stored once. |
| `age_ms` | Required, not negative. How long ago the session began, in milliseconds, measured with the monotonic clock of the sensor, so that the clocks of the sensor and the server need not agree. A session that began longer than five minutes ago is stored as if it had begun five minutes ago; a sensor drops such a report instead of sending it. |
| `duration_ms` | Required, not negative. How long the session lasted, in milliseconds. A session is reported within five minutes of its beginning, so a value beyond 300,000 is stored as 300,000. |
| `client_ip` | Required. The address of the attacker, as the sensor saw it. |
| `port` | Required. The port of the honeypot that the attacker reached, 1 to 65535. |
| `attempts` | Required, possibly empty. At most 6 logins or binds, in the order in which they were made, each with `username` (required, possibly empty; for a directory the distinguished name of the bind), `password_length` (the length of the password that was sent, 0 to 65535, or absent) and `key_fingerprint` (the `SHA256:` fingerprint of an offered public key, or absent). **A password is never sent and never stored**, only its length. |
| `client_version` | Optional, `ssh` only. The version string of the client, up to 128 bytes. |
| `database`, `application_name` | Optional, `postgres` only. What the client asked for and called itself, up to 64 bytes each. |
| `query` | Optional, `ldap` only. The first search of the session, with `base_dn` and `filter` (both required, the base may be empty for the root of the directory), up to 256 bytes each. |

The sensor does not send the service, the severity, the techniques or the kind of event. The service, the severity and the techniques come from the honeypot, and the server derives the kind of event from the content.

Every text field is chosen by the attacker. The trigger cuts it to its length and replaces characters that are not printable, as for the headers of a request.

### Heartbeat

The sensor says that it is alive when it starts and every five minutes, for each honeypot it runs:

```json
{ "version": 1, "type": "heartbeat", "sensor_version": "0.1.0" }
```

`sensor_version` is optional: up to 32 characters (letters, digits and `.+_-`, starting with a letter or digit). A heartbeat sets the time of the [last report](#status) and the version, at most once a minute, and nothing else. It never records an event, opens an incident or raises an alert, and it works for a disabled honeypot as well, so that the console shows whether its sensor runs.

### The answer

The trigger answers every report like any other `POST` to `/`: the same redirect to the default target, whether the report was recorded, the secret is unknown, the honeypot is disabled or deleted, the database failed or the report was malformed. The sensor learns nothing from the answer, and neither does anyone who finds the address. A sensor therefore repeats a report only after a failure of the transport, or of a proxy in front of the trigger that answers 502, 503 or 504, at most three times with a growing pause, and follows no redirect. It drops a session that has waited longer than five minutes, so the age of a report is never beyond what the server takes; see [How reports are delivered](sensor.md#how-reports-are-delivered). The [log of the trigger](logs.md#trigger) names the outcome.

### Versions

A report names its version, and the server reads only versions it knows. A report with a version or a member that the server does not know is not stored; the log of the trigger records `rejected` with the reason `unsupported_version` or `invalid_report`. A change of the report needs a new version, so update the server before the sensors.

## Events

Every session that a sensor reports for an enabled honeypot becomes one event, with its job in the same transaction, and joins the [incident](incidents.md) of the honeypot's scenario, or of the honeypot if it stands alone.

The kind of event is the highest stage that the session reached:

| Kind | A session that | Techniques it suggests |
|---|---|---|
| `connection` | only connected | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery |
| `login_attempt` | tried to log in or bind | T1110 Brute Force; for `ssh` also T1021.004 Remote Services: SSH |
| `directory_query` | searched a directory (`ldap` only) | T1087.002 Account Discovery: Domain Account |

A session that reached several stages raises one event of the highest, so that a directory query is not hidden by the bind before it. The event keeps the techniques of its kind, followed by the techniques of the honeypot, the severity of the honeypot, its service and its scenario as they were when the event arrived; a later change of the honeypot, or its deletion, does not change the event. `occurred_at` is when the session began; `recorded_at` is when the event was written.

The event holds what the attacker typed: user names and bind names, the version string of the client, the database and the search of a directory client, with the length of each password and the fingerprint of each key offered. This is personal data, and it is untrusted: treat it as claims, not facts. A password is never stored: a person who mistypes the address of a host in a terminal sends their own password to the honeypot, and an event is readable by everyone who may read events for the length of the [retention](database.md#periodic-tasks). Alerts, metrics and logs hold none of it. [Reading incidents and events](incidents.md#reading-incidents-and-events) describes how to read them.

## Limits

- At most 10 events per honeypot and minute are stored. Further sessions are counted and logged as `trigger: reports not recorded`; a flood of connections to one honeypot cannot fill the database.
- A session is stored once per `session_id` and honeypot.
- A session of a disabled honeypot is not stored. Its heartbeats are.
- The body of a report is limited to 64 KiB.
- A session counts as a sign of life, like a heartbeat, if it was stored or turned away by the limit or as a duplicate; one that is refused does not.

## Who can read honeypots

Every role reads honeypots; `admin` and `user` create, change and delete them and replace their secrets. [API keys](api-keys.md) carry the scopes `honeypots:read` and `honeypots:write`; the second requires the first.

Honeypots and their notes are part of the inventory: whoever reads them knows which addresses to avoid. Give integrations that do not manage honeypots keys without these scopes, and grant the role `viewer` only to people who need to see the decoys.

## Audit

The [audit log](audit-log.md) records every creation as `honeypot.create`, every change as `honeypot.update` with the names of the changed fields, and every deletion as `honeypot.delete`, also one with its scenario. A new secret is recorded as `honeypot.update` with the field `secret`, never its value, and joining or leaving a scenario with the field `scenario_id`. Entries name the honeypot by its identifier only, never by its name or notes. A change that changes no value is not recorded. Reads are not recorded.
