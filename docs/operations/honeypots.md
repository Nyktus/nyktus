# Honeypots

A honeypot is a network service that nobody has a reason to connect to, such as an SSH server on a host that the team never uses or a directory server that no application knows. The sensor `nyktus-sensor` emulates it inside the monitored network: it answers like the real service, but offers nothing behind the login, and reports every session to the trigger.

This page covers the management of honeypots in the console.

## Services

| Service | Emulates | Typical placement |
|---|---|---|
| `ssh` | an SSH server | a jump host or a server that admins would try with stolen credentials |
| `telnet` | a Telnet login, as on network devices and old servers | a switch, a printer or an appliance in a management network |
| `postgres` | a PostgreSQL server | a database host named in a configuration file or a connection string |
| `ldap` | a directory server | a domain controller or a directory that tools look for when they map the network |

A honeypot is one service on one address. To emulate several services of one host, create a honeypot for each and add them to the same [scenario](#scenarios), so that their events become one incident. A honeypot has no port in the console: the sensor reports the port it was reached on.

## Creating a honeypot

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
  "secret": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
}
```

## The secret

The sensor authenticates to the trigger with the `secret` of the honeypot: 256 random bits, 43 characters without a prefix, so that nothing on the host of the sensor marks it as a decoy. **The secret is shown only in this response** and is sent with `Cache-Control: no-store`. Nyktus keeps only a SHA-256 hash of it; no later response, log or audit entry contains it. Store it where the sensor reads it, for example in a file that only the user of the sensor can read.

Every honeypot has a secret of its own. A secret that an attacker takes from the host of a sensor reveals only the honeypots configured there.

### Replacing the secret

`POST /api/v1/honeypots/<id>/secret` gives a honeypot a new secret, for example when the old one was lost, exposed or left on a host that was decommissioned. The answer is the honeypot with the new `secret`, as when it was created, and the same applies: it is shown once.

The old secret stops working at once. A sensor that still uses it is shut out until you configure it with the new one. The honeypot forgets what its sensor last reported: its `status` is `never` until a sensor reports with the new secret, so you can see when the replacement has reached the sensor.

## Status

The console shows whether a sensor reports for a honeypot. A sensor reports for each of its honeypots when it starts and every five minutes, and every session it reports counts as well.

| `status` | Meaning |
|---|---|
| `never` | No sensor has reported with the current secret: the honeypot is new, its secret was replaced, or the sensor does not reach the trigger. |
| `online` | A sensor reported within the last 15 minutes. |
| `offline` | The last report is older than 15 minutes: the sensor stopped, lost its connection to the trigger or no longer runs this honeypot. |

`last_seen_at` is the time of the last report, and `sensor_version` the version that the sensor named. The status is evaluated against the clock of the database when you read the honeypot. An offline honeypot raises no alert: alerts belong to incidents, which only attacker activity opens.

## Listing, changing and deleting

- `GET /api/v1/honeypots` lists honeypots from the newest to the oldest, 50 per page by default and at most 200 (`limit`). To read the next page, pass the `next_cursor` of the response as `cursor`, with the same filters. `service=<service>`, `enabled=true` or `enabled=false` and `scenario_id=<scenario>` narrow the list.
- `GET /api/v1/honeypots/<id>` returns one honeypot.
- `PATCH /api/v1/honeypots/<id>` changes `name`, `notes`, `enabled`, `techniques` or `severity`. Members that you leave out stay unchanged; `"techniques": []` removes the techniques. The service and the secret cannot be changed this way.
- `DELETE /api/v1/honeypots/<id>` deletes a honeypot. Its secret stops working, and its events remain. Stop the honeypot on the sensor as well, so that a service without a honeypot in the console does not mislead your own team.

Every role reads honeypots; viewers cannot change them.

## Severity

Every event of a honeypot receives the severity of the honeypot, whatever the attacker did, and an [incident](incidents.md#severity) takes the highest severity of its events. A new honeypot has `medium` for every service: a honeypot answers whoever connects, including the vulnerability scanners and inventory tools of your own team. Choose a higher severity for a honeypot that nothing in your network should ever reach, and exclude the addresses of honeypots from your own scanners where you can. A change applies to later events only. `info` is not a severity of a honeypot.

## Scenarios

A honeypot can belong to a [scenario](scenarios.md), like a honeytoken. Its `scenario_id` names the scenario, or is `null` for a honeypot that stands alone. A new honeypot stands alone; `PUT /api/v1/honeypots/<id>/scenario` with `{"scenario_id": "<scenario>"}` adds it to a scenario, and `DELETE /api/v1/honeypots/<id>/scenario` removes it:

- Assigning a honeypot to the scenario it belongs to changes nothing.
- A honeypot that belongs to another scenario receives `409` with the code `honeypot_in_scenario`. Remove it from that scenario first, so that nothing takes a honeypot from a scenario by mistake.
- A scenario that does not exist receives `422` with the code `scenario_not_found`.

Changing the scenario of a honeypot needs the permission `honeypots:write` only. Deleting a scenario keeps its honeypots unless you ask to delete them; see [Listing, changing and deleting](scenarios.md#listing-changing-and-deleting) of scenarios.

## Who can read honeypots

Every role reads honeypots; `admin` and `user` create, change and delete them and replace their secrets. [API keys](api-keys.md) carry the scopes `honeypots:read` and `honeypots:write`; the second requires the first.

Honeypots and their notes are part of the inventory: whoever reads them knows which addresses to avoid. Give integrations that do not manage honeypots keys without these scopes, and grant the role `viewer` only to people who need to see the decoys.

## Audit

The [audit log](audit-log.md) records every creation as `honeypot.create`, every change as `honeypot.update` with the names of the changed fields, and every deletion as `honeypot.delete`, also one with its scenario. A new secret is recorded as `honeypot.update` with the field `secret`, never its value, and joining or leaving a scenario with the field `scenario_id`. Entries name the honeypot by its identifier only, never by its name or notes. A change that changes no value is not recorded. Reads are not recorded.
