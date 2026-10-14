# Incidents

An incident collects the events of one honeytoken: the first event opens it, and every further event joins it until it is closed. Triage happens on incidents, not on single events, so that an intruder who opens a URL ten times raises one incident instead of ten. When an incident opens, Nyktus raises its alert, the single notification about the incident.

> This version records alerts, but does not deliver them yet. The web console does not show incidents yet; read and triage them through the API.

## How events become incidents

The [worker](configuration.md#role-worker) processes every event that the trigger or the DNS role records:

- If the honeytoken has an open incident, the event joins it.
- Otherwise the event opens a new incident and raises its alert.

A honeytoken has at most one open incident at a time, also when several workers process its events at the same moment.

An incident is `open` until someone looks into it, `acknowledged` while someone does, and `closed` when the triage is finished. An acknowledged incident is still open: it keeps collecting the events of its honeytoken. A closed incident is never opened again. The next event of its honeytoken opens a new incident with a new alert.

Close an incident once its triage is finished. As long as it stays open, new events of its honeytoken join it without an alert, even if they come from someone else weeks later.

An event is processed once and belongs to exactly one incident. Events outlive their honeytoken, and so do incidents: deleting a honeytoken keeps both.

## Severity

The severity says how urgently someone should look at an incident: `low`, `medium`, `high` or `critical`. Every event suggests a severity by the type of its honeytoken, and the incident takes the highest severity of its events:

| Type | Severity | Reason |
|---|---|---|
| `web_url` | `medium` | Opening a URL is deliberate, but what it pretends to lead to is unknown. |
| `web_image` | `low` | Mail gateways, previews and scanners load images without anyone opening them. |
| `dns` | `medium` | Resolving a name is deliberate, as for a URL. |

An analyst can [override](#triage) the severity, including with `info` for an incident that turned out to be irrelevant. The incident then has the severity of the override; `event_severity` keeps what the events suggest.

## Techniques

An incident holds every [technique](honeytokens.md#techniques) of its events. Each event keeps the techniques that its honeytoken had when it was requested, so a change of the honeytoken affects only later events. An analyst can [override](#triage) the techniques; `event_techniques` keeps those of the events.

## Alerts

The alert of an incident reports the severity and the techniques that the incident had when it opened. Later events change the incident, but not its alert.

## Reading incidents and events

Every role reads incidents and events, with a session or with an [API key](api-keys.md) that carries the scope `incidents:read` or `events:read`:

- `GET /api/v1/incidents` lists incidents from the most recently opened to the oldest, 50 per page by default and at most 200 (`limit`). To read the next page, pass the `next_cursor` of the response as `cursor`, with the same filters. `status` narrows the list to one or more statuses, separated by commas, such as `status=open,acknowledged` for every incident that is not closed; `resource_id` to the incidents of one honeytoken.
- `GET /api/v1/incidents/<id>` returns one incident.
- `GET /api/v1/events` lists events from the most recently recorded to the oldest, paged in the same way. `incident_id` narrows the list to the events of an incident. To read the events of a honeytoken, list its incidents and then their events.
- `GET /api/v1/events/<id>` returns one event, with the request (`http`) or the query (`dns`) that it recorded.

Events are listed by the time they were recorded (`recorded_at`), not the time the request or query arrived (`occurred_at`): the DNS role records a query up to five minutes after it arrived. Events recorded meanwhile do not shift the following pages. If you collect events regularly, for example into a SIEM, read again from a few seconds before the newest event you have and skip the identifiers you already know, because an event is listed by the time it was written, which can precede the commit of a slow transaction.

An incident shows its effective `severity` and `techniques` next to what the events suggest (`event_severity`, `event_techniques`) and the overrides of an analyst (`severity_override`, `techniques_override`, null if there are none).

## Triage

Administrators and users with the role `user` triage incidents, with a session or with an [API key](api-keys.md) that carries the scopes `incidents:write` and `incidents:read`:

```sh
curl --fail-with-body --request PATCH https://nyktus.example.com/api/v1/incidents/<id> \
  --header 'Content-Type: application/json' \
  --data '{"status": "acknowledged", "notes": "Checking the backup jobs of fs01."}' \
  --cookie cookies.txt
```

| Field | Rules |
|---|---|
| `status` | `open`, `acknowledged` or `closed`. The status only moves forward and can skip `acknowledged`; a request to move it back, for example to open a closed incident again, receives `409` with the code `invalid_state`. Nyktus records when the status changed as `acknowledged_at` and `closed_at`. |
| `notes` | Replaces the notes, up to 10000 characters. Line breaks and tabs are allowed; other control characters and invisible format characters, such as those that change the direction of text, are not. |
| `severity_override` | `info`, `low`, `medium`, `high` or `critical`; `null` removes the override. |
| `techniques_override` | Up to 20 distinct identifiers of techniques, as for honeytokens. An empty list states that the incident suggests no technique; `null` removes the override. |

Members that you leave out stay unchanged. Notes and overrides can still be changed after an incident is closed, for example to record the outcome of the triage.

## Processing

The worker looks for new events every second and processes a backlog without waiting. Several workers share the events without further setup, and a worker processes up to `NYKTUS_WORKER_CONCURRENCY` events at a time.

An event is assigned to its incident in the same transaction that marks it as processed, so no event is lost or processed twice, also when a worker stops in the middle. If an event cannot be processed, the worker logs `incident: event not processed` and tries it again later, after 2 seconds at first and up to an hour after repeated failures; other events are not held up. While the database is unreachable, the worker logs `worker: job failed` and tries again after up to 30 seconds. See [Logs](logs.md#worker).

When the worker stops, it takes no further events and gives those in progress up to 15 seconds to finish or to be postponed. An event that does not finish stays unprocessed and is taken up again by the next worker.

## Personal data

Events contain personal data: the address of the client, or for DNS the address of the resolver, and the `User-Agent`, `Referer` and `Accept-Language` headers that the client sent. Incidents and alerts contain none of it; they name the honeytoken, the times, the severity and the techniques.

Every read of events is recorded in the [audit log](audit-log.md) as `events.read`, at most once per user or API key and minute. A read that cannot be recorded returns no events. Integrations that only follow incidents, such as a ticket system, need keys without the scope `events:read`.

Nyktus records these data to detect and investigate intrusions into your network. In the EU, this is usually covered by the legitimate interest in the security of networks and information (Art. 6(1)(f) and Recital 49 GDPR). Record it in your records of processing activities. Every role reads events, because triage needs them: grant accounts, including the role `viewer`, only to people who triage incidents, and give integrations that do not need client addresses keys without `events:read`. This version keeps events until the database is deleted.

## Audit

The [audit log](audit-log.md) records every triage as `incident.update` with the names of the changed fields, never their values, and the reads of events as `events.read`. A triage that changes no value is not recorded. Reads of incidents are not recorded: Nyktus stores no personal data in them. Notes are free text; keep personal data, such as the names of employees, out of them, or restrict who reads incidents accordingly.
