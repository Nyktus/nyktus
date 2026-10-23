# Incidents

An incident collects the events of one [scenario](scenarios.md), or of one honeytoken or [honeypot](honeypots.md) that stands alone: the first event opens it, and every further event joins it until it is closed. Triage happens on incidents, not on single events, so that an intruder who opens a URL ten times raises one incident instead of ten. When an incident opens, Nyktus raises its alert, the single notification about the incident.

The web console lists incidents under Incidents and is the way to triage them by hand; the API serves scripts and other tools.

## How events become incidents

The [worker](configuration.md#role-worker) processes every event that the trigger or the DNS role records, whether it is a request of a honeytoken or a [session](honeypots.md#events) of a honeypot:

- If the honeytoken or honeypot belonged to a scenario when the event was recorded, the event joins the open incident of the scenario. The events of every honeytoken and honeypot of a scenario share one incident with one alert: an intruder who follows the story of a scenario raises one alert, not one per decoy, and one who opens a URL and then logs in to a host of the same story is one incident.
- Otherwise the event joins the open incident of its honeytoken or honeypot.
- If there is none, the event opens a new incident and raises its alert.

A scenario, and a honeytoken or honeypot that stands alone, has at most one open incident at a time, also when several workers process its events at the same moment.

Each event keeps the scenario its honeytoken or honeypot belonged to when it was recorded, shown as `scenario_id`. When a honeytoken or honeypot joins or leaves a scenario, its events from then on go to the incident of the scenario or of the resource itself; its earlier events stay where they belong, and an open incident of the resource stays open until it is triaged or [closes after its inactivity](#closing-inactive-incidents). An incident of a scenario outlives the scenario, like events outlive their honeytoken: events recorded before a scenario was deleted still join its incident.

An incident is `open` until someone looks into it, `acknowledged` while someone does, and `closed` when the triage is finished. An acknowledged incident is still open: it keeps collecting events. A closed incident is never opened again. The next event of its scenario, honeytoken or honeypot opens a new incident with a new alert.

Close an incident once its triage is finished. As long as it stays open, new events of its scenario, honeytoken or honeypot join it without an alert, even if they come from someone else weeks later.

### Closing inactive incidents

The [worker](database.md#periodic-tasks) closes incidents, open or acknowledged, whose last event was more than `NYKTUS_INCIDENT_AUTO_CLOSE_DAYS` ago, 14 by default, every 15 minutes, so that a forgotten incident does not swallow the alerts of later intrusions. A triage does not count as activity: what keeps an incident open is a new event. Set the variable to `0` to leave every incident open until it is triaged; otherwise it is between 1 and 365 days. The [audit log](audit-log.md) records each closing as `incident.update` of the field `status` by the system, and the log of the worker as `incident: closed`. An event that arrives while its incident closes opens a new incident with a new alert.

An incident names what it correlates in `resource_name`: the name of the scenario, honeytoken or honeypot at the moment the incident opened. Each event keeps the names of its honeytoken or honeypot and of its scenario when it is recorded, and the first event gives the incident its name. The name is a snapshot: renaming or deleting the resource does not change it, and later events do not either, so an incident still says what was triggered. Look at `resource_id` to find the resource itself, if it still exists.

An event is processed once and belongs to exactly one incident. Events outlive their honeytoken or honeypot, and so do incidents: deleting a honeytoken, a honeypot or a scenario keeps both.

## Severity

The severity says how urgently someone should look at an incident: `low`, `medium`, `high` or `critical`. Every event keeps the [severity of its honeytoken](honeytokens.md#severity) or [honeypot](honeypots.md#severity) at the time it was recorded, and the incident takes the highest severity of its events. A later change of the honeytoken or honeypot does not change recorded events or their incidents.

An analyst can [override](#triage) the severity, including with `info` for an incident that turned out to be irrelevant. The incident then has the severity of the override; `event_severity` keeps what the events suggest.

## Techniques

An incident holds every [technique](honeytokens.md#techniques) of its events. Each event keeps the techniques that its honeytoken had when it was requested, so a change of the honeytoken affects only later events; the event of a session keeps those of its [kind of event](honeypots.md#events) and of its honeypot. An analyst can [override](#triage) the techniques; `event_techniques` keeps those of the events.

## Alerts

The alert of an incident reports the severity and the techniques that the incident had when it opened. Later events change the incident, but not its alert. The worker delivers the alert to every enabled [alert channel](alerting.md); `GET /api/v1/incidents/{id}/deliveries` shows whether it reached them.

## Reading incidents and events

Every role reads incidents and events, with a session or with an [API key](api-keys.md) that carries the scope `incidents:read` or `events:read`:

- `GET /api/v1/incidents` lists incidents from the most recently opened to the oldest, 50 per page by default and at most 200 (`limit`). To read the next page, pass the `next_cursor` of the response as `cursor`, with the same filters. `status` narrows the list to one or more statuses, separated by commas, such as `status=open,acknowledged` for every incident that is not closed; `resource_id` to the incidents of one scenario, honeytoken or honeypot. `resource_type` of an incident says which: `scenario`, `honeytoken` or `honeypot`. The events of a honeytoken or honeypot in a scenario belong to the incidents of the scenario.
- `GET /api/v1/incidents/<id>` returns one incident.
- `GET /api/v1/events` lists events from the most recently recorded to the oldest, paged in the same way. `incident_id` narrows the list to the events of an incident. To read the events of a honeytoken or honeypot, list its incidents, and those of its scenario, and then their events; `resource_id` of an event names its honeytoken or honeypot, `resource_type` says which, and `scenario_id` is the scenario it belonged to.
- `GET /api/v1/events/<id>` returns one event, with the request (`http`), the query (`dns`) or the session (`sensor`) that it recorded. `techniques` and `severity` of an event are those its honeytoken or honeypot had when it was recorded.

Events are listed by the time they were recorded (`recorded_at`), not the time the request or query arrived (`occurred_at`): the DNS role records a query up to five minutes after it arrived. Events recorded meanwhile do not shift the following pages. If you collect events regularly, for example into a SIEM, read again from a few seconds before the newest event you have and skip the identifiers you already know, because an event is listed by the time it was written, which can precede the commit of a slow transaction.

An incident shows its effective `severity` and `techniques` next to what the events suggest (`event_severity`, `event_techniques`) and the overrides of an analyst (`severity_override`, `techniques_override`, null if there are none).

## Triage

In the web console, open Incidents. The list shows the incidents that are not closed, newest first, with their status, severity, the scenario, honeytoken or honeypot, and the time of the last event; the filter shows the others. While the page is open and visible, it looks for a newer incident once a minute and says so without moving the list. The overview says that incidents wait when one is open, without a number.

An incident opens with its events, the request, the query or the session that each recorded. Acknowledge it to say that you look into it, and close it when the triage is finished; closing asks first, because a closed incident never opens again. Below, you change the notes, override the severity and override the techniques. The console sends only what you changed. Everything that an attacker sent, such as headers, user names, database names and search filters, appears as text exactly as it arrived, in its own direction so that it cannot reorder the text around it; characters that show nothing, and spaces other than the plain one, are marked with their code point. Administrators and users triage; the role `viewer` only reads.

Through the API, administrators and users with the role `user` triage incidents with a session or with an [API key](api-keys.md) that carries the scopes `incidents:write` and `incidents:read`:

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

Events contain personal data: the address of the client, or for DNS the address of the resolver, or for a honeypot the address of the attacker, and the `User-Agent`, `Referer` and `Accept-Language` headers that the client sent. The event of a session also holds what the attacker typed into the honeypot, such as user names, bind names and search filters; a person who mistypes the address of a host can type their own user name, which is why passwords are never stored, only their length. Incidents and alerts contain none of it; they name the scenario, honeytoken or honeypot, the times, the severity and the techniques.

Every read of events is recorded in the [audit log](audit-log.md) as `events.read`, at most once per user or API key and minute. A read that cannot be recorded returns no events. Integrations that only follow incidents, such as a ticket system, need keys without the scope `events:read`.

Nyktus records these data to detect and investigate intrusions into your network. In the EU, this is usually covered by the legitimate interest in the security of networks and information (Art. 6(1)(f) and Recital 49 GDPR). Record it in your records of processing activities. Every role reads events, because triage needs them: grant accounts, including the role `viewer`, only to people who triage incidents, and give integrations that do not need client addresses keys without `events:read`. Events are deleted after the [retention](#retention).

## Retention

The [worker](database.md#periodic-tasks) deletes, every hour, what is older than `NYKTUS_EVENT_RETENTION_DAYS`, 180 days by default, between 30 and 3650:

- **Events**, counted from when they were recorded, whether their incident is open or closed. An event that has not been assigned to an incident yet stays until it is.
- **Closed incidents**, counted from when they closed, with their alert and its [deliveries](alerting.md#reading-deliveries). Open incidents stay; their `event_count` keeps counting the deleted events, so an incident can list fewer events than it counts.

The deletion is not recorded in the audit log; the log of the worker records how many rows each run deleted. Backups of the database hold events beyond the retention. Give them a retention of their own that fits the one above.

## Audit

The [audit log](audit-log.md) records every triage as `incident.update` with the names of the changed fields, never their values, and the reads of events as `events.read`. A triage that changes no value is not recorded. Reads of incidents are not recorded: Nyktus stores no personal data in them. Notes are free text; keep personal data, such as the names of employees, out of them, or restrict who reads incidents accordingly.
