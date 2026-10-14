# Incidents

An incident collects the events of one honeytoken: the first event opens it, and every further event joins it until it is closed. Triage happens on incidents, not on single events, so that an intruder who opens a URL ten times raises one incident instead of ten. When an incident opens, Nyktus raises its alert, the single notification about the incident.

> This version opens incidents and records their alerts, but does not show them in the console or deliver alerts yet.

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

## Techniques

An incident holds every [technique](honeytokens.md#techniques) of its events. Each event keeps the techniques that its honeytoken had when it was requested, so a change of the honeytoken affects only later events.

## Alerts

The alert of an incident reports the severity and the techniques that the incident had when it opened. Later events change the incident, but not its alert.

## Processing

The worker looks for new events every second and processes a backlog without waiting. Several workers share the events without further setup, and a worker processes up to `NYKTUS_WORKER_CONCURRENCY` events at a time.

An event is assigned to its incident in the same transaction that marks it as processed, so no event is lost or processed twice, also when a worker stops in the middle. If an event cannot be processed, the worker logs `incident: event not processed` and tries it again later, after 2 seconds at first and up to an hour after repeated failures; other events are not held up. While the database is unreachable, the worker logs `worker: job failed` and tries again after up to 30 seconds. See [Logs](logs.md#worker).

When the worker stops, it takes no further events and gives those in progress up to 15 seconds to finish or to be postponed. An event that does not finish stays unprocessed and is taken up again by the next worker.

## Personal data

Events contain personal data: the address of the client, or for DNS the address of the resolver, and the `User-Agent`, `Referer` and `Accept-Language` headers that the client sent. Incidents and alerts contain none of it; they name the honeytoken, the times, the severity and the techniques.

Nyktus records these data to detect and investigate intrusions into your network. In the EU, this is usually covered by the legitimate interest in the security of networks and information (Art. 6(1)(f) and Recital 49 GDPR). Record it in your records of processing activities and restrict access to events like access to the [audit log](audit-log.md). This version keeps events until the database is deleted.
