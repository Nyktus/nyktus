# Metrics

The console reports the state of Nyktus to a monitoring system such as Prometheus: the queues of events and alerts, the incidents that are not closed, the honeypots by whether a sensor reports for them, and the [periodic tasks](database.md#periodic-tasks) of the worker. The worker listens on no port, so the console answers for it; the values come from the database, which all roles share.

## Reading the metrics

In the web console, administrators open Metrics: the page shows every family with its help text, labels and values, a time next to the metrics that report one, and the text as the server wrote it to fold open. It reads the values when it opens and when you choose Refresh, and draws no charts; use your monitoring system for those.

`GET /api/v1/metrics` returns the metrics in the text format of Prometheus, version 0.0.4. Administrators read it with a session, a monitoring system with an [API key](api-keys.md) that carries the scope `metrics:read`. Other roles and keys receive `403`. Whether incidents are open tells an intruder whether they were noticed, so give the scope only to the monitoring system and keep its key in its secret store.

A scrape configuration for Prometheus, with the key in a file:

```yaml
scrape_configs:
  - job_name: nyktus
    scheme: https
    metrics_path: /api/v1/metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/nyktus-key
    static_configs:
      - targets: ["nyktus.example.com"]
```

Every request reads the database, so scrape at most every 15 seconds; once a minute is enough. Reads are not recorded in the [audit log](audit-log.md); a request denied for a missing permission is, as for every route.

## What the metrics report

Every metric is a gauge. Values are aggregates; labels name only a fixed status or the name of a periodic task, never a honeytoken, a honeypot, an incident, a channel, an address or a name. Ages are in seconds, times in seconds since the epoch, and `0` where there is nothing to measure.

| Metric | Labels | Value |
|---|---|---|
| `nyktus_event_jobs` | | Events waiting to be [processed](incidents.md). |
| `nyktus_event_jobs_due` | | Of these, the events that are due now. |
| `nyktus_event_jobs_retrying` | | Of these, the events that failed at least once. They are tried again, at the latest every hour, and raise no alert until they are processed; the log names the cause as `incident: event not processed`. |
| `nyktus_event_jobs_oldest_age_seconds` | | Age of the oldest event that waits. |
| `nyktus_alert_deliveries` | `status`: `pending`, `dead` | [Deliveries](alerting.md#delivery) of alerts and tests that wait to be sent, and those that [failed for good](alerting.md#dead-deliveries), within the retention. |
| `nyktus_alert_deliveries_oldest_due_age_seconds` | | How long the delivery that has been due longest has waited. |
| `nyktus_incidents` | `status`: `open`, `acknowledged` | Incidents that are not closed. |
| `nyktus_honeypots` | `status`: `never`, `online`, `offline` | Honeypots by their [status](honeypots.md#status), disabled ones included. All three values are always reported, also with `0`. |
| `nyktus_periodic_task_last_success_timestamp_seconds` | `task` | When a periodic task last ran to its end. |
| `nyktus_periodic_task_last_failure_timestamp_seconds` | `task` | When a periodic task last failed. |
| `nyktus_periodic_task_last_rows` | `task` | Rows that the last successful run removed or changed. |
| `nyktus_build_info` | `version`, `go_version` | Always `1`; the labels name the version of Nyktus and of Go. |

## Suggested alerts

- **No worker.** `time() - nyktus_periodic_task_last_success_timestamp_seconds{task="delete_expired_sign_in_data"} > 900`: the task runs every five minutes, so no worker has run it for three intervals. Without a worker, events raise no alerts.
- **Events not processed.** `nyktus_event_jobs_oldest_age_seconds > 300` or `nyktus_event_jobs_retrying > 0`: events wait, and their alerts with them.
- **Alerts not delivered.** `nyktus_alert_deliveries{status="dead"} > 0` after a change, or `nyktus_alert_deliveries_oldest_due_age_seconds > 300`: a channel does not accept alerts. [Retry](alerting.md#dead-deliveries) dead deliveries once the channel works.
- **A sensor stopped.** `nyktus_honeypots{status="offline"} > 0`: no sensor has reported for a honeypot in 15 minutes. A honeypot that nobody reaches raises no alert, so this is the only sign that a sensor stopped, lost its connection to the trigger or no longer runs a honeypot. A honeypot that you removed from the sensor stays offline until you delete it in the console. `nyktus_honeypots{status="never"} > 0` for longer than it takes to set up a sensor means that a sensor has not yet reported with the current secret.
- **A periodic task fails.** `nyktus_periodic_task_last_failure_timestamp_seconds > nyktus_periodic_task_last_success_timestamp_seconds`: the log of the worker names the cause as `worker: job failed`.

Monitor the processes themselves, their memory and their connections, with the tools of your platform; Nyktus reports no metrics of the Go runtime.
