// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metrics exposes the state of Nyktus to a monitoring system in the
// text format of Prometheus: the queues of events and alerts, the open
// incidents, the honeypots by whether a sensor reports for them and the
// periodic tasks of the worker.
//
// The values come from a function of the database that returns aggregates
// only, and labels name fixed states or tasks, never a resource, an address
// or a name, so that the metrics reveal neither the inventory nor personal
// data. They do reveal whether incidents are open, which tells an intruder
// whether they were noticed, so only administrators and keys with the scope
// metrics:read read them.
package metrics

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/platform/buildinfo"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/httpx"
)

// family describes a metric that the database reports.
type family struct {
	name string
	help string
	// label names the label of the metric, or is empty for a metric with a
	// single value.
	label string
}

// families lists the metrics that the database reports, in the order of the
// output. The database names them without the prefix nyktus_.
var families = []family{
	{"event_jobs", "Jobs of events that wait to be processed.", ""},
	{"event_jobs_due", "Jobs of events that are due.", ""},
	{"event_jobs_retrying", "Jobs of events that failed at least once and wait for another attempt.", ""},
	{"event_jobs_oldest_age_seconds", "Age of the oldest job of an event, or 0 without jobs.", ""},
	{"alert_deliveries", "Deliveries of alerts and tests that wait to be sent, or that failed for good, by status.", "status"},
	{"alert_deliveries_oldest_due_age_seconds", "How long the delivery that has been due longest has waited, or 0.", ""},
	{"incidents", "Incidents that are not closed, by status.", "status"},
	{"honeypots", "Honeypots by whether a sensor reports for them: never, online or offline.", "status"},
	{"periodic_task_last_success_timestamp_seconds", "When a periodic task of the worker last succeeded, or 0.", "task"},
	{"periodic_task_last_failure_timestamp_seconds", "When a periodic task of the worker last failed, or 0.", "task"},
	{"periodic_task_last_rows", "Rows that the last successful run of a periodic task removed or changed.", "task"},
}

// sample is one value that the database reports.
type sample struct {
	label string
	value float64
}

// read returns the values that the database reports, by metric. It fails on a
// metric that this package does not describe, so that a change of the
// database cannot pass unnoticed.
func read(ctx context.Context, q db.Querier) (map[string][]sample, error) {
	rows, err := q.Query(ctx, `SELECT metric, coalesce(label, ''), value FROM public.read_metrics()`)
	if err != nil {
		return nil, fmt.Errorf("read metrics: %w", err)
	}
	known := make(map[string]family, len(families))
	for _, f := range families {
		known[f.name] = f
	}
	values := map[string][]sample{}
	var name string
	var s sample
	_, err = pgx.ForEachRow(rows, []any{&name, &s.label, &s.value}, func() error {
		f, ok := known[name]
		switch {
		case !ok:
			return fmt.Errorf("unknown metric %q", name)
		case (f.label == "") != (s.label == ""):
			return fmt.Errorf("metric %q with label %q", name, s.label)
		}
		values[name] = append(values[name], s)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read metrics: %w", err)
	}
	return values, nil
}

// format returns values and the build information in the text format of
// Prometheus, version 0.0.4. Every metric is a gauge.
func format(values map[string][]sample) string {
	var b strings.Builder
	for _, f := range families {
		b.WriteString("# HELP nyktus_" + f.name + " " + f.help + "\n# TYPE nyktus_" + f.name + " gauge\n")
		for _, s := range values[f.name] {
			b.WriteString("nyktus_" + f.name)
			if f.label != "" {
				b.WriteString("{" + f.label + `="` + escapeLabel(s.label) + `"}`)
			}
			b.WriteString(" " + strconv.FormatFloat(s.value, 'g', -1, 64) + "\n")
		}
	}
	b.WriteString("# HELP nyktus_build_info The version of Nyktus and of Go that built it.\n# TYPE nyktus_build_info gauge\n")
	b.WriteString(`nyktus_build_info{version="` + escapeLabel(buildinfo.Version()) + `",go_version="` + escapeLabel(runtime.Version()) + "\"} 1\n")
	return b.String()
}

// escapeLabel escapes a label value as the text format requires.
var escapeLabel = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace

// contentType is the media type of the text format.
const contentType = "text/plain; version=0.0.4; charset=utf-8"

// Handler returns the handler of GET /api/v1/metrics, which reads the
// metrics through q.
func Handler(logger *slog.Logger, q db.Querier) http.Handler {
	if logger == nil || q == nil {
		panic("metrics: nil logger or database")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values, err := read(r.Context(), q)
		if err != nil {
			httpx.ServerError(w, r, logger, "read metrics", err)
			return
		}
		h := w.Header()
		h.Set("Content-Type", contentType)
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		// The status is sent; a failed write means that the client is gone.
		_, _ = io.WriteString(w, format(values))
	})
}
