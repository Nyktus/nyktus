// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package incident

import (
	"bytes"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/platform/config"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/worker"
)

// openIncident processes an event of a new honeytoken into an incident, moves
// its last event lastEvent into the past and returns the honeytoken and the
// incident.
func (f fixture) openIncident(t *testing.T, lastEvent time.Duration) (resource, incident string) {
	t.Helper()
	resource, _ = f.honeytoken(t, "web_url", nil)
	f.event(t, resource, "web_url", nil, time.Now())
	incident = f.process(t).IncidentID
	if _, err := f.owner.Exec(t.Context(), `
UPDATE incidents SET first_event_at = clock_timestamp() - $2::interval, last_event_at = clock_timestamp() - $2::interval,
	opened_at = clock_timestamp() - $2::interval
WHERE id = $1`, incident, lastEvent); err != nil {
		t.Fatalf("move the last event: %v", err)
	}
	return resource, incident
}

// Incidents, open or acknowledged, whose last event lies beyond the inactivity
// are closed, each with an audit entry of the system; younger incidents stay
// open.
func TestCloseInactive_ClosesOnlyQuietIncidents(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	const inactive = 14
	const margin = time.Minute
	quiet := 24*time.Hour*inactive + margin
	_, quietOpen := f.openIncident(t, quiet)
	_, quietAcknowledged := f.openIncident(t, quiet)
	if _, err := f.owner.Exec(t.Context(), "UPDATE incidents SET status = 'acknowledged' WHERE id = $1", quietAcknowledged); err != nil {
		t.Fatal(err)
	}
	_, recent := f.openIncident(t, 24*time.Hour*inactive-margin)

	var log bytes.Buffer
	task := CloseInactive(slog.New(slog.NewJSONHandler(&log, nil)), schematest.Open(t, f.workerURL), inactive)
	rows, more, err := task.Step(t.Context())
	if rows != 2 || more || err != nil {
		t.Fatalf("Step() = %d, %t, %v; want 2, false, nil", rows, more, err)
	}
	for _, id := range []string{quietOpen, quietAcknowledged} {
		if got := f.incident(t, id).status; got != StatusClosed {
			t.Errorf("quiet incident %s: status = %s, want closed", id, got)
		}
		if n := f.count(t, "SELECT count(*) FROM incidents WHERE id = $1 AND closed_at IS NOT NULL", id); n != 1 {
			t.Errorf("quiet incident %s has no closing time", id)
		}
		if !strings.Contains(log.String(), `"msg":"incident: closed","incident_id":"`+id+`","reason":"inactive"`) {
			t.Errorf("log does not name the closed incident %s: %s", id, log.String())
		}
	}
	if got := f.incident(t, recent).status; got != StatusOpen {
		t.Errorf("recent incident: status = %s, want open", got)
	}

	// The entries carry what the audit package names, so that they read like
	// those of a triage.
	rows2, err := f.owner.Query(t.Context(), `
SELECT action, outcome, actor_kind, auth_method, resource_type, resource_id::text, changed_fields
FROM audit_entries ORDER BY resource_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows2.Close()
	var ids []string
	for rows2.Next() {
		var action, outcome, kind, method, resourceTypeName, id string
		var changed []string
		if err := rows2.Scan(&action, &outcome, &kind, &method, &resourceTypeName, &id, &changed); err != nil {
			t.Fatal(err)
		}
		if action != string(audit.ActionIncidentUpdate) || outcome != string(audit.OutcomeSuccess) ||
			kind != string(audit.ActorSystem) || method != string(audit.AuthNone) || resourceTypeName != resourceType ||
			!slices.Equal(changed, []string{"status"}) {
			t.Errorf("audit entry = %s %s %s %s %s %v, want an update of the status of the incident by the system",
				action, outcome, kind, method, resourceTypeName, changed)
		}
		ids = append(ids, id)
	}
	if err := rows2.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{quietOpen, quietAcknowledged}
	slices.Sort(want)
	if !slices.Equal(ids, want) {
		t.Errorf("audit entries of %v, want %v", ids, want)
	}

	// A closed incident is not closed again.
	if rows, _, err := task.Step(t.Context()); rows != 0 || err != nil {
		t.Errorf("Step() again = %d, %v; want 0, nil", rows, err)
	}
}

// With an inactivity of 0, incidents stay open until they are triaged, and the
// task does not reach the database.
func TestCloseInactive_ZeroNeverCloses(t *testing.T) {
	t.Parallel()

	rows, more, err := CloseInactive(slog.New(slog.DiscardHandler), nil, 0).Step(t.Context())
	if rows != 0 || more || err != nil {
		t.Errorf("Step() = %d, %t, %v; want 0, false, nil", rows, more, err)
	}
}

// The database refuses an inactivity below a day, so that a compromised worker
// cannot close the incidents that analysts are working on.
func TestCloseInactive_RejectsInactivityBeyondTheLimits(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	worker := schematest.Open(t, f.workerURL)
	if _, err := worker.Exec(t.Context(), "SELECT public.close_inactive_incidents($1, 1)", config.MaxAutoCloseDays); err != nil {
		t.Errorf("close_inactive_incidents(%d, 1) error = %v, want nil", config.MaxAutoCloseDays, err)
	}
	for _, days := range []any{0, -1, config.MaxAutoCloseDays + 1, nil} {
		if _, err := worker.Exec(t.Context(), "SELECT public.close_inactive_incidents($1, 1)", days); err == nil || !strings.Contains(err.Error(), "SQLSTATE 22023") {
			t.Errorf("close_inactive_incidents(%v, 1) error = %v, want invalid_parameter_value", days, err)
		}
	}
	for _, batch := range []any{0, 10001, nil} {
		if _, err := worker.Exec(t.Context(), "SELECT public.close_inactive_incidents(14, $1)", batch); err == nil || !strings.Contains(err.Error(), "SQLSTATE 22023") {
			t.Errorf("close_inactive_incidents(14, %v) error = %v, want invalid_parameter_value", batch, err)
		}
	}
}

// Closing takes only the lock of the incident. An event of its resource that
// waits for the incident meanwhile, holding its job, finds it closed
// afterwards and opens a new incident with a new alert; the closed incident
// is never opened again.
func TestCloseInactive_EventWaitingForTheIncidentOpensANewOne(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	resource, quiet := f.openIncident(t, 15*24*time.Hour)
	eventID := f.event(t, resource, "web_url", nil, time.Now())

	// The worker's own login, in a transaction that has closed the incident
	// but not yet committed.
	tx, err := schematest.Open(t, f.workerURL).Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	var closed string
	if err := tx.QueryRow(t.Context(), "SELECT public.close_inactive_incidents(14, 10)").Scan(&closed); err != nil || closed != quiet {
		t.Fatalf("close_inactive_incidents() = %s, %v; want %s", closed, err, quiet)
	}

	done := make(chan error, 1)
	var p Processed
	go func() {
		var err error
		p, _, err = f.store.ProcessNext(t.Context(), func() {})
		done <- err
	}()
	waitForLockWaiter(t, f.owner, done)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("ProcessNext() error = %v", err)
	}

	if !p.Opened || p.IncidentID == quiet || f.eventIncident(t, eventID) != p.IncidentID {
		t.Errorf("ProcessNext() = %+v, want the event in a new incident", p)
	}
	if n := f.count(t, "SELECT count(*) FROM alerts WHERE incident_id = $1", p.IncidentID); n != 1 {
		t.Errorf("the new incident has %d alerts, want 1", n)
	}
	if got := f.incident(t, quiet); got.status != StatusClosed || got.count != 1 {
		t.Errorf("closed incident = %+v, want closed with its one event", got)
	}
}

// An incident that another transaction holds, such as a triage or the worker
// adding an event, is skipped instead of waited for.
func TestCloseInactive_SkipsHeldIncidents(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, held := f.openIncident(t, 15*24*time.Hour)
	_, free := f.openIncident(t, 15*24*time.Hour)
	tx, err := f.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), "SELECT FROM incidents WHERE id = $1 FOR NO KEY UPDATE", held); err != nil {
		t.Fatal(err)
	}

	// A wait would end on the lock timeout of the function with an error.
	rows, _, err := CloseInactive(slog.New(slog.DiscardHandler), schematest.Open(t, f.workerURL), 14).Step(t.Context())
	if rows != 1 || err != nil {
		t.Fatalf("Step() = %d, %v; want 1, nil", rows, err)
	}
	if got := f.incident(t, free).status; got != StatusClosed {
		t.Errorf("free incident: status = %s, want closed", got)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := f.incident(t, held).status; got != StatusOpen {
		t.Errorf("held incident: status = %s, want open until the next run", got)
	}
}

// The task closes a batch at a time and reports more while a full batch was
// closed, so that a backlog is closed within one run.
func TestCloseInactive_StepsInBatches(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	if _, err := f.owner.Exec(t.Context(), `
INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at, opened_at)
SELECT 'honeytoken', gen_random_uuid(), 'low', t, t, t
FROM generate_series(1, $1::int), LATERAL (SELECT clock_timestamp() - interval '2 days') AS c (t)`, worker.BatchSize+1); err != nil {
		t.Fatal(err)
	}
	task := CloseInactive(slog.New(slog.DiscardHandler), schematest.Open(t, f.workerURL), 1)
	for _, want := range []struct {
		rows int64
		more bool
	}{{worker.BatchSize, true}, {1, false}} {
		rows, more, err := task.Step(t.Context())
		if rows != want.rows || more != want.more || err != nil {
			t.Errorf("Step() = %d, %t, %v; want %d, %t, nil", rows, more, err, want.rows, want.more)
		}
	}
}
