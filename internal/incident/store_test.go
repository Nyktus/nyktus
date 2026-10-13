// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package incident

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/schematest"
)

// fixture holds a migrated database, a pool of the owner to set up and inspect
// rows, and a store that connects with the worker's database role.
type fixture struct {
	owner     *pgxpool.Pool
	store     *Store
	workerURL string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ownerURL, workerURL := schematest.Worker(t)
	return fixture{owner: schematest.Open(t, ownerURL), store: NewStore(schematest.Open(t, workerURL)), workerURL: workerURL}
}

// honeytoken creates a honeytoken and returns its identifier and trigger value.
func (f fixture) honeytoken(t *testing.T, typ string, techniques []string) (id, value string) {
	t.Helper()
	if techniques == nil {
		techniques = []string{}
	}
	err := f.owner.QueryRow(t.Context(), `
INSERT INTO honeytokens (type, name, techniques, trigger_value)
VALUES ($1, 'h', $2, translate(left(replace(gen_random_uuid()::text, '-', ''), 26), '0189', 'wxyz'))
RETURNING id, trigger_value`, typ, techniques).Scan(&id, &value)
	if err != nil {
		t.Fatalf("create honeytoken: %v", err)
	}
	return id, value
}

// event writes an event of the honeytoken resource with its job, as the
// recording functions do, at occurredAt, and returns its identifier.
func (f fixture) event(t *testing.T, resource, typ string, techniques []string, occurredAt time.Time) string {
	t.Helper()
	if techniques == nil {
		techniques = []string{}
	}
	var id string
	err := f.owner.QueryRow(t.Context(), `
WITH e AS (
	INSERT INTO events (resource_type, resource_id, honeytoken_type, techniques, occurred_at, recorded_at, channel, method)
	VALUES ('honeytoken', $1, $2, $3, $4, $4, 'http', 'GET')
	RETURNING id
)
INSERT INTO event_jobs (event_id) SELECT id FROM e RETURNING event_id`, resource, typ, techniques, occurredAt).Scan(&id)
	if err != nil {
		t.Fatalf("write event: %v", err)
	}
	return id
}

// process processes the next job and fails the test unless one was due.
func (f fixture) process(t *testing.T) Processed {
	t.Helper()
	claimed := false
	p, found, err := f.store.ProcessNext(t.Context(), func() { claimed = true })
	if err != nil || !found || !claimed {
		t.Fatalf("ProcessNext() = %+v, found %v, claimed %v, error %v; want a processed job", p, found, claimed, err)
	}
	return p
}

type incidentRow struct {
	status     Status
	severity   Severity
	techniques []string
	count      int
	first      time.Time
	last       time.Time
}

func (f fixture) incident(t *testing.T, id string) incidentRow {
	t.Helper()
	var r incidentRow
	err := f.owner.QueryRow(t.Context(), `
SELECT status, severity, techniques, event_count, first_event_at, last_event_at FROM incidents WHERE id = $1`, id,
	).Scan(&r.status, &r.severity, &r.techniques, &r.count, &r.first, &r.last)
	if err != nil {
		t.Fatalf("read incident: %v", err)
	}
	return r
}

func (f fixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := f.owner.QueryRow(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func (f fixture) exec(t *testing.T, statement string, args ...any) {
	t.Helper()
	if _, err := f.owner.Exec(t.Context(), statement, args...); err != nil {
		t.Fatalf("%s: %v", statement, err)
	}
}

// eventIncident returns the incident of the event, or "" if it has none.
func (f fixture) eventIncident(t *testing.T, eventID string) string {
	t.Helper()
	var id *string
	if err := f.owner.QueryRow(t.Context(), "SELECT incident_id FROM events WHERE id = $1", eventID).Scan(&id); err != nil {
		t.Fatalf("read event: %v", err)
	}
	if id == nil {
		return ""
	}
	return *id
}

// The worker refuses to start with a login that reaches more than its tables,
// such as the login of the console, or that is no member of its group role.
func TestCheckPrivileges(t *testing.T) {
	t.Parallel()

	ownerURL, workerURL := schematest.Worker(t)
	if err := CheckPrivileges(t.Context(), schematest.Open(t, workerURL)); err != nil {
		t.Errorf("CheckPrivileges(worker) = %v, want nil", err)
	}

	_, consoleURL := dbtest.Role(t, ownerURL, "console", "IN ROLE "+pgx.Identifier{schematest.ConsoleRole}.Sanitize())
	if err := CheckPrivileges(t.Context(), schematest.Open(t, consoleURL)); !errors.Is(err, db.ErrRolePrivileges) || !strings.Contains(err.Error(), "member of [nyktus_console]") {
		t.Errorf("CheckPrivileges(console) = %v, want ErrRolePrivileges naming the console role", err)
	}
	// A member of the worker's group role with a privilege of its own.
	name, widerURL := dbtest.Role(t, ownerURL, "wider", "IN ROLE "+pgx.Identifier{schematest.WorkerRole}.Sanitize())
	dbtest.Exec(t, ownerURL, "GRANT SELECT ON honeytokens TO "+pgx.Identifier{name}.Sanitize())
	if err := CheckPrivileges(t.Context(), schematest.Open(t, widerURL)); !errors.Is(err, db.ErrRolePrivileges) || !strings.Contains(err.Error(), "tables [honeytokens]") {
		t.Errorf("CheckPrivileges(wider) = %v, want ErrRolePrivileges naming the honeytokens", err)
	}
	_, triggerURL := dbtest.Role(t, ownerURL, "trigger", "IN ROLE "+pgx.Identifier{schematest.TriggerRole}.Sanitize())
	if err := CheckPrivileges(t.Context(), schematest.Open(t, triggerURL)); !errors.Is(err, db.ErrRolePrivileges) || !strings.Contains(err.Error(), "cannot execute") {
		t.Errorf("CheckPrivileges(trigger) = %v, want ErrRolePrivileges containing %q", err, "cannot execute")
	}
}

// An event recorded by the trigger opens an incident of its honeytoken, with
// the single alert of the incident, in the transaction that deletes its job.
func TestStore_OpensAnIncidentWithItsAlert(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, value := f.honeytoken(t, "web_url", []string{"T1213"})
	f.exec(t, "SELECT * FROM record_honeytoken_request($1, 'GET', NULL, '', '', '')", value)

	p := f.process(t)
	if !p.Opened || p.ResourceType != ResourceHoneytoken || p.ResourceID != id || p.Severity != SeverityMedium || p.IncidentID == "" {
		t.Errorf("ProcessNext() = %+v, want an opened incident of the honeytoken with severity medium", p)
	}
	got := f.incident(t, p.IncidentID)
	if got.status != StatusOpen || got.severity != SeverityMedium || !slices.Equal(got.techniques, []string{"T1213"}) ||
		got.count != 1 || !got.first.Equal(got.last) {
		t.Errorf("incident = %+v, want open, medium, T1213, one event", got)
	}
	if f.eventIncident(t, p.EventID) != p.IncidentID {
		t.Error("the event is not assigned to the incident")
	}
	if n := f.count(t, "SELECT count(*) FROM alerts WHERE incident_id = $1 AND severity = 'medium' AND techniques = '{T1213}'", p.IncidentID); n != 1 {
		t.Errorf("%d alerts with the state at opening, want 1", n)
	}
	if n := f.count(t, "SELECT count(*) FROM event_jobs"); n != 0 {
		t.Errorf("%d jobs left, want none", n)
	}
	if _, found, err := f.store.ProcessNext(t.Context(), func() { t.Error("claimed a job that does not exist") }); found || err != nil {
		t.Errorf("ProcessNext() without jobs = found %v, %v; want nothing", found, err)
	}
}

// Severity follows the type of the honeytoken.
func TestStore_SeverityFollowsTheTypeOfTheHoneytoken(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	for typ, want := range map[string]Severity{"web_url": SeverityMedium, "web_image": SeverityLow, "dns": SeverityMedium} {
		id, _ := f.honeytoken(t, typ, nil)
		f.event(t, id, typ, nil, time.Now())
		if p := f.process(t); p.Severity != want {
			t.Errorf("%s: severity %s, want %s", typ, p.Severity, want)
		}
	}
}

// Further events of the resource join its open incident: the severity is the
// highest of the events, the techniques are all of theirs, and the times span
// them, whatever the order in which they are processed. They raise no alert.
func TestStore_AddsEventsToTheOpenIncident(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, _ := f.honeytoken(t, "web_url", nil)
	start := time.Now().UTC().Truncate(time.Microsecond)
	f.event(t, id, "web_url", []string{"T1213"}, start)
	first := f.process(t)

	// An analyst may have judged the incident lower; the events still count.
	f.exec(t, "UPDATE incidents SET severity = 'low'")
	f.event(t, id, "web_url", []string{"T1083", "T1213"}, start.Add(time.Minute))
	second := f.process(t)
	f.event(t, id, "web_url", nil, start.Add(-time.Minute))
	third := f.process(t)

	if second.Opened || third.Opened || second.IncidentID != first.IncidentID || third.IncidentID != first.IncidentID {
		t.Fatalf("processed %+v, %+v; want both in the incident %s", second, third, first.IncidentID)
	}
	got := f.incident(t, first.IncidentID)
	if got.severity != SeverityMedium || !slices.Equal(got.techniques, []string{"T1213", "T1083"}) || got.count != 3 ||
		!got.first.Equal(start.Add(-time.Minute)) || !got.last.Equal(start.Add(time.Minute)) {
		t.Errorf("incident = %+v, want medium, T1213 and T1083, three events from %v to %v", got, start.Add(-time.Minute), start.Add(time.Minute))
	}

	// A higher severity is kept.
	f.exec(t, "UPDATE incidents SET severity = 'critical'")
	f.event(t, id, "web_url", nil, start)
	if p := f.process(t); p.Severity != SeverityCritical {
		t.Errorf("severity after a lower event = %s, want critical", p.Severity)
	}
	if n := f.count(t, "SELECT count(*) FROM alerts"); n != 1 {
		t.Errorf("%d alerts, want 1", n)
	}
}

// An acknowledged incident is still open and collects events.
func TestStore_AcknowledgedIncidentCollectsEvents(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, _ := f.honeytoken(t, "dns", nil)
	f.event(t, id, "dns", nil, time.Now())
	first := f.process(t)
	f.exec(t, "UPDATE incidents SET status = 'acknowledged', acknowledged_at = clock_timestamp()")

	f.event(t, id, "dns", nil, time.Now())
	if p := f.process(t); p.Opened || p.IncidentID != first.IncidentID {
		t.Errorf("ProcessNext() = %+v, want the event in the acknowledged incident %s", p, first.IncidentID)
	}
}

// A closed incident is never opened again: the next event of its resource
// opens a new incident with a new alert.
func TestStore_ClosedIncidentStaysClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, _ := f.honeytoken(t, "web_image", nil)
	f.event(t, id, "web_image", nil, time.Now())
	first := f.process(t)
	f.exec(t, "UPDATE incidents SET status = 'closed', closed_at = clock_timestamp()")

	f.event(t, id, "web_image", nil, time.Now())
	second := f.process(t)
	if !second.Opened || second.IncidentID == first.IncidentID {
		t.Errorf("ProcessNext() = %+v, want a new incident", second)
	}
	if got := f.incident(t, first.IncidentID); got.status != StatusClosed || got.count != 1 {
		t.Errorf("closed incident = %+v, want closed with its one event", got)
	}
	if n := f.count(t, "SELECT count(*) FROM alerts"); n != 2 {
		t.Errorf("%d alerts, want one for each incident", n)
	}
}

// An event is never lost: if it cannot be processed, its job stays, unassigned,
// and is tried again later, without holding up the jobs behind it.
func TestStore_FailedJobStaysAndIsTriedAgain(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, _ := f.honeytoken(t, "web_url", nil)
	eventID := f.event(t, id, "web_url", nil, time.Now())
	f.exec(t, "ALTER TABLE alerts ADD CONSTRAINT alerts_reject CHECK (false) NOT VALID")

	for attempt := 1; attempt <= 2; attempt++ {
		_, found, err := f.store.ProcessNext(t.Context(), func() {})
		var jobErr *JobError
		if !found || !errors.As(err, &jobErr) || jobErr.EventID != eventID || jobErr.Attempts != attempt {
			t.Fatalf("attempt %d: ProcessNext() = found %v, %v; want a JobError of the event", attempt, found, err)
		}
		var wait time.Duration
		if err := f.owner.QueryRow(t.Context(), "SELECT extract(epoch FROM not_before - clock_timestamp()) * interval '1 second' FROM event_jobs").Scan(&wait); err != nil {
			t.Fatal(err)
		}
		// The wait doubles from two seconds.
		if want := time.Duration(1<<attempt) * time.Second; wait > want || wait < want-time.Second {
			t.Errorf("attempt %d: job due again in %v, want about %v", attempt, wait, want)
		}
		if f.eventIncident(t, eventID) != "" || f.count(t, "SELECT count(*) FROM incidents") != 0 {
			t.Error("the failed attempt left an incident or an assignment behind")
		}
		// A postponed job is not due, so it holds up nothing.
		if _, found, err := f.store.ProcessNext(t.Context(), func() {}); found || err != nil {
			t.Errorf("ProcessNext() with the job postponed = found %v, %v; want nothing due", found, err)
		}
		f.exec(t, "UPDATE event_jobs SET not_before = clock_timestamp()")
	}
	if n := f.count(t, "SELECT count(*) FROM event_jobs WHERE event_id = $1 AND attempts = 2", eventID); n != 1 {
		t.Errorf("%d jobs with two attempts, want 1", n)
	}

	f.exec(t, "ALTER TABLE alerts DROP CONSTRAINT alerts_reject")
	if p := f.process(t); p.EventID != eventID || !p.Opened {
		t.Errorf("ProcessNext() after the failure = %+v, want the event to open an incident", p)
	}
}

// An event belongs to one incident only. An event that already belongs to one
// is not assigned again and does not change any incident.
func TestStore_EventIsAssignedOnlyOnce(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, _ := f.honeytoken(t, "web_url", nil)
	f.event(t, id, "web_url", nil, time.Now())
	first := f.process(t)
	f.exec(t, "UPDATE incidents SET status = 'closed', closed_at = clock_timestamp()")
	eventID := f.event(t, id, "web_url", nil, time.Now())
	f.exec(t, "UPDATE events SET incident_id = $1 WHERE id = $2", first.IncidentID, eventID)

	_, found, err := f.store.ProcessNext(t.Context(), func() {})
	var jobErr *JobError
	if !found || !errors.As(err, &jobErr) || jobErr.EventID != eventID {
		t.Fatalf("ProcessNext() = found %v, %v; want a JobError of the event", found, err)
	}
	if f.eventIncident(t, eventID) != first.IncidentID || f.count(t, "SELECT count(*) FROM incidents") != 1 || f.incident(t, first.IncidentID).count != 1 {
		t.Error("the assigned event was assigned again or changed an incident")
	}
}

// The wait between attempts stops growing at an hour.
func TestStore_WaitBetweenAttemptsIsBounded(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, _ := f.honeytoken(t, "web_url", nil)
	f.event(t, id, "web_url", nil, time.Now())
	f.exec(t, "ALTER TABLE alerts ADD CONSTRAINT alerts_reject CHECK (false) NOT VALID")
	f.exec(t, "UPDATE event_jobs SET attempts = 1000000")
	_, _, err := f.store.ProcessNext(t.Context(), func() {})
	var jobErr *JobError
	if !errors.As(err, &jobErr) {
		t.Fatalf("ProcessNext() error = %v, want a JobError", err)
	}
	if wait := time.Until(jobErr.Retry); wait > time.Hour || wait < 59*time.Minute {
		t.Errorf("job due again in %v, want an hour", wait)
	}
}

// Workers take different jobs instead of waiting for each other.
func TestStore_SkipsJobsThatAnotherWorkerHolds(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, _ := f.honeytoken(t, "web_url", nil)
	held := f.event(t, id, "web_url", nil, time.Now())
	f.exec(t, "UPDATE event_jobs SET not_before = not_before - interval '1 minute'")
	other := f.event(t, id, "web_url", nil, time.Now())

	tx, err := f.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), "SELECT FROM event_jobs WHERE event_id = $1 FOR UPDATE", held); err != nil {
		t.Fatal(err)
	}
	if p := f.process(t); p.EventID != other {
		t.Errorf("processed %s, want the job that nobody holds", p.EventID)
	}
	if _, found, err := f.store.ProcessNext(t.Context(), func() {}); found || err != nil {
		t.Errorf("ProcessNext() with the only job held = found %v, %v; want nothing", found, err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if p := f.process(t); p.EventID != held {
		t.Errorf("processed %s after the release, want %s", p.EventID, held)
	}
}

// waitForLockWaiter returns once a session of the test database waits for a
// lock. It polls instead of sleeping, so it neither depends on timing nor
// returns before the waiter has reached the lock.
func waitForLockWaiter(t *testing.T, owner *pgxpool.Pool, done <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		var waiting bool
		err := owner.QueryRow(ctx, `
SELECT EXISTS (SELECT FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting)
		if err != nil {
			t.Fatalf("query waiting sessions: %v", err)
		}
		if waiting {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("the job completed without waiting for a lock: %v", err)
		default:
		}
	}
}

// Two workers that process events of the same resource at the same time open
// one incident. The other transaction stands for a worker that has opened the
// incident but not yet committed: the worker must wait for it and then add its
// event to that incident instead of opening a second one.
func TestStore_ConcurrentEventsOfAResourceOpenOneIncident(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, _ := f.honeytoken(t, "web_url", nil)
	eventID := f.event(t, id, "web_url", nil, time.Now())

	tx, err := f.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	var opened string
	err = tx.QueryRow(t.Context(), `
INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at)
VALUES ('honeytoken', $1, 'medium', now(), now()) RETURNING id`, id).Scan(&opened)
	if err != nil {
		t.Fatal(err)
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

	if p.Opened || p.IncidentID != opened || f.eventIncident(t, eventID) != opened {
		t.Errorf("ProcessNext() = %+v, want the event in the incident %s", p, opened)
	}
	if n := f.count(t, "SELECT count(*) FROM incidents WHERE status <> 'closed'"); n != 1 {
		t.Errorf("%d open incidents, want 1", n)
	}
}

// An incident that is closed while the worker waits to add an event to it
// stays closed: the event opens a new incident.
func TestStore_IncidentClosedWhileWaitingStaysClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, _ := f.honeytoken(t, "web_url", nil)
	f.event(t, id, "web_url", nil, time.Now())
	first := f.process(t)
	eventID := f.event(t, id, "web_url", nil, time.Now())

	tx, err := f.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), "UPDATE incidents SET status = 'closed', closed_at = clock_timestamp() WHERE id = $1", first.IncidentID); err != nil {
		t.Fatal(err)
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

	if !p.Opened || p.IncidentID == first.IncidentID || f.eventIncident(t, eventID) != p.IncidentID {
		t.Errorf("ProcessNext() = %+v, want the event in a new incident", p)
	}
	if got := f.incident(t, first.IncidentID); got.status != StatusClosed || got.count != 1 {
		t.Errorf("closed incident = %+v, want closed with its one event", got)
	}
}

// Workers that process many events of few resources side by side assign every
// event once, open one incident per resource, and raise one alert per
// incident.
func TestStore_ConcurrentWorkersAssignEveryEventOnce(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	resources := make([]string, 2)
	for i := range resources {
		resources[i], _ = f.honeytoken(t, "web_url", nil)
	}
	const perResource = 15
	for i := range perResource {
		for _, r := range resources {
			f.event(t, r, "web_url", []string{[]string{"T1213", "T1083", "T1078"}[i%3]}, time.Now())
		}
	}

	const workers = 4
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		store := NewStore(schematest.Open(t, f.workerURL))
		wg.Go(func() {
			for {
				_, found, err := store.ProcessNext(t.Context(), func() {})
				if err != nil {
					errs <- err
					return
				}
				if !found {
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("ProcessNext() error = %v", err)
	}

	if n := f.count(t, "SELECT count(*) FROM events WHERE incident_id IS NULL"); n != 0 {
		t.Errorf("%d events without an incident", n)
	}
	if n := f.count(t, "SELECT count(*) FROM event_jobs"); n != 0 {
		t.Errorf("%d jobs left", n)
	}
	if n := f.count(t, "SELECT count(*) FROM incidents"); n != len(resources) {
		t.Errorf("%d incidents, want one per resource", n)
	}
	if n := f.count(t, "SELECT count(*) FROM incidents AS i WHERE event_count = $1 AND cardinality(techniques) = 3 AND EXISTS (SELECT FROM alerts AS a WHERE a.incident_id = i.id)", perResource); n != len(resources) {
		t.Errorf("%d incidents with all their events, techniques and their alert, want %d", n, len(resources))
	}
	if n := f.count(t, "SELECT count(*) FROM alerts"); n != len(resources) {
		t.Errorf("%d alerts, want one per incident", n)
	}
}

// The worker finds the next due job through the index, also with many jobs
// waiting.
func TestStore_NextJobUsesTheIndex(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	conn, err := f.owner.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(t.Context(), "SET enable_seqscan = off"); err != nil {
		t.Fatal(err)
	}
	rows, err := conn.Query(t.Context(), `
EXPLAIN SELECT event_id, attempts FROM public.event_jobs
WHERE not_before <= statement_timestamp()
ORDER BY not_before
LIMIT 1
FOR UPDATE SKIP LOCKED`)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(plan, "\n"), "Index Cond: (not_before <= statement_timestamp())") {
		t.Errorf("plan does not seek into the index by due time:\n%s", strings.Join(plan, "\n"))
	}
}

// The schema accepts every status and severity that the code knows, and no
// incident takes info as the severity of its events.
func TestStatusesAndSeverities_MatchTheSchema(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	const insert = `
INSERT INTO incidents (resource_type, resource_id, status, severity, severity_override, first_event_at, last_event_at, acknowledged_at, closed_at)
VALUES ($1, gen_random_uuid(), $2, $3, $4, now(), now(),
	CASE WHEN $2 <> 'open' THEN clock_timestamp() END, CASE WHEN $2 = 'closed' THEN clock_timestamp() END)`
	for _, status := range Statuses {
		if _, err := f.owner.Exec(t.Context(), insert, ResourceHoneytoken, status, SeverityLow, nil); err != nil {
			t.Errorf("status %s: %v", status, err)
		}
	}
	for _, severity := range Severities {
		if _, err := f.owner.Exec(t.Context(), insert, ResourceHoneytoken, StatusOpen, SeverityLow, severity); err != nil {
			t.Errorf("override %s: %v", severity, err)
		}
		f.exec(t, "DELETE FROM incidents WHERE status = 'open'")
		_, err := f.owner.Exec(t.Context(), insert, ResourceHoneytoken, StatusOpen, severity, nil)
		if severity == SeverityInfo {
			if err == nil {
				t.Error("an incident took info as its severity")
			}
		} else if err != nil {
			t.Errorf("severity %s: %v", severity, err)
		}
		f.exec(t, "DELETE FROM incidents WHERE status = 'open'")
	}
	for _, severity := range honeytokenSeverity {
		if _, err := f.owner.Exec(t.Context(), "INSERT INTO alerts (incident_id, severity) SELECT id, $1 FROM incidents WHERE status = 'closed'", severity); err != nil {
			t.Errorf("alert of severity %s: %v", severity, err)
		}
		f.exec(t, "DELETE FROM alerts")
	}
}

// The processor logs an opened incident, and logs a failed job without
// reporting the database as unreachable.
func TestProcessor_LogsWhatBecameOfTheJob(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	var buf bytes.Buffer
	p := NewProcessor(f.store, slog.New(slog.NewJSONHandler(&buf, nil)))
	id, _ := f.honeytoken(t, "web_url", nil)
	f.event(t, id, "web_url", nil, time.Now())
	if found, err := p.Process(t.Context(), func() {}); !found || err != nil {
		t.Fatalf("Process() = %v, %v; want a processed job", found, err)
	}
	if !strings.Contains(buf.String(), `"msg":"incident: opened"`) || !strings.Contains(buf.String(), `"resource_id":"`+id+`"`) {
		t.Errorf("log = %s, want the opened incident", buf.String())
	}

	buf.Reset()
	f.exec(t, "UPDATE incidents SET status = 'closed', closed_at = clock_timestamp()")
	f.exec(t, "ALTER TABLE alerts ADD CONSTRAINT alerts_reject CHECK (false) NOT VALID")
	eventID := f.event(t, id, "web_url", nil, time.Now())
	if found, err := p.Process(t.Context(), func() {}); !found || err != nil {
		t.Fatalf("Process() = %v, %v; want the failed job to count as processed", found, err)
	}
	if !strings.Contains(buf.String(), `"msg":"incident: event not processed"`) || !strings.Contains(buf.String(), `"event_id":"`+eventID+`"`) ||
		!strings.Contains(buf.String(), `"attempts":1`) || !strings.Contains(buf.String(), `"level":"ERROR"`) {
		t.Errorf("log = %s, want the failed job", buf.String())
	}
}
