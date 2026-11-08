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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/severity"
)

// fixture holds a migrated database, a pool of the owner to set up and inspect
// rows, and a store that connects with the worker's database role.
type fixture struct {
	owner               *pgxpool.Pool
	store               *Store
	ownerURL, workerURL string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ownerURL, workerURL := schematest.Worker(t)
	return fixture{
		owner: schematest.Open(t, ownerURL), store: NewStore(schematest.Open(t, workerURL)),
		ownerURL: ownerURL, workerURL: workerURL,
	}
}

// honeytoken creates a honeytoken with the default severity of its type and
// returns its identifier and trigger value.
func (f fixture) honeytoken(t *testing.T, typ string, techniques []string) (id, value string) {
	t.Helper()
	if techniques == nil {
		techniques = []string{}
	}
	err := f.owner.QueryRow(t.Context(), `
INSERT INTO honeytokens (type, name, techniques, severity, trigger_value)
VALUES ($1, 'h', $2, $3, translate(left(replace(gen_random_uuid()::text, '-', ''), 26), '0189', 'wxyz'))
RETURNING id, trigger_value`, typ, techniques, honeytoken.Type(typ).DefaultSeverity()).Scan(&id, &value)
	if err != nil {
		t.Fatalf("create honeytoken: %v", err)
	}
	return id, value
}

// event writes an event of the honeytoken resource with its job, as the
// recording functions do, at occurredAt, with the default severity of the
// type, and returns its identifier.
func (f fixture) event(t *testing.T, resource, typ string, techniques []string, occurredAt time.Time) string {
	t.Helper()
	if techniques == nil {
		techniques = []string{}
	}
	var id string
	err := f.owner.QueryRow(t.Context(), `
WITH e AS (
	INSERT INTO events (resource_type, resource_id, honeytoken_type, techniques, severity, occurred_at, recorded_at,
		channel, method, resource_name)
	VALUES ('honeytoken', $1, $2, $3, $5, $4, $4, 'http', 'GET', 'Name')
	RETURNING id
)
INSERT INTO event_jobs (event_id) SELECT id FROM e RETURNING event_id`, resource, typ, techniques, occurredAt,
		honeytoken.Type(typ).DefaultSeverity()).Scan(&id)
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
	severity   severity.Level
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

// An event recorded by the trigger opens an incident of its honeytoken, with
// the single alert of the incident, in the transaction that deletes its job.
func TestStore_OpensAnIncidentWithItsAlert(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, value := f.honeytoken(t, "web_url", []string{"T1213"})
	f.exec(t, "SELECT * FROM record_honeytoken_request($1, 'GET', NULL, '', '', '', '')", value)

	p := f.process(t)
	if !p.Opened || p.ResourceType != honeytoken.ResourceType || p.ResourceID != id || p.Severity != severity.Medium || p.IncidentID == "" {
		t.Errorf("ProcessNext() = %+v, want an opened incident of the honeytoken with severity medium", p)
	}
	got := f.incident(t, p.IncidentID)
	if got.status != StatusOpen || got.severity != severity.Medium || !slices.Equal(got.techniques, []string{"T1213"}) ||
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

// An event keeps the severity that its honeytoken had when it was requested,
// over HTTP and DNS, and the worker gives the incident that severity: a
// change of the honeytoken afterwards changes neither.
func TestStore_SeverityIsFrozenOnTheEvent(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	for _, record := range []string{
		"SELECT * FROM record_honeytoken_request($1, 'GET', NULL, '', '', '', '')",
		"SELECT * FROM record_dns_query($1, 'd.example.com', '', 'A', 'udp', NULL, NULL)",
	} {
		id, value := f.honeytoken(t, "dns", nil)
		f.exec(t, "UPDATE honeytokens SET severity = 'critical' WHERE id = $1", id)
		f.exec(t, record, value)
		f.exec(t, "UPDATE honeytokens SET severity = 'low' WHERE id = $1", id)

		p := f.process(t)
		if !p.Opened || p.Severity != severity.Critical {
			t.Errorf("%s: processed %+v, want an incident with the severity critical of the event", record, p)
		}
		if got := f.incident(t, p.IncidentID); got.severity != severity.Critical {
			t.Errorf("%s: incident severity %s, want critical", record, got.severity)
		}
		if n := f.count(t, "SELECT count(*) FROM events WHERE id = $1 AND severity = 'critical'", p.EventID); n != 1 {
			t.Errorf("%s: the event did not keep the severity critical", record)
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
	if got.severity != severity.Medium || !slices.Equal(got.techniques, []string{"T1213", "T1083"}) || got.count != 3 ||
		!got.first.Equal(start.Add(-time.Minute)) || !got.last.Equal(start.Add(time.Minute)) {
		t.Errorf("incident = %+v, want medium, T1213 and T1083, three events from %v to %v", got, start.Add(-time.Minute), start.Add(time.Minute))
	}

	// A higher severity is kept.
	f.exec(t, "UPDATE incidents SET severity = 'critical'")
	f.event(t, id, "web_url", nil, start)
	if p := f.process(t); p.Severity != severity.Critical {
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

// A job that runs out of time, here because another transaction holds its
// incident, is postponed like any failed job, although its connection was
// broken off with it.
func TestStore_JobThatRunsOutOfTimeIsPostponed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// Only the deadline ends the wait for the lock.
	f.store.lockTimeout = time.Hour

	id, _ := f.honeytoken(t, "web_url", nil)
	f.event(t, id, "web_url", nil, time.Now())
	first := f.process(t)
	eventID := f.event(t, id, "web_url", nil, time.Now())

	tx, err := f.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), "SELECT FROM incidents WHERE id = $1 FOR UPDATE", first.IncidentID); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, found, err := f.store.ProcessNext(ctx, func() {})
	var jobErr *JobError
	if !found || !errors.As(err, &jobErr) || jobErr.EventID != eventID || jobErr.Attempts != 1 {
		t.Fatalf("ProcessNext() = found %v, %v; want a JobError of the event after one attempt", found, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, "SELECT count(*) FROM event_jobs WHERE event_id = $1 AND attempts = 1 AND not_before > clock_timestamp()", eventID); n != 1 {
		t.Errorf("%d postponed jobs of the event, want 1", n)
	}
	if f.eventIncident(t, eventID) != "" || f.incident(t, first.IncidentID).count != 1 {
		t.Error("the attempt that ran out of time assigned the event")
	}
}

// A stopping worker cancels its search for a job, but a job that it has taken
// runs to its end.
func TestStore_TakenJobOutlivesTheStop(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, _ := f.honeytoken(t, "web_url", nil)
	eventID := f.event(t, id, "web_url", nil, time.Now())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	p, found, err := f.store.ProcessNext(ctx, cancel)
	if !found || err != nil || p.EventID != eventID || !p.Opened {
		t.Fatalf("ProcessNext() canceled after the claim = %+v, found %v, %v; want the event processed", p, found, err)
	}
	if _, found, err := f.store.ProcessNext(ctx, func() {}); found || err == nil {
		t.Errorf("ProcessNext() on a canceled context = found %v, %v; want a failed search", found, err)
	}
}

// A job whose incident stays locked fails on the lock timeout and is postponed
// in its own transaction, while it is still held, so that no other worker
// takes it again before.
func TestStore_JobWaitingForALockIsPostponed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.store.lockTimeout = 100 * time.Millisecond

	id, _ := f.honeytoken(t, "web_url", nil)
	f.event(t, id, "web_url", nil, time.Now())
	first := f.process(t)
	eventID := f.event(t, id, "web_url", nil, time.Now())

	tx, err := f.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), "SELECT FROM incidents WHERE id = $1 FOR UPDATE", first.IncidentID); err != nil {
		t.Fatal(err)
	}

	_, found, err := f.store.ProcessNext(t.Context(), func() {})
	var jobErr *JobError
	if !found || !errors.As(err, &jobErr) || jobErr.EventID != eventID || jobErr.Attempts != 1 || !strings.Contains(err.Error(), "lock timeout") {
		t.Fatalf("ProcessNext() = found %v, %v; want a JobError of the event on the lock timeout", found, err)
	}
	if n := f.count(t, "SELECT count(*) FROM event_jobs WHERE event_id = $1 AND attempts = 1 AND not_before > clock_timestamp()", eventID); n != 1 {
		t.Errorf("%d postponed jobs of the event, want 1", n)
	}
}

// A failed job is postponed before it is released, so that no other worker
// takes it again in between. The other transaction stands for such a worker:
// it waits for the job and must find it postponed once it gets it.
func TestStore_FailedJobIsPostponedBeforeItIsReleased(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, _ := f.honeytoken(t, "web_url", nil)
	f.event(t, id, "web_url", nil, time.Now())
	first := f.process(t)
	eventID := f.event(t, id, "web_url", nil, time.Now())
	// The second event fails once it has the lock of the incident.
	f.exec(t, "ALTER TABLE incidents ADD CONSTRAINT incidents_reject CHECK (event_count < 2) NOT VALID")

	// Holding the incident keeps the worker on the job until the other
	// transaction waits for the job as well.
	holder, err := f.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(t.Context()) }()
	if _, err := holder.Exec(t.Context(), "SELECT FROM incidents WHERE id = $1 FOR UPDATE", first.IncidentID); err != nil {
		t.Fatal(err)
	}
	processed := make(chan error, 1)
	go func() {
		_, _, err := f.store.ProcessNext(t.Context(), func() {})
		processed <- err
	}()
	waitForLockWaiter(t, f.owner, processed)

	other, err := pgx.Connect(t.Context(), f.ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close(context.WithoutCancel(t.Context())) }()
	attempts := make(chan int, 1)
	taken := make(chan error, 1)
	go func() {
		var n int
		err := other.QueryRow(t.Context(), "SELECT attempts FROM event_jobs WHERE event_id = $1 FOR UPDATE", eventID).Scan(&n)
		attempts <- n
		taken <- err
	}()
	waitForLockWaiters(t, f.owner, 2, taken)
	if err := holder.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}

	var jobErr *JobError
	if err := <-processed; !errors.As(err, &jobErr) || jobErr.Attempts != 1 {
		t.Errorf("ProcessNext() error = %v, want a JobError after one attempt", err)
	}
	if err := <-taken; err != nil {
		t.Fatal(err)
	}
	if n := <-attempts; n != 1 {
		t.Errorf("the other transaction got the job with %d attempts, want it postponed first", n)
	}
}

// A failed attempt whose transaction broke off does not wait for a job that
// another worker has taken meanwhile: that worker processes it.
func TestStore_PostponeAfterBreakSkipsAJobThatAnotherWorkerHolds(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, _ := f.honeytoken(t, "web_url", nil)
	eventID := f.event(t, id, "web_url", nil, time.Now())
	tx, err := f.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), "SELECT FROM event_jobs WHERE event_id = $1 FOR UPDATE", eventID); err != nil {
		t.Fatal(err)
	}

	err = f.store.postponeAfterBreak(t.Context(), nil, eventID, errors.New("deadline exceeded"))
	var jobErr *JobError
	if errors.As(err, &jobErr) || err == nil || !strings.Contains(err.Error(), "another worker took the job") {
		t.Errorf("postponeAfterBreak() = %v, want an error that another worker took the job", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, "SELECT count(*) FROM event_jobs WHERE event_id = $1 AND attempts = 0", eventID); n != 1 {
		t.Errorf("%d unchanged jobs, want 1", n)
	}
}

// endingSession is a connection that broke off and that the server has not
// finished with. It reports when it is asked to wait for its end.
type endingSession struct {
	closed  bool
	ended   chan struct{}
	waiting chan struct{}
	once    sync.Once
}

func (e *endingSession) IsClosed() bool { return e.closed }

func (e *endingSession) CleanupDone() chan struct{} {
	e.once.Do(func() { close(e.waiting) })
	return e.ended
}

// The server frees the job of a transaction that broke off only after it has
// processed the cancel request of the driver. A failed attempt is not recorded
// before that: the job would look like one that another worker holds.
func TestStore_PostponeAfterBreakWaitsForTheSessionThatBrokeOff(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, _ := f.honeytoken(t, "web_url", nil)
	eventID := f.event(t, id, "web_url", nil, time.Now())
	dying, err := f.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dying.Rollback(t.Context()) }()
	if _, err := dying.Exec(t.Context(), "SELECT FROM event_jobs WHERE event_id = $1 FOR UPDATE", eventID); err != nil {
		t.Fatal(err)
	}

	session := &endingSession{closed: true, ended: make(chan struct{}), waiting: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		result <- f.store.postponeAfterBreak(t.Context(), session, eventID, errors.New("deadline exceeded"))
	}()

	select {
	case <-session.waiting:
	case err := <-result:
		t.Fatalf("postponeAfterBreak() returned %v while the session had not ended", err)
	}
	// The server ends the session: the transaction is rolled back and the job
	// is free, then the driver reports the end of the connection.
	if err := dying.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	close(session.ended)

	var jobErr *JobError
	if err := <-result; !errors.As(err, &jobErr) || jobErr.Attempts != 1 {
		t.Errorf("postponeAfterBreak() = %v, want a JobError after one attempt", err)
	}
}

// A connection that is still open is not waited for: nothing ends it.
func TestAwaitEnd_DoesNotWaitForAnOpenConnection(t *testing.T) {
	t.Parallel()

	awaitEnd(t.Context(), &endingSession{closed: false, ended: make(chan struct{}), waiting: make(chan struct{})})
	awaitEnd(t.Context(), nil)
}

// The wait ends with the context, so that a session that never ends does not
// hold a worker.
func TestAwaitEnd_StopsWithTheContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	awaitEnd(ctx, &endingSession{closed: true, ended: make(chan struct{}), waiting: make(chan struct{})})
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
	// The database set the time with its own clock, which may run ahead of
	// the clock of the test.
	var seconds float64
	if err := f.owner.QueryRow(t.Context(), `SELECT extract(epoch FROM $1::timestamptz - clock_timestamp())`, jobErr.Retry).Scan(&seconds); err != nil {
		t.Fatal(err)
	}
	if wait := time.Duration(seconds * float64(time.Second)); wait > time.Hour || wait < 59*time.Minute {
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
	waitForLockWaiters(t, owner, 1, done)
}

// waitForLockWaiters returns once n sessions of the test database wait for a
// lock.
func waitForLockWaiters(t *testing.T, owner *pgxpool.Pool, n int, done <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		var waiting int
		err := owner.QueryRow(ctx, `
SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting)
		if err != nil {
			t.Fatalf("query waiting sessions: %v", err)
		}
		if waiting >= n {
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
INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at, resource_name)
VALUES ('honeytoken', $1, 'medium', now(), now(), 'Name') RETURNING id`, id).Scan(&opened)
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

// The events of an incident are found through the index.
func TestStore_EventsOfAnIncidentUseTheIndex(t *testing.T) {
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
	rows, err := conn.Query(t.Context(), "EXPLAIN SELECT id FROM events WHERE incident_id = '00000000-0000-4000-8000-000000000000'")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(plan, "\n"), "Index Cond: (incident_id = '00000000-0000-4000-8000-000000000000'::uuid)") {
		t.Errorf("plan does not seek into the index by incident:\n%s", strings.Join(plan, "\n"))
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
INSERT INTO incidents (resource_type, resource_id, status, severity, severity_override, first_event_at, last_event_at, acknowledged_at, closed_at, resource_name)
VALUES ($1, gen_random_uuid(), $2, $3, $4, now(), now(),
	CASE WHEN $2 <> 'open' THEN clock_timestamp() END, CASE WHEN $2 = 'closed' THEN clock_timestamp() END, 'Name')`
	for _, status := range Statuses {
		if _, err := f.owner.Exec(t.Context(), insert, honeytoken.ResourceType, status, severity.Low, nil); err != nil {
			t.Errorf("status %s: %v", status, err)
		}
	}
	for _, level := range severity.Levels {
		if _, err := f.owner.Exec(t.Context(), insert, honeytoken.ResourceType, StatusOpen, severity.Low, level); err != nil {
			t.Errorf("override %s: %v", level, err)
		}
		f.exec(t, "DELETE FROM incidents WHERE status = 'open'")
		_, err := f.owner.Exec(t.Context(), insert, honeytoken.ResourceType, StatusOpen, level, nil)
		var pgErr *pgconn.PgError
		if level == severity.Info {
			if !errors.As(err, &pgErr) || pgErr.ConstraintName != "incidents_severity_check" {
				t.Errorf("incident of severity info: error = %v, want a violation of incidents_severity_check", err)
			}
		} else if err != nil {
			t.Errorf("severity %s: %v", level, err)
		}
		f.exec(t, "DELETE FROM incidents WHERE status = 'open'")
	}
	for _, level := range severity.Levels {
		_, err := f.owner.Exec(t.Context(), "INSERT INTO alerts (incident_id, severity) SELECT id, $1 FROM incidents WHERE status = 'closed'", level)
		var pgErr *pgconn.PgError
		if level == severity.Info {
			if !errors.As(err, &pgErr) || pgErr.ConstraintName != "alerts_severity_check" {
				t.Errorf("alert of severity info: error = %v, want a violation of alerts_severity_check", err)
			}
		} else if err != nil {
			t.Errorf("alert of severity %s: %v", level, err)
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
	// No channel is enabled, so the alert reaches nobody.
	if !strings.Contains(buf.String(), `"msg":"alerting: no enabled channel"`) || !strings.Contains(buf.String(), `"level":"WARN"`) {
		t.Errorf("log = %s, want a warning that the alert reaches nobody", buf.String())
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

// An alert gets its deliveries, one for every enabled channel, in the
// transaction that opens its incident; events added to the incident later
// raise no further deliveries.
func TestStore_OpenedIncidentEnqueuesDeliveriesOfItsAlert(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for _, c := range []struct {
		name    string
		enabled bool
	}{{"a", true}, {"b", true}, {"off", false}} {
		f.exec(t, `INSERT INTO alert_channels (name, type, enabled, target) VALUES ($1, 'webhook', $2, 'https://h.example.com')`, c.name, c.enabled)
	}
	id, _ := f.honeytoken(t, "web_url", nil)
	f.event(t, id, "web_url", nil, time.Now())
	p := f.process(t)
	if !p.Opened || p.Deliveries != 2 {
		t.Fatalf("ProcessNext() = %+v, want an opened incident with 2 deliveries", p)
	}
	if n := f.count(t, "SELECT count(*) FROM alert_deliveries WHERE alert_id = $1 AND status = 'pending' AND channel_name IN ('a', 'b')", p.IncidentID); n != 2 {
		t.Errorf("%d deliveries, want one to each enabled channel", n)
	}
	f.event(t, id, "web_url", nil, time.Now())
	if p := f.process(t); p.Opened || p.Deliveries != 0 {
		t.Errorf("second event: %+v", p)
	}
	if n := f.count(t, "SELECT count(*) FROM alert_deliveries"); n != 2 {
		t.Errorf("%d deliveries after a second event, want 2", n)
	}
}

// An incident carries the name its resource had when the incident opened. A
// later event of the renamed resource, or of a resource that was deleted, does
// not change it.
func TestStore_IncidentKeepsTheNameItOpenedWith(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, value := f.honeytoken(t, "web_url", nil)
	f.exec(t, "UPDATE honeytokens SET name = 'Wiki' WHERE id = $1", id)
	f.exec(t, "SELECT * FROM record_honeytoken_request($1, 'GET', NULL, '', '', '', '')", value)
	opened := f.process(t)
	if opened.ResourceName != "Wiki" {
		t.Errorf("name of the processed incident = %q, want Wiki", opened.ResourceName)
	}

	f.exec(t, "UPDATE honeytokens SET name = 'Renamed' WHERE id = $1", id)
	f.exec(t, "SELECT * FROM record_honeytoken_request($1, 'GET', NULL, '', '', '', '')", value)
	if again := f.process(t); again.IncidentID != opened.IncidentID {
		t.Fatalf("event of the renamed honeytoken = %+v, want it in %s", again, opened.IncidentID)
	}
	f.exec(t, "DELETE FROM honeytokens WHERE id = $1", id)

	var name string
	if err := f.owner.QueryRow(t.Context(), `SELECT resource_name FROM incidents WHERE id = $1`, opened.IncidentID).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "Wiki" {
		t.Errorf("resource_name of the incident = %q, want the name when it opened", name)
	}
}
