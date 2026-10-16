// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package incident

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/alerting"
	"nyktus.org/nyktus/internal/platform/db"
)

// DB runs queries and starts transactions. A connection pool implements it.
type DB interface {
	db.Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Store assigns events to incidents, with the privileges of the worker's
// database role.
type Store struct {
	db          DB
	lockTimeout time.Duration
}

// NewStore returns a Store that works on d.
func NewStore(d DB) *Store {
	if d == nil {
		panic("incident: nil database")
	}
	return &Store{db: d, lockTimeout: defaultLockTimeout}
}

// Processed describes the job of an event that was processed.
type Processed struct {
	EventID      string
	IncidentID   string
	ResourceType string
	ResourceID   string
	// Opened reports whether the event opened the incident, together with its
	// alert.
	Opened bool
	// Deliveries counts the deliveries of the alert, one for every enabled
	// alert channel, if the event opened the incident.
	Deliveries int
	// Severity is the severity of the incident after the event.
	Severity Severity
}

// LogValue implements slog.LogValuer.
func (p Processed) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("event_id", p.EventID),
		slog.String("incident_id", p.IncidentID),
		slog.String("resource_type", p.ResourceType),
		slog.String("resource_id", p.ResourceID),
		slog.String("severity", string(p.Severity)),
	)
}

// JobError means that the job of an event failed and stays to be tried again
// later. The event is not assigned to an incident until then.
type JobError struct {
	EventID string
	// Attempts counts the failed attempts, including this one.
	Attempts int
	// Retry is when the job is due again.
	Retry time.Time
	Err   error
}

func (e *JobError) Error() string {
	return fmt.Sprintf("process event %s: %v", e.EventID, e.Err)
}

func (e *JobError) Unwrap() error { return e.Err }

// openRounds bounds the attempts to find or open the incident of an event. A
// round fails only if a concurrent transaction opens and closes the incident of
// the resource in between, which needs a human closing it within moments.
const openRounds = 3

// postponeTimeout bounds ending a transaction and recording a failed attempt
// when the attempt broke off its transaction, for example on its deadline.
const postponeTimeout = 5 * time.Second

// defaultLockTimeout bounds the wait for the lock of an incident. A lock held
// longer, for example by a forgotten session, fails the attempt with an error
// that its transaction survives, so that the attempt is recorded while the job
// is still held. The deadline of the job is the last resort.
const defaultLockTimeout = 5 * time.Second

// ProcessNext processes the job of an event that is due, if there is one: it
// assigns the event to the open incident of its resource, or opens one with
// its alert, and deletes the job, all in one transaction. It calls claimed once
// it holds the job. found is false if no job was due.
//
// Canceling ctx ends the search for a job, but not a job that was taken: it
// runs to its end within the deadline of ctx, so that a stopping worker
// completes its transaction instead of cutting it off.
//
// If the event cannot be processed, the job stays and is due again later, and
// ProcessNext returns a *JobError. Other errors mean that the database could
// not be reached; the job stays as well.
func (s *Store) ProcessNext(ctx context.Context, claimed func()) (p Processed, found bool, err error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Processed{}, false, fmt.Errorf("process event job: %w", err)
	}
	defer rollback(ctx, tx)

	// SKIP LOCKED lets concurrent workers take different jobs instead of
	// waiting for each other.
	err = tx.QueryRow(ctx, `
SELECT event_id FROM public.event_jobs
WHERE not_before <= statement_timestamp()
ORDER BY not_before
LIMIT 1
FOR UPDATE SKIP LOCKED`).Scan(&p.EventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Processed{}, false, nil
	}
	if err != nil {
		return Processed{}, false, fmt.Errorf("process event job: %w", err)
	}
	claimed()
	ctx, cancel := withoutCancel(ctx)
	defer cancel()

	// The event is processed in a savepoint. If it fails, the failure is
	// recorded in this transaction, which still holds the job; released
	// first, the job would be due and could be taken again at once, before
	// it is postponed.
	held, cause := s.assignInSavepoint(ctx, tx, &p)
	if cause == nil {
		if err := tx.Commit(ctx); err != nil {
			return Processed{}, true, s.postponeAfterBreak(ctx, p.EventID, fmt.Errorf("commit: %w", err))
		}
		return p, true, nil
	}
	if held {
		jobErr, err := postpone(ctx, tx, p.EventID, cause)
		if err == nil {
			err = tx.Commit(ctx)
		}
		if err == nil {
			return Processed{}, true, jobErr
		}
	}
	return Processed{}, true, s.postponeAfterBreak(ctx, p.EventID, cause)
}

// assignInSavepoint assigns the event of p in a savepoint of tx. On failure,
// it returns whether tx still holds the job, that is, whether the savepoint
// could be rolled back, and the cause.
func (s *Store) assignInSavepoint(ctx context.Context, tx pgx.Tx, p *Processed) (held bool, cause error) {
	if _, err := tx.Exec(ctx, "SELECT set_config('lock_timeout', $1, true)", fmt.Sprintf("%dms", s.lockTimeout.Milliseconds())); err != nil {
		return false, fmt.Errorf("set lock timeout: %w", err)
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin savepoint: %w", err)
	}
	if err := s.assign(ctx, sp, p); err != nil {
		return sp.Rollback(ctx) == nil, err
	}
	if err := sp.Commit(ctx); err != nil {
		return false, fmt.Errorf("release savepoint: %w", err)
	}
	return true, nil
}

// rollback ends tx unless it was committed. It runs on a context of its own,
// so that a canceled ctx does not break off the connection instead of rolling
// back.
func rollback(ctx context.Context, tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), postponeTimeout)
	defer cancel()
	_ = tx.Rollback(ctx)
}

// withoutCancel returns a context that keeps the values and the deadline of
// ctx, but is not canceled with it.
func withoutCancel(ctx context.Context) (context.Context, context.CancelFunc) {
	detached := context.WithoutCancel(ctx)
	if deadline, ok := ctx.Deadline(); ok {
		return context.WithDeadline(detached, deadline)
	}
	return detached, func() {}
}

// postponeQuery records a failed attempt on a job and postpones it, so that a
// job that keeps failing does not hold up the jobs behind it. The wait doubles
// with every attempt, from two seconds up to an hour. A job that another
// transaction holds is skipped: that transaction is processing it.
const postponeQuery = `
UPDATE public.event_jobs
SET attempts = attempts + 1,
	not_before = clock_timestamp() + least(interval '1 second' * power(2, least(attempts + 1, 12)), interval '1 hour')
WHERE event_id = (SELECT event_id FROM public.event_jobs WHERE event_id = $1 FOR UPDATE SKIP LOCKED)
RETURNING attempts, not_before`

// postpone records the failed attempt cause on the job of eventID on q.
func postpone(ctx context.Context, q db.Querier, eventID string, cause error) (*JobError, error) {
	jobErr := &JobError{EventID: eventID, Err: cause}
	if err := q.QueryRow(ctx, postponeQuery, eventID).Scan(&jobErr.Attempts, &jobErr.Retry); err != nil {
		return nil, err
	}
	return jobErr, nil
}

// postponeAfterBreak records a failed attempt whose transaction broke off, for
// example on its deadline, in a transaction of its own. The job is due again
// meanwhile; if another worker has taken or completed it, the attempt is not
// recorded.
func (s *Store) postponeAfterBreak(ctx context.Context, eventID string, cause error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), postponeTimeout)
	defer cancel()

	jobErr, err := postpone(ctx, s.db, eventID, cause)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("process event %s: %w; another worker took the job meanwhile", eventID, cause)
	}
	if err != nil {
		return fmt.Errorf("process event %s: %w; postpone job: %w", eventID, cause, err)
	}
	return jobErr
}

// assign assigns the event of p to an incident and deletes its job. Locks are
// taken in the order job, incident, as everywhere.
func (s *Store) assign(ctx context.Context, tx pgx.Tx, p *Processed) error {
	var (
		honeytokenType *string
		techniques     []string
		occurredAt     time.Time
	)
	err := tx.QueryRow(ctx, `
SELECT resource_type, resource_id, honeytoken_type, techniques, occurred_at
FROM public.events WHERE id = $1`, p.EventID).Scan(&p.ResourceType, &p.ResourceID, &honeytokenType, &techniques, &occurredAt)
	if err != nil {
		return fmt.Errorf("load event: %w", err)
	}
	severity, err := eventSeverity(p.ResourceType, honeytokenType)
	if err != nil {
		return err
	}

	if err := s.open(ctx, tx, p, severity, techniques, occurredAt); err != nil {
		return err
	}

	tag, err := tx.Exec(ctx, `UPDATE public.events SET incident_id = $1 WHERE id = $2 AND incident_id IS NULL`, p.IncidentID, p.EventID)
	if err != nil {
		return fmt.Errorf("assign event: %w", err)
	}
	// An event that already belongs to an incident keeps it. Its job is left
	// for an operator to look into instead of being dropped silently.
	if tag.RowsAffected() != 1 {
		return errors.New("assign event: event is already assigned to an incident")
	}
	if _, err := tx.Exec(ctx, `DELETE FROM public.event_jobs WHERE event_id = $1`, p.EventID); err != nil {
		return fmt.Errorf("delete job: %w", err)
	}
	return nil
}

// open finds the open incident of the resource of p and adds the event to it,
// or opens one with its alert. It sets the incident of p.
//
// Two workers that process events of the same resource at the same time must
// not open two incidents. The unique index over open incidents decides: an
// INSERT that conflicts with an incident that another transaction has just
// opened waits for that transaction and then inserts nothing, and the next
// round finds the incident. An incident that is closed while a round waits for
// its lock no longer matches, and the round opens a new one.
func (s *Store) open(ctx context.Context, tx pgx.Tx, p *Processed, severity Severity, techniques []string, occurredAt time.Time) error {
	for range openRounds {
		var (
			current           Severity
			currentTechniques []string
		)
		err := tx.QueryRow(ctx, `
SELECT id, severity, techniques FROM public.incidents
WHERE resource_type = $1 AND resource_id = $2 AND status <> 'closed'
FOR NO KEY UPDATE`, p.ResourceType, p.ResourceID).Scan(&p.IncidentID, &current, &currentTechniques)
		switch {
		case err == nil:
			p.Severity = higher(current, severity)
			_, err := tx.Exec(ctx, `
UPDATE public.incidents
SET severity = $2, techniques = $3, event_count = event_count + 1,
	first_event_at = least(first_event_at, $4), last_event_at = greatest(last_event_at, $4)
WHERE id = $1`, p.IncidentID, p.Severity, union(currentTechniques, techniques), occurredAt)
			if err != nil {
				return fmt.Errorf("add event to incident: %w", err)
			}
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("find incident: %w", err)
		}

		err = tx.QueryRow(ctx, `
INSERT INTO public.incidents (resource_type, resource_id, severity, techniques, first_event_at, last_event_at)
VALUES ($1, $2, $3, $4, $5, $5)
ON CONFLICT (resource_type, resource_id) WHERE status <> 'closed' DO NOTHING
RETURNING id`, p.ResourceType, p.ResourceID, severity, techniques, occurredAt).Scan(&p.IncidentID)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			continue
		case err != nil:
			return fmt.Errorf("open incident: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.alerts (incident_id, severity, techniques) VALUES ($1, $2, $3)`,
			p.IncidentID, severity, techniques); err != nil {
			return fmt.Errorf("raise alert: %w", err)
		}
		// The alert and its deliveries are written together, so that an
		// alert is never left without them.
		if p.Deliveries, err = alerting.Enqueue(ctx, tx, p.IncidentID); err != nil {
			return err
		}
		p.Opened, p.Severity = true, severity
		return nil
	}
	return fmt.Errorf("open incident: no open incident after %d rounds", openRounds)
}
