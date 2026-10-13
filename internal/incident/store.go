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
	db DB
}

// NewStore returns a Store that works on d.
func NewStore(d DB) *Store {
	if d == nil {
		panic("incident: nil database")
	}
	return &Store{db: d}
}

// workerScope is everything that the worker's database role reaches. It reads
// no inventory: an event holds what its incident needs.
var workerScope = db.Scope{
	GroupRole: "nyktus_worker",
	Tables:    []string{"event_jobs", "events", "incidents", "alerts"},
	// The checks of the techniques run with the privileges of the role that
	// writes.
	Functions: []string{"public.attack_technique_ids_valid(text[])"},
}

// CheckPrivileges returns db.ErrRolePrivileges unless the connected role stays
// within the scope of the worker, as a member of nyktus_worker.
func CheckPrivileges(ctx context.Context, q db.Querier) error {
	return db.CheckScope(ctx, q, workerScope)
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

// ProcessNext processes the job of an event that is due, if there is one: it
// assigns the event to the open incident of its resource, or opens one with
// its alert, and deletes the job, all in one transaction. It calls claimed
// once it holds the job, before it processes it. found is false if no job was
// due.
//
// If the event cannot be processed, the job stays and is due again later, and
// ProcessNext returns a *JobError. Other errors mean that the database could
// not be reached or the transaction failed; the job stays as well.
func (s *Store) ProcessNext(ctx context.Context, claimed func()) (p Processed, found bool, err error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Processed{}, false, fmt.Errorf("process event job: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// SKIP LOCKED lets concurrent workers take different jobs instead of
	// waiting for each other.
	var attempts int
	err = tx.QueryRow(ctx, `
SELECT event_id, attempts FROM public.event_jobs
WHERE not_before <= statement_timestamp()
ORDER BY not_before
LIMIT 1
FOR UPDATE SKIP LOCKED`).Scan(&p.EventID, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return Processed{}, false, nil
	}
	if err != nil {
		return Processed{}, false, fmt.Errorf("process event job: %w", err)
	}
	claimed()

	// The event is processed in a savepoint, so that a failure can be
	// recorded on the job, which stays locked meanwhile.
	sp, err := tx.Begin(ctx)
	if err != nil {
		return Processed{}, true, fmt.Errorf("process event %s: %w", p.EventID, err)
	}
	if err := s.assign(ctx, sp, &p); err != nil {
		_ = sp.Rollback(ctx)
		return Processed{}, true, s.postpone(ctx, tx, p.EventID, attempts, err)
	}
	if err := sp.Commit(ctx); err != nil {
		return Processed{}, true, fmt.Errorf("process event %s: %w", p.EventID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Processed{}, true, fmt.Errorf("process event %s: %w", p.EventID, err)
	}
	return p, true, nil
}

// postpone records a failed attempt on the job of eventID and postpones it, so
// that a job that keeps failing does not hold up the jobs behind it. The wait
// doubles with every attempt, from two seconds up to an hour.
func (s *Store) postpone(ctx context.Context, tx pgx.Tx, eventID string, attempts int, cause error) error {
	jobErr := &JobError{EventID: eventID, Attempts: attempts + 1, Err: cause}
	err := tx.QueryRow(ctx, `
UPDATE public.event_jobs
SET attempts = attempts + 1,
	not_before = clock_timestamp() + least(interval '1 second' * power(2, least(attempts + 1, 12)), interval '1 hour')
WHERE event_id = $1
RETURNING not_before`, eventID).Scan(&jobErr.Retry)
	if err != nil {
		return fmt.Errorf("process event %s: %w; defer job: %w", eventID, cause, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("process event %s: %w; defer job: %w", eventID, cause, err)
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
FOR UPDATE`, p.ResourceType, p.ResourceID).Scan(&p.IncidentID, &current, &currentTechniques)
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
		p.Opened, p.Severity = true, severity
		return nil
	}
	return fmt.Errorf("open incident: no open incident after %d rounds", openRounds)
}
