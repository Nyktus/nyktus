// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/platform/db"
)

// BatchSize bounds the rows that one step of a periodic task removes or
// changes, so that no step holds many locks or runs long.
const BatchSize = 1000

// Task is a periodic task of the worker, such as removing expired rows.
type Task struct {
	// Name names the row of the task in periodic_tasks.
	Name string
	// Interval is the time from the start of one run to the next.
	Interval time.Duration
	// Step does a bounded part of the task in a transaction of its own and
	// returns the rows that it removed or changed and whether more may
	// remain. Runs of a task can overlap, when one takes longer than the
	// interval, and a run can end after any step, so a step must be safe to
	// repeat and to run beside another one.
	Step func(ctx context.Context) (rows int64, more bool, err error)
}

// retryDelay is the wait before a run that failed or was cut short starts
// again.
const retryDelay = time.Minute

// recordTimeout bounds recording the end of a run, also when the run ended on
// its deadline.
const recordTimeout = 5 * time.Second

// Periodic runs periodic tasks as a Queue: every task is a job that is due at
// its next run. The next run is stored in the database, so that several
// worker processes share the tasks and each task runs once per interval.
type Periodic struct {
	logger    *slog.Logger
	db        db.Querier
	tasks     map[string]Task
	names     []string
	intervals []int64
}

// NewPeriodic returns a Periodic that runs tasks on d. It panics on a missing
// logger, database or step, a duplicate name or an interval below a second,
// which are programming errors.
func NewPeriodic(logger *slog.Logger, d db.Querier, tasks []Task) *Periodic {
	if logger == nil || d == nil {
		panic("worker: nil logger or database")
	}
	p := &Periodic{logger: logger, db: d, tasks: make(map[string]Task, len(tasks))}
	for _, t := range tasks {
		if _, ok := p.tasks[t.Name]; ok || t.Name == "" || t.Step == nil || t.Interval < time.Second {
			panic(fmt.Sprintf("worker: invalid periodic task %q", t.Name))
		}
		p.tasks[t.Name] = t
		p.names = append(p.names, t.Name)
		p.intervals = append(p.intervals, t.Interval.Microseconds())
	}
	return p
}

// claimQuery takes the task that has been due longest and moves it to its
// next run, in one statement: the run then needs no transaction that stays
// open while it runs, and a worker that stops or fails meanwhile leaves the
// task due at its next run, not at once. Tasks that another transaction is
// claiming are skipped. Only tasks of this worker are taken.
const claimQuery = `
WITH due AS (
	SELECT p.name, t.interval_us
	FROM public.periodic_tasks AS p
	JOIN unnest($1::text[], $2::bigint[]) AS t (name, interval_us) ON t.name = p.name
	WHERE p.next_run_at <= statement_timestamp()
	ORDER BY p.next_run_at
	LIMIT 1
	FOR UPDATE OF p SKIP LOCKED
)
UPDATE public.periodic_tasks AS p
SET next_run_at = clock_timestamp() + interval '1 microsecond' * due.interval_us, last_started_at = clock_timestamp()
FROM due
WHERE p.name = due.name
RETURNING p.name`

// Process runs the periodic task that is due, if there is one, step by step
// until no more remains. It calls claimed once it has taken the task.
//
// Canceling ctx ends the search for a task and the run after its current
// step, which ends within the deadline of ctx; the task is then due again
// soon. A step that fails ends the run, which is recorded as failed and due
// again soon as well.
func (p *Periodic) Process(ctx context.Context, claimed func()) (bool, error) {
	var name string
	err := p.db.QueryRow(ctx, claimQuery, p.names, p.intervals).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("claim periodic task: %w", err)
	}
	claimed()
	task := p.tasks[name]

	stepCtx, cancel := withoutCancel(ctx)
	defer cancel()
	var rows int64
	for {
		n, more, err := task.Step(stepCtx)
		rows += n
		switch {
		case err != nil:
			err = fmt.Errorf("periodic task %s: %w", name, err)
			if recordErr := p.retrySoon(ctx, name, true); recordErr != nil {
				err = errors.Join(err, recordErr)
			}
			return true, err
		case !more:
			if err := p.recordSuccess(ctx, name, rows); err != nil {
				return true, err
			}
			level := slog.LevelDebug
			if rows > 0 {
				level = slog.LevelInfo
			}
			p.logger.Log(ctx, level, "worker: periodic task completed", slog.String("task", name), slog.Int64("rows", rows))
			return true, nil
		case ctx.Err() != nil:
			return true, p.retrySoon(ctx, name, false)
		}
	}
}

// recordSuccess records that a run of the task name ended with rows removed
// or changed. Like retrySoon, it runs on a context of its own, so that a run
// that ended on its deadline or with the worker is still recorded.
func (p *Periodic) recordSuccess(ctx context.Context, name string, rows int64) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	if _, err := p.db.Exec(ctx, `
UPDATE public.periodic_tasks SET last_succeeded_at = clock_timestamp(), last_rows = $2 WHERE name = $1`, name, rows); err != nil {
		return fmt.Errorf("record run of periodic task %s: %w", name, err)
	}
	return nil
}

// retrySoon moves the next run of the task name closer after a run that
// failed or was cut short, so that the rest is not left until the next
// interval, and records a failure.
func (p *Periodic) retrySoon(ctx context.Context, name string, failed bool) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	if _, err := p.db.Exec(ctx, `
UPDATE public.periodic_tasks
SET next_run_at = least(next_run_at, clock_timestamp() + $2::interval),
	last_failed_at = CASE WHEN $3 THEN clock_timestamp() ELSE last_failed_at END
WHERE name = $1`, name, retryDelay, failed); err != nil {
		return fmt.Errorf("record run of periodic task %s: %w", name, err)
	}
	return nil
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
