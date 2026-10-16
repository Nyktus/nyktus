// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/platform/schematest"
)

// taskRun is what a periodic task looked like in the database after a run.
type taskRun struct {
	// untilNext is the time from the end of the run to the next one.
	untilNext                  time.Duration
	started, succeeded, failed bool
	rows                       *int64
}

func readTask(t *testing.T, pool *pgxpool.Pool, name string) taskRun {
	t.Helper()
	var r taskRun
	err := pool.QueryRow(t.Context(), `
SELECT next_run_at - clock_timestamp(), last_started_at IS NOT NULL, last_succeeded_at IS NOT NULL, last_failed_at IS NOT NULL, last_rows
FROM periodic_tasks WHERE name = $1`, name).Scan(&r.untilNext, &r.started, &r.succeeded, &r.failed, &r.rows)
	if err != nil {
		t.Fatalf("read periodic task %s: %v", name, err)
	}
	return r
}

// makeDue makes every periodic task due.
func makeDue(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `UPDATE periodic_tasks SET next_run_at = clock_timestamp() - interval '1 second'`); err != nil {
		t.Fatalf("make tasks due: %v", err)
	}
}

// stepTask is a task with the name of a row of periodic_tasks whose steps the
// test decides.
func stepTask(step func(ctx context.Context) (int64, bool, error)) Task {
	return Task{Name: TaskDeleteExpiredSignInData, Interval: time.Hour, Step: step}
}

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// A due task runs step by step until no more remains, and is then not due
// before its interval has passed.
func TestPeriodic_RunsADueTaskUntilDone(t *testing.T) {
	t.Parallel()

	ownerURL, workerURL := schematest.Worker(t)
	owner := schematest.Open(t, ownerURL)
	makeDue(t, owner)

	steps := 0
	p := NewPeriodic(discard(), schematest.Open(t, workerURL), []Task{stepTask(func(context.Context) (int64, bool, error) {
		steps++
		return 2, steps < 3, nil
	})})
	claimed := false
	found, err := p.Process(t.Context(), func() { claimed = true })
	if !found || err != nil || !claimed {
		t.Fatalf("Process() = %t, %v, claimed %t; want true, nil, claimed", found, err, claimed)
	}
	if steps != 3 {
		t.Errorf("steps = %d, want 3", steps)
	}
	r := readTask(t, owner, TaskDeleteExpiredSignInData)
	if !r.started || !r.succeeded || r.failed || r.rows == nil || *r.rows != 6 {
		t.Errorf("task after run = %+v, want started and succeeded with 6 rows", r)
	}
	if r.untilNext < 59*time.Minute || r.untilNext > time.Hour {
		t.Errorf("next run in %v, want about an hour", r.untilNext)
	}

	if found, err := p.Process(t.Context(), func() {}); found || err != nil {
		t.Errorf("Process() again = %t, %v; want false, nil: the task is not due", found, err)
	}
}

// Two workers that look for due tasks at the same time run each task once:
// the first one moves the task to its next run before it runs it, and a task
// that another worker is claiming is skipped instead of waited for.
func TestPeriodic_TwoWorkersRunATaskOnce(t *testing.T) {
	t.Parallel()

	ownerURL, workerURL := schematest.Worker(t)
	owner := schematest.Open(t, ownerURL)
	makeDue(t, owner)

	running, release := make(chan struct{}), make(chan struct{})
	runs := 0
	first := NewPeriodic(discard(), schematest.Open(t, workerURL), []Task{stepTask(func(context.Context) (int64, bool, error) {
		runs++
		close(running)
		<-release
		return 0, false, nil
	})})
	second := NewPeriodic(discard(), schematest.Open(t, workerURL), []Task{stepTask(func(context.Context) (int64, bool, error) {
		t.Error("the second worker ran the task as well")
		return 0, false, nil
	})})

	done := make(chan error, 1)
	go func() {
		_, err := first.Process(t.Context(), func() {})
		done <- err
	}()
	<-running
	if found, err := second.Process(t.Context(), func() {}); found || err != nil {
		t.Errorf("second Process() while the first runs = %t, %v; want false, nil", found, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first Process() error = %v", err)
	}

	// A claim that another transaction holds is skipped; waiting for it would
	// hold up the other tasks.
	makeDue(t, owner)
	tx, err := owner.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) })
	if _, err := tx.Exec(t.Context(), `SELECT FROM periodic_tasks FOR UPDATE`); err != nil {
		t.Fatalf("lock tasks: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if found, err := second.Process(ctx, func() {}); found || err != nil {
		t.Errorf("Process() while another transaction claims = %t, %v; want false, nil", found, err)
	}
	if runs != 1 {
		t.Errorf("runs = %d, want 1", runs)
	}
}

// A step that fails ends the run. The failure is recorded and the task is due
// again soon, not only after its interval.
func TestPeriodic_FailedStepIsRetriedSoon(t *testing.T) {
	t.Parallel()

	ownerURL, workerURL := schematest.Worker(t)
	owner := schematest.Open(t, ownerURL)
	makeDue(t, owner)

	errStep := errors.New("step failed")
	steps := 0
	p := NewPeriodic(discard(), schematest.Open(t, workerURL), []Task{stepTask(func(context.Context) (int64, bool, error) {
		steps++
		if steps == 2 {
			return 0, false, errStep
		}
		return 1, true, nil
	})})
	found, err := p.Process(t.Context(), func() {})
	if !found || !errors.Is(err, errStep) {
		t.Fatalf("Process() = %t, %v; want true, %v", found, err, errStep)
	}
	if steps != 2 {
		t.Errorf("steps = %d, want 2: the run ends with the failed step", steps)
	}
	r := readTask(t, owner, TaskDeleteExpiredSignInData)
	if !r.failed || r.succeeded || r.rows != nil {
		t.Errorf("task after failed run = %+v, want failed, not succeeded, without rows", r)
	}
	if r.untilNext > retryDelay {
		t.Errorf("next run in %v, want within %v", r.untilNext, retryDelay)
	}
}

// A worker that stops ends a run after its current step, which completes. The
// task is due again soon, without a failure.
func TestPeriodic_StopEndsTheRunAfterTheCurrentStep(t *testing.T) {
	t.Parallel()

	ownerURL, workerURL := schematest.Worker(t)
	owner := schematest.Open(t, ownerURL)
	makeDue(t, owner)

	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	steps := 0
	p := NewPeriodic(discard(), schematest.Open(t, workerURL), []Task{stepTask(func(stepCtx context.Context) (int64, bool, error) {
		steps++
		stop()
		// The step itself is not canceled with the worker.
		if err := stepCtx.Err(); err != nil {
			return 0, false, err
		}
		// More remains after the first step, but a run that ignored the stop
		// would end after the third.
		return 1, steps < 3, nil
	})})
	found, err := p.Process(ctx, func() {})
	if !found || err != nil {
		t.Fatalf("Process() = %t, %v; want true, nil", found, err)
	}
	if steps != 1 {
		t.Errorf("steps = %d, want 1", steps)
	}
	r := readTask(t, owner, TaskDeleteExpiredSignInData)
	if r.failed || r.succeeded {
		t.Errorf("task after stop = %+v, want neither failed nor succeeded", r)
	}
	if r.untilNext > retryDelay {
		t.Errorf("next run in %v, want within %v", r.untilNext, retryDelay)
	}
}

// A worker takes only the tasks that it knows, so that a task without code
// does not fail every poll.
func TestPeriodic_TakesOnlyItsTasks(t *testing.T) {
	t.Parallel()

	ownerURL, workerURL := schematest.Worker(t)
	makeDue(t, schematest.Open(t, ownerURL))

	p := NewPeriodic(discard(), schematest.Open(t, workerURL), nil)
	if found, err := p.Process(t.Context(), func() { t.Error("claimed a task without code") }); found || err != nil {
		t.Errorf("Process() = %t, %v; want false, nil", found, err)
	}
}

// The task removes expired sign-in data a batch at a time, with the
// privileges of the worker, and reports more while a full batch was removed.
func TestDeleteExpiredSignInData_StepsInBatches(t *testing.T) {
	t.Parallel()

	ownerURL, workerURL := schematest.Worker(t)
	if _, err := schematest.Open(t, ownerURL).Exec(t.Context(), `
INSERT INTO oidc_logins (state_hash, browser_hash, nonce, code_verifier, purpose, expires_at)
SELECT sha256(convert_to(i::text, 'UTF8')), sha256(convert_to(i::text, 'UTF8')), repeat('n', 43), repeat('v', 43), 'sign_in',
	clock_timestamp() - interval '1 second'
FROM generate_series(1, $1::int) AS i`, BatchSize+1); err != nil {
		t.Fatalf("insert sign-ins: %v", err)
	}
	task := DeleteExpiredSignInData(schematest.Open(t, workerURL))
	for _, want := range []struct {
		rows int64
		more bool
	}{{BatchSize, true}, {1, false}} {
		rows, more, err := task.Step(t.Context())
		if rows != want.rows || more != want.more || err != nil {
			t.Errorf("Step() = %d, %t, %v; want %d, %t, nil", rows, more, err, want.rows, want.more)
		}
	}
}

func TestNewPeriodic_RejectsInvalidTasks(t *testing.T) {
	t.Parallel()

	step := func(context.Context) (int64, bool, error) { return 0, false, nil }
	valid := Task{Name: "a", Interval: time.Minute, Step: step}
	for name, tasks := range map[string][]Task{
		"duplicate":      {valid, valid},
		"without name":   {{Interval: time.Minute, Step: step}},
		"without step":   {{Name: "a", Interval: time.Minute}},
		"short interval": {{Name: "a", Interval: time.Millisecond, Step: step}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Error("NewPeriodic() did not panic")
				}
			}()
			NewPeriodic(discard(), &pgxpool.Pool{}, tasks)
		})
	}
}

// The tasks of the retention run with the privileges of the worker and pass
// the configured retention to the database.
func TestRetentionTasks_DeleteWhatIsBeyondTheirRetention(t *testing.T) {
	t.Parallel()

	ownerURL, workerURL := schematest.Worker(t)
	owner := schematest.Open(t, ownerURL)
	if _, err := owner.Exec(t.Context(), `
INSERT INTO audit_entries (occurred_at, action, outcome, actor_kind, auth_method, changed_fields)
VALUES (clock_timestamp() - interval '101 days', 'user.create', 'success', 'system', 'cli', '{}'),
	(clock_timestamp() - interval '99 days', 'user.create', 'success', 'system', 'cli', '{}')`); err != nil {
		t.Fatalf("insert audit entries: %v", err)
	}
	if _, err := owner.Exec(t.Context(), `
INSERT INTO events (resource_type, resource_id, honeytoken_type, occurred_at, recorded_at, channel, method)
SELECT 'honeytoken', gen_random_uuid(), 'web_url', t, t, 'http', 'GET'
FROM unnest(ARRAY[clock_timestamp() - interval '41 days', clock_timestamp() - interval '39 days']) AS t`); err != nil {
		t.Fatalf("insert events: %v", err)
	}
	worker := schematest.Open(t, workerURL)
	for _, task := range []Task{DeleteExpiredAuditEntries(worker, 100), DeleteExpiredIncidentData(worker, 40)} {
		rows, more, err := task.Step(t.Context())
		if rows != 1 || more || err != nil {
			t.Errorf("%s: Step() = %d, %t, %v; want 1, false, nil", task.Name, rows, more, err)
		}
	}
	// A retention below the limit of the database fails the task.
	if _, _, err := DeleteExpiredAuditEntries(worker, 1).Step(t.Context()); err == nil {
		t.Error("Step() with a retention of one day succeeded")
	}
}
