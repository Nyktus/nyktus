// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenario_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"nyktus.org/nyktus/internal/scenario"
)

// assertLockedAgainst fails the test unless the statement, run from a
// transaction of its own, cannot take the lock it asks for at once. The
// statement ends with NOWAIT.
func assertLockedAgainst(t *testing.T, d testDB, statement string, args ...any) {
	t.Helper()
	tx, err := d.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	_, err = tx.Exec(t.Context(), statement, args...)
	var pgErr *pgconn.PgError
	// 55P03 is lock_not_available.
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("%s: error = %v, want lock_not_available", statement, err)
	}
}

// waitForLockWaiter returns once a session of the test database waits for a
// lock, or fails the test if done receives first.
func waitForLockWaiter[T any](t *testing.T, d testDB, done <-chan T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		var waiting bool
		err := d.owner.QueryRow(ctx, `
SELECT EXISTS (SELECT FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting)
		if err != nil {
			t.Fatalf("query waiting sessions: %v", err)
		}
		if waiting {
			return
		}
		select {
		case r := <-done:
			t.Fatalf("the operation completed without waiting for the scenario: %v", r)
		default:
		}
	}
}

// What adds a deception to a scenario, or removes one, holds its lock until the
// end of the transaction, a lock that excludes another change and the deletion,
// so that two of them never interleave.
func TestAddAndRemoveDeception_LockTheScenarioFirst(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	if _, err := scenario.AddDeception(t.Context(), d.console, actor, addition(t, c, sc.ID, "hint", false)); err != nil {
		t.Fatal(err)
	}

	for name, run := range map[string]func(scenario.DB) error{
		"add": func(tx scenario.DB) error {
			_, err := scenario.AddDeception(t.Context(), tx, actor, addition(t, c, sc.ID, "ssh", true))
			return err
		},
		"remove": func(tx scenario.DB) error {
			_, err := scenario.RemoveDeception(t.Context(), tx, actor, sc.ID, "hint")
			return err
		},
	} {
		tx, err := d.console.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := run(tx); err != nil {
			_ = tx.Rollback(t.Context())
			t.Fatalf("%s: %v", name, err)
		}
		assertLockedAgainst(t, d, `SELECT id FROM scenarios WHERE id = $1 FOR NO KEY UPDATE NOWAIT`, sc.ID)
		assertLockedAgainst(t, d, `SELECT id FROM scenarios WHERE id = $1 FOR UPDATE NOWAIT`, sc.ID)
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}

// A removal waits for the lock of the scenario before it touches the row of the
// deception. Whoever adds the same deception locks the scenario first and then
// writes that row, so a removal that took the row first could deadlock with it.
func TestRemoveDeception_TakesTheLockOfTheScenarioBeforeTheRowOfTheDeception(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	if _, err := scenario.AddDeception(t.Context(), d.console, actor, addition(t, c, sc.ID, "hint", false)); err != nil {
		t.Fatal(err)
	}

	holder, err := d.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := holder.Exec(t.Context(), `SELECT FROM scenarios WHERE id = $1 FOR NO KEY UPDATE`, sc.ID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := scenario.RemoveDeception(t.Context(), d.console, actor, sc.ID, "hint")
		done <- err
	}()
	waitForLockWaiter(t, d, done)

	// The removal waits for the scenario and has not touched the row.
	tx, err := d.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := tx.Exec(t.Context(), `SELECT FROM scenario_deceptions WHERE scenario_id = $1 FOR UPDATE NOWAIT`, sc.ID); err != nil {
		t.Errorf("probe of the row of the deception: error = %v, want no lock while the removal waits for the scenario", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := holder.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Errorf("RemoveDeception() error = %v", err)
	}
}

// A deception that is added while the scenario is being deleted waits for the
// deletion and then finds no scenario; nothing is left behind.
func TestAddDeception_WaitsForTheDeletionOfTheScenario(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})

	tx, err := d.console.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := scenario.NewStore(tx).Delete(t.Context(), sc.ID, scenario.ResourceRemovals{
		Honeytokens: scenario.RemovalKeep, Honeypots: scenario.RemovalKeep,
	}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := scenario.AddDeception(t.Context(), d.console, actor, addition(t, c, sc.ID, "ssh", true))
		done <- err
	}()
	waitForLockWaiter(t, d, done)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, scenario.ErrNotFound) {
		t.Errorf("AddDeception() error = %v, want ErrNotFound", err)
	}
	for _, table := range []string{"scenarios", "scenario_deceptions", "honeytokens", "honeypots"} {
		if n := count(t, d, `SELECT count(*) FROM `+table); n != 0 {
			t.Errorf("%d rows in %s, want none", n, table)
		}
	}
}

// Several requests that add the same deception at once, with its resources:
// one wins, the others are told that the deception is part of the scenario,
// and only the winner has created resources.
func TestAddDeception_ConcurrentRepeatsCreateTheResourcesOnce(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})

	const n = 4
	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		results = make(chan error, n)
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := scenario.AddDeception(t.Context(), d.console, actor, addition(t, c, sc.ID, "ssh", true))
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var won, repeated int
	for err := range results {
		switch {
		case err == nil:
			won++
		case errors.Is(err, scenario.ErrDeceptionAdded):
			repeated++
		default:
			t.Errorf("AddDeception() error = %v", err)
		}
	}
	if won != 1 || repeated != n-1 {
		t.Errorf("%d won and %d were told of the repeat, want 1 and %d", won, repeated, n-1)
	}
	if h, p := count(t, d, `SELECT count(*) FROM honeytokens`), count(t, d, `SELECT count(*) FROM honeypots`); h != 2 || p != 1 {
		t.Errorf("%d honeytokens and %d honeypots, want 2 and 1 of the winner only", h, p)
	}
}
