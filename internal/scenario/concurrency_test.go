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

	"nyktus.org/nyktus/internal/artifact"
	"nyktus.org/nyktus/internal/catalog"
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

// What adds to a scenario holds its lock until the end of the transaction, and
// it is a lock that excludes another change of the persona and the deletion,
// but not the assignment of a honeytoken, which only keeps the scenario from
// going away.
func TestAddDeception_LocksTheScenarioFirst(t *testing.T) {
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
	if _, err := scenario.AddDeception(t.Context(), tx, actor, scenario.Addition{ScenarioID: sc.ID, Join: join(t, c, "ssh", domain)}); err != nil {
		t.Fatal(err)
	}
	assertLockedAgainst(t, d, `SELECT id FROM scenarios WHERE id = $1 FOR NO KEY UPDATE NOWAIT`, sc.ID)
	assertLockedAgainst(t, d, `SELECT id FROM scenarios WHERE id = $1 FOR UPDATE NOWAIT`, sc.ID)
}

func TestAddArtifact_LocksTheScenarioFirst(t *testing.T) {
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
	if _, err := scenario.AddArtifact(t.Context(), tx, actor, artifactAddition(t, c, sc.ID, "memo", nil, nil)); err != nil {
		t.Fatal(err)
	}
	assertLockedAgainst(t, d, `SELECT id FROM scenarios WHERE id = $1 FOR NO KEY UPDATE NOWAIT`, sc.ID)
}

// Two deceptions that join at once with the same new key of the persona and
// different values: one wins and its value stays, the other is refused with
// the conflict, and what it created is gone with it.
func TestAddDeception_ConcurrentPersonaConflict(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})

	values := map[string]string{"ssh": "one.example.com", "pair": "two.example.com"}
	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		results = map[string]error{}
		mu      sync.Mutex
	)
	for id, value := range values {
		wg.Go(func() {
			<-start
			_, err := scenario.AddDeception(t.Context(), d.console, actor, scenario.Addition{
				ScenarioID: sc.ID, Join: join(t, c, id, map[string]string{"Domain": value}),
			})
			mu.Lock()
			results[id] = err
			mu.Unlock()
		})
	}
	close(start)
	wg.Wait()

	var winner string
	for id, err := range results {
		switch {
		case err == nil && winner == "":
			winner = id
		case err == nil:
			t.Errorf("both deceptions joined: %v", results)
		case !errors.Is(err, catalog.ErrPersonaConflict):
			t.Errorf("%s: AddDeception() error = %v, want the conflict of the persona", id, err)
		}
	}
	if winner == "" {
		t.Fatalf("no deception joined: %v", results)
	}
	got, err := scenario.NewStore(d.console).Get(t.Context(), sc.ID)
	if err != nil || got.Persona["Domain"] != values[winner] || len(got.Deceptions) != 1 || got.Deceptions[0].DeceptionID != winner {
		t.Errorf("scenario = %+v, %v; want the domain and the deception of %s", got, err, winner)
	}
	// What the loser created is gone: two honeytokens and the artifacts of the winner.
	want := map[string]int{"ssh": 1, "pair": 2}[winner]
	if n := count(t, d, `SELECT count(*) FROM honeytokens`); n != 2 {
		t.Errorf("%d honeytokens, want the 2 of the winner", n)
	}
	if n := count(t, d, `SELECT count(*) FROM artifacts`); n != want {
		t.Errorf("%d artifacts, want the %d of the winner", n, want)
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
		Honeytokens: scenario.RemovalKeep, Honeypots: scenario.RemovalKeep, Artifacts: scenario.RemovalKeep,
	}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := scenario.AddDeception(t.Context(), d.console, actor, scenario.Addition{ScenarioID: sc.ID, Join: join(t, c, "ssh", domain)})
		done <- err
	}()
	waitForLockWaiter(t, d, done)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, scenario.ErrNotFound) {
		t.Errorf("AddDeception() error = %v, want ErrNotFound", err)
	}
	for _, table := range []string{"scenarios", "scenario_deceptions", "honeytokens", "artifacts"} {
		if n := count(t, d, `SELECT count(*) FROM `+table); n != 0 {
			t.Errorf("%d rows in %s, want none", n, table)
		}
	}
}

// The schema lets the persona grow and nothing else, whatever role writes it.
func TestSchema_ThePersonaOnlyGrows(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	if _, err := d.console.Exec(t.Context(), `UPDATE scenarios SET persona = '{"Domain": "corp.example.com"}' WHERE id = $1`, sc.ID); err != nil {
		t.Fatalf("add a key: %v", err)
	}

	for _, tt := range []struct {
		name, statement string
		allowed         bool
	}{
		{"add another key", `UPDATE scenarios SET persona = persona || '{"Company": "Example Ltd"}'`, true},
		{"repeat a value", `UPDATE scenarios SET persona = persona || '{"Domain": "corp.example.com"}'`, true},
		{"change the persona of nothing else", `UPDATE scenarios SET name = 't', updated_at = clock_timestamp()`, true},
		{"change a value", `UPDATE scenarios SET persona = persona || '{"Domain": "other.example.com"}'`, false},
		{"change the case of a value", `UPDATE scenarios SET persona = persona || '{"Domain": "Corp.example.com"}'`, false},
		{"remove a key", `UPDATE scenarios SET persona = persona - 'Domain'`, false},
		{"remove every key", `UPDATE scenarios SET persona = '{}'`, false},
	} {
		_, err := d.console.Exec(t.Context(), tt.statement)
		var pgErr *pgconn.PgError
		switch {
		case tt.allowed && err != nil:
			t.Errorf("%s: error = %v, want it to succeed", tt.name, err)
		case !tt.allowed && (!errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "scenarios_persona_grows_check"):
			t.Errorf("%s: error = %v, want a violation of scenarios_persona_grows_check", tt.name, err)
		}
	}
	// What the persona may hold is the rule of the check, as before.
	for _, statement := range []string{
		`UPDATE scenarios SET persona = persona || '{"Port": 22}'`,
		`UPDATE scenarios SET persona = '[]'`,
	} {
		_, err := d.console.Exec(t.Context(), statement)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Errorf("%s: error = %v, want a check violation", statement, err)
		}
	}
	var persona map[string]string
	if err := d.owner.QueryRow(t.Context(), `SELECT persona FROM scenarios WHERE id = $1`, sc.ID).Scan(&persona); err != nil ||
		len(persona) != 2 || persona["Domain"] != "corp.example.com" {
		t.Errorf("persona = %v, %v; want the domain and the company", persona, err)
	}
}

// The limits hold when two additions race for the last place.
func TestAdd_ConcurrentAdditionsRespectTheLimits(t *testing.T) {
	t.Parallel()
	c := testCatalog(t)

	race := func(t *testing.T, name string, run func(i int) error, want error) {
		t.Helper()
		var (
			wg      sync.WaitGroup
			start   = make(chan struct{})
			errs    [2]error
			success int
		)
		for i := range errs {
			wg.Go(func() {
				<-start
				errs[i] = run(i)
			})
		}
		close(start)
		wg.Wait()
		for _, err := range errs {
			switch {
			case err == nil:
				success++
			case !errors.Is(err, want):
				t.Errorf("%s: error = %v, want %v", name, err, want)
			}
		}
		if success != 1 {
			t.Errorf("%s: %d additions succeeded, want exactly one: %v", name, success, errs)
		}
	}

	t.Run("deceptions", func(t *testing.T) {
		t.Parallel()
		d := newTestDB(t)
		actor := createUser(t, d)
		sc := create(t, d, scenario.Spec{Name: "s"})
		if _, err := d.owner.Exec(t.Context(), `
INSERT INTO scenario_deceptions (scenario_id, deception_id, language, guide)
SELECT $1, 'filler-' || n, 'en', 'g' FROM generate_series(1, $2::int - 1) AS n`, sc.ID, scenario.MaxDeceptions); err != nil {
			t.Fatal(err)
		}
		personas := [2]map[string]string{domain, {"Domain": "corp.example.com", "Company": "Example Ltd"}}
		ids := [2]string{"ssh", "rdp"}
		race(t, "deceptions", func(i int) error {
			_, err := scenario.AddDeception(t.Context(), d.console, actor, scenario.Addition{ScenarioID: sc.ID, Join: join(t, c, ids[i], personas[i])})
			return err
		}, scenario.ErrTooManyDeceptions)
		if n := count(t, d, `SELECT count(*) FROM scenario_deceptions`); n != scenario.MaxDeceptions {
			t.Errorf("%d deceptions, want %d", n, scenario.MaxDeceptions)
		}
	})
	t.Run("artifacts", func(t *testing.T) {
		t.Parallel()
		d := newTestDB(t)
		actor := createUser(t, d)
		sc := create(t, d, scenario.Spec{Name: "s"})
		if _, err := d.owner.Exec(t.Context(), `
INSERT INTO artifacts (scenario_id, catalog_artifact, file_name, format, content)
SELECT $1, 'filler', 'f', 'text', '\x41' FROM generate_series(1, $2::int - 1)`, sc.ID, artifact.MaxPerScenario); err != nil {
			t.Fatal(err)
		}
		race(t, "artifacts", func(int) error {
			_, err := scenario.AddArtifact(t.Context(), d.console, actor, artifactAddition(t, c, sc.ID, "memo", nil, nil))
			return err
		}, artifact.ErrLimit)
		if n := count(t, d, `SELECT count(*) FROM artifacts WHERE scenario_id = $1`, sc.ID); n != artifact.MaxPerScenario {
			t.Errorf("%d artifacts, want %d", n, artifact.MaxPerScenario)
		}
	})
}
