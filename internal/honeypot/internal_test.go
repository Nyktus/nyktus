// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeypot

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
)

// The store validates every field before it writes, so the checks of the
// schema only fire if both rules ever differ. The mapping still turns them
// into the errors of the validation, also when they are wrapped.
func TestMapWriteError_MapsTheChecksOfTheSchema(t *testing.T) {
	t.Parallel()

	for constraint, want := range constraintErrors {
		err := fmt.Errorf("insert: %w", &pgconn.PgError{Code: db.CheckViolation, ConstraintName: constraint})
		if got := mapWriteError(err); !errors.Is(got, want) {
			t.Errorf("mapWriteError(%s) = %v, want %v", constraint, got, want)
		}
	}
	missing := fmt.Errorf("insert: %w", &pgconn.PgError{Code: db.ForeignKeyViolation, ConstraintName: "honeypots_scenario_id_fkey"})
	if got := mapWriteError(missing); !errors.Is(got, ErrScenarioNotFound) {
		t.Errorf("mapWriteError(scenario key) = %v, want ErrScenarioNotFound", got)
	}
	otherKey := &pgconn.PgError{Code: db.ForeignKeyViolation, ConstraintName: "honeypots_other_fkey"}
	if got := mapWriteError(otherKey); !errors.Is(got, otherKey) {
		t.Errorf("mapWriteError(other key) = %v, want it unchanged", got)
	}
	other := &pgconn.PgError{Code: db.CheckViolation, ConstraintName: "honeypots_updated_at_check"}
	if got := mapWriteError(other); !errors.Is(got, other) {
		t.Errorf("mapWriteError(other check) = %v, want it unchanged", got)
	}
}

// A page after a cursor must seek into the index instead of reading every newer
// honeypot, also with the generic plan that PostgreSQL may choose for a
// prepared statement after a few executions, and also with the filters, which
// are always part of the statement. The list of a scenario seeks into the
// index of its scenario with the cursor.
func TestList_CursorIsAnIndexConditionInTheGenericPlan(t *testing.T) {
	t.Parallel()

	ownerURL, _ := schematest.Console(t)
	// A connection of its own, closed afterwards: the settings and the prepared
	// statements below must not reach a connection that other queries reuse.
	conn, err := pgx.Connect(t.Context(), ownerURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(t.Context())) }()

	for _, statement := range []string{
		"SET plan_cache_mode = force_generic_plan",
		// The test table is tiny; without this, a sequential scan would win.
		"SET enable_seqscan = off",
		"PREPARE list_after AS " + listAfter,
		"PREPARE list_scenario_after AS " + listScenarioAfter,
	} {
		if _, err := conn.Exec(t.Context(), statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	const cursor = `'2026-10-10T12:00:00Z', '00000000-0000-4000-8000-000000000000'`
	for _, tt := range []struct {
		explain, index, cond string
	}{
		{
			"EXPLAIN EXECUTE list_after('{ssh}', '{true}', " + cursor + ", 51)",
			"honeypots_created_at_id_idx", "Index Cond: (ROW(created_at, id) < ROW(",
		},
		{
			"EXPLAIN EXECUTE list_scenario_after('{ssh}', '{true}', '00000000-0000-4000-8000-000000000001', " + cursor + ", 51)",
			"honeypots_scenario_id_created_at_id_idx", "Index Cond: ((scenario_id = $3) AND (ROW(created_at, id) < ROW(",
		},
	} {
		rows, err := conn.Query(t.Context(), tt.explain)
		if err != nil {
			t.Fatalf("explain: %v", err)
		}
		plan, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatalf("read plan: %v", err)
		}
		text := strings.Join(plan, "\n")
		if !strings.Contains(text, tt.index) || !strings.Contains(text, tt.cond) {
			t.Errorf("generic plan does not seek into %s with %q:\n%s", tt.index, tt.cond, text)
		}
	}
}

// A sealed secret that opens, with the associated data of its own honeypot, to
// a value other than the one its hash was made from is not handed out: the
// trigger would not find the honeypot by it.
func TestStore_Secret_RefusesASecretThatDoesNotMatchItsHash(t *testing.T) {
	t.Parallel()

	ownerURL, consoleURL := schematest.Console(t)
	owner, console := schematest.Open(t, ownerURL), schematest.Open(t, consoleURL)
	keys := secretboxtest.Keyring(t)
	store := NewStore(console, keys)

	c, err := store.Create(t.Context(), Spec{Service: ServiceSSH, Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	var hash []byte
	if err := owner.QueryRow(t.Context(), `SELECT secret_hash FROM honeypots WHERE id = $1`, c.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	forged, err := keys.Seal([]byte("another secret that its hash was not made from"), secretData(hash))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(t.Context(), `UPDATE honeypots SET secret_sealed = $2 WHERE id = $1`, c.ID, forged); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Secret(t.Context(), c.ID); !errors.Is(err, ErrSecretUnreadable) || got.Secret != "" {
		t.Errorf("Secret() = %q, %v; want ErrSecretUnreadable and no secret", string(got.Secret), err)
	}
}
