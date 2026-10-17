// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenario

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
	other := &pgconn.PgError{Code: db.CheckViolation, ConstraintName: "scenarios_updated_at_check"}
	if got := mapWriteError(other); !errors.Is(got, other) {
		t.Errorf("mapWriteError(other check) = %v, want it unchanged", got)
	}
}

// A page after a cursor must seek into the index instead of reading every
// newer scenario, also with the generic plan that PostgreSQL may choose for a
// prepared statement after a few executions.
func TestList_CursorIsAnIndexConditionInTheGenericPlan(t *testing.T) {
	t.Parallel()

	ownerURL, _ := schematest.Console(t)
	// A connection of its own, closed afterwards: the settings and the prepared
	// statement below must not reach a connection that other queries reuse.
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
	} {
		if _, err := conn.Exec(t.Context(), statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	rows, err := conn.Query(t.Context(), `EXPLAIN EXECUTE list_after('2026-10-10T12:00:00Z', '00000000-0000-4000-8000-000000000000', 51)`)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	plan, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}
	text := strings.Join(plan, "\n")
	if !strings.Contains(text, "scenarios_created_at_id_idx") || !strings.Contains(text, "Index Cond: (ROW(created_at, id) < ROW(") {
		t.Errorf("generic plan does not seek into the index with the cursor:\n%s", text)
	}
}
