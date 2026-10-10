// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/platform/schematest"
)

// A page after a cursor must seek into the index instead of reading every newer
// entry, also with the generic plan that PostgreSQL may choose for a prepared
// statement after a few executions. Otherwise each page would cost as much as
// all pages before it.
func TestList_CursorIsAnIndexConditionInTheGenericPlan(t *testing.T) {
	t.Parallel()

	ownerURL, _ := schematest.Console(t)
	pool := schematest.Open(t, ownerURL)
	conn, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()

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
	rows, err := conn.Query(t.Context(), "EXPLAIN EXECUTE list_after('2026-10-10T12:00:00Z', '00000000-0000-4000-8000-000000000000', 51)")
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	var plan []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("read plan: %v", err)
		}
		plan = append(plan, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read plan: %v", err)
	}
	text := strings.Join(plan, "\n")
	if !strings.Contains(text, "audit_entries_occurred_at_id_idx") || !strings.Contains(text, "Index Cond: (ROW(occurred_at, id) < ROW(") {
		t.Errorf("generic plan does not seek into the index with the cursor:\n%s", text)
	}
}
