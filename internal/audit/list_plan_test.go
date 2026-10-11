// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/platform/schematest"
)

// A page after a cursor must seek into the index instead of reading every newer
// entry, also with the generic plan that PostgreSQL may choose for a prepared
// statement after a few executions. Otherwise each page would cost as much as
// all pages before it.
func TestList_CursorIsAnIndexConditionInTheGenericPlan(t *testing.T) {
	t.Parallel()

	text := genericPlan(t, "list_after", listAfter,
		"EXECUTE list_after('2026-10-10T12:00:00Z', '00000000-0000-4000-8000-000000000000', 51)")
	if !strings.Contains(text, "audit_entries_occurred_at_id_idx") || !strings.Contains(text, "Index Cond: (ROW(occurred_at, id) < ROW(") {
		t.Errorf("generic plan does not seek into the index with the cursor:\n%s", text)
	}
}

// The check for a recent entry of the same kind must seek into the index by
// time, also with the generic plan, instead of reading every entry the actor
// ever caused: an integration that polls the audit log adds one every minute.
func TestRecordUnlessRepeated_WindowIsAnIndexConditionInTheGenericPlan(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name, query, index, args string
	}{
		{"user", insertUnlessRepeatedByUser, "audit_entries_actor_user_id_idx", "'user', 'session', '00000000-0000-4000-8000-000000000000', NULL"},
		{"key", insertUnlessRepeatedByKey, "audit_entries_api_key_id_idx", "'api_key', 'api_key', NULL, '00000000-0000-4000-8000-000000000000'"},
	} {
		text := genericPlan(t, "insert_unless_repeated", tt.query, `
EXECUTE insert_unless_repeated('audit.read', 'success', `+tt.args+`, NULL, NULL, '{}', NULL, NULL, '1 minute')`)
		var seeks bool
		for line := range strings.SplitSeq(text, "\n") {
			line = strings.TrimSpace(line)
			seeks = seeks || (strings.HasPrefix(line, "Index Cond: ") && strings.Contains(line, "(occurred_at > (statement_timestamp() - "))
		}
		if !strings.Contains(text, tt.index) || !seeks {
			t.Errorf("%s: generic plan does not seek into the index by time:\n%s", tt.name, text)
		}
	}
}

// genericPlan prepares query as name and returns the generic plan of explain,
// an EXECUTE of it.
func genericPlan(t *testing.T, name, query, explain string) string {
	t.Helper()
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
		"PREPARE " + name + " AS " + query,
	} {
		if _, err := conn.Exec(t.Context(), statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	rows, err := conn.Query(t.Context(), "EXPLAIN "+explain)
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
	return strings.Join(plan, "\n")
}
