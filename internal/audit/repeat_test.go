// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

import (
	"testing"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/platform/schematest"
)

func TestRecordUnlessRepeated_RecordsOncePerUserActionOutcomeAndWindow(t *testing.T) {
	t.Parallel()

	ownerURL, consoleURL := schematest.Console(t)
	pool := schematest.Open(t, consoleURL)
	owner := schematest.Open(t, ownerURL)
	s := audit.NewStore(pool)
	ada := createUser(t, pool, "ada@example.com", "Ada")
	eve := createUser(t, pool, "eve@example.com", "Eve")
	entry := func(userID string, action audit.Action, outcome audit.Outcome) audit.Entry {
		return audit.Entry{
			Action:  action,
			Outcome: outcome,
			Actor:   audit.Actor{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: userID},
		}.WithRequest(t.Context())
	}
	record := func(e audit.Entry) {
		t.Helper()
		if err := s.RecordUnlessRepeated(t.Context(), e); err != nil {
			t.Fatalf("RecordUnlessRepeated() error = %v", err)
		}
	}
	count := func() int {
		t.Helper()
		var n int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_entries`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	for range 5 {
		record(entry(ada, audit.ActionAuditRead, audit.OutcomeDenied))
	}
	if n := count(); n != 1 {
		t.Fatalf("%d entries after five repeats, want 1", n)
	}

	record(entry(ada, audit.ActionAuditRead, audit.OutcomeSuccess))
	record(entry(ada, audit.ActionSessionDelete, audit.OutcomeDenied))
	record(entry(eve, audit.ActionAuditRead, audit.OutcomeDenied))
	if n := count(); n != 4 {
		t.Errorf("%d entries, want 4: other outcome, other action and other user are each recorded", n)
	}
	// Record appends regardless of earlier entries.
	if err := s.Record(t.Context(), entry(ada, audit.ActionAuditRead, audit.OutcomeDenied)); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if n := count(); n != 5 {
		t.Errorf("%d entries after Record, want 5", n)
	}

	if _, err := owner.Exec(t.Context(), `UPDATE audit_entries SET occurred_at = occurred_at - interval '61 seconds'`); err != nil {
		t.Fatalf("age entries: %v", err)
	}
	record(entry(ada, audit.ActionAuditRead, audit.OutcomeDenied))
	if n := count(); n != 6 {
		t.Errorf("%d entries after the window, want 6", n)
	}

	// Each API key is recorded on its own, apart from the users.
	keyA := createKey(t, owner, "SIEM export")
	keyB := createKey(t, owner, "Backup")
	keyEntry := func(keyID string) audit.Entry {
		return audit.Entry{
			Action:  audit.ActionAuditRead,
			Outcome: audit.OutcomeDenied,
			Actor:   audit.Actor{Kind: audit.ActorAPIKey, Method: audit.AuthAPIKey, APIKeyID: keyID},
		}.WithRequest(t.Context())
	}
	record(keyEntry(keyA))
	record(keyEntry(keyA))
	record(keyEntry(keyB))
	record(entry(ada, audit.ActionAuditRead, audit.OutcomeDenied))
	if n := count(); n != 8 {
		t.Errorf("%d entries after requests through two keys, want 8", n)
	}
}

func TestRecordUnlessRepeated_RequiresAUser(t *testing.T) {
	t.Parallel()

	s, _ := newStore(t)
	if err := s.RecordUnlessRepeated(t.Context(), systemEntry()); err == nil {
		t.Error("RecordUnlessRepeated() without a user actor succeeded")
	}
}
