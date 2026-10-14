// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package incident

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/platform/schematest"
)

// The statements of the lists seek into their index, also in the generic plan
// that PostgreSQL may switch to after a few executions.
func TestLists_UseTheirIndex(t *testing.T) {
	t.Parallel()
	ownerURL := schematest.New(t)
	pool := schematest.Open(t, ownerURL)

	tests := []struct {
		name, types, statement, index, cond string
	}{
		{"incidents", "text[], int", listIncidentsNewest, "incidents_opened_at_id_idx", ""},
		{"incidents after", "text[], timestamptz, uuid, int", listIncidentsAfter, "incidents_opened_at_id_idx", "Index Cond: (ROW(opened_at, id) < ROW($2, $3))"},
		{"incidents of a resource", "text[], uuid, int", listResourceIncidentsNewest, "incidents_resource_id_opened_at_id_idx", "Index Cond: (resource_id = $2)"},
		{"incidents of a resource after", "text[], uuid, timestamptz, uuid, int", listResourceIncidentsAfter, "incidents_resource_id_opened_at_id_idx", "Index Cond: ((resource_id = $2) AND (ROW(opened_at, id) < ROW($3, $4)))"},
		{"events", "int", listEventsNewest, "events_occurred_at_id_idx", ""},
		{"events after", "timestamptz, uuid, int", listEventsAfter, "events_occurred_at_id_idx", "Index Cond: (ROW(occurred_at, id) < ROW($1, $2))"},
		{"events of an incident", "uuid, int", listIncidentEventsNewest, "events_incident_id_occurred_at_id_idx", "Index Cond: (incident_id = $1)"},
		{"events of an incident after", "uuid, timestamptz, uuid, int", listIncidentEventsAfter, "events_incident_id_occurred_at_id_idx", "Index Cond: ((incident_id = $1) AND (ROW(occurred_at, id) < ROW($2, $3)))"},
	}
	conn, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	for _, statement := range []string{"SET plan_cache_mode = force_generic_plan", "SET enable_seqscan = off"} {
		if _, err := conn.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	for i, tt := range tests {
		name := "list" + string(rune('a'+i))
		if _, err := conn.Exec(t.Context(), "PREPARE "+name+" ("+tt.types+") AS "+tt.statement); err != nil {
			t.Fatalf("%s: prepare: %v", tt.name, err)
		}
		args := make([]string, len(strings.Split(tt.types, ",")))
		for j, typ := range strings.Split(tt.types, ",") {
			switch strings.TrimSpace(typ) {
			case "text[]":
				args[j] = "'{open}'"
			case "timestamptz":
				args[j] = "now()"
			case "uuid":
				args[j] = "'00000000-0000-4000-8000-000000000000'"
			case "int":
				args[j] = "10"
			}
		}
		rows, err := conn.Query(t.Context(), "EXPLAIN EXECUTE "+name+" ("+strings.Join(args, ", ")+")")
		if err != nil {
			t.Fatalf("%s: explain: %v", tt.name, err)
		}
		plan, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatalf("%s: explain: %v", tt.name, err)
		}
		text := strings.Join(plan, "\n")
		if !strings.Contains(text, "Index Scan using "+tt.index) || !strings.Contains(text, tt.cond) {
			t.Errorf("%s: plan does not use %s with %q:\n%s", tt.name, tt.index, tt.cond, text)
		}
	}
}

// triageFixture is a migrated database with an open incident, a pool of the
// owner and one of the console.
func triageFixture(t *testing.T) (owner, console *pgxpool.Pool, id string, actor audit.Actor) {
	t.Helper()
	ownerURL, consoleURL := schematest.Console(t)
	owner = schematest.Open(t, ownerURL)
	var userID string
	err := owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status) VALUES ('u@example.com', 'U', 'user', 'pending') RETURNING id`).Scan(&userID)
	if err != nil {
		t.Fatal(err)
	}
	err = owner.QueryRow(t.Context(), `
INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at)
VALUES ('honeytoken', gen_random_uuid(), 'medium', now(), now()) RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return owner, schematest.Open(t, consoleURL), id, audit.Actor{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: userID}
}

// The triage compares the change with the incident as it is once locked, so
// that a concurrent change cannot make it record a field that it did not
// change. The other transaction writes the same notes first.
func TestTriage_ComparesWithTheLockedIncident(t *testing.T) {
	t.Parallel()
	owner, console, id, actor := triageFixture(t)

	tx, err := owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), "UPDATE incidents SET notes = 'backup job' WHERE id = $1", id); err != nil {
		t.Fatal(err)
	}

	notes := "backup job"
	done := make(chan error, 1)
	go func() {
		_, err := Triage(t.Context(), console, actor, id, Change{Notes: &notes})
		done <- err
	}()
	waitForLockWaiter(t, owner, done)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Triage() error = %v", err)
	}
	var entries int
	if err := owner.QueryRow(t.Context(), "SELECT count(*) FROM audit_entries WHERE action = 'incident.update'").Scan(&entries); err != nil {
		t.Fatal(err)
	}
	if entries != 0 {
		t.Errorf("%d changes recorded, want none: the notes were already set", entries)
	}
}

// A triage that waits for an incident that is closed meanwhile does not open
// it again.
func TestTriage_DoesNotReopenAnIncidentClosedMeanwhile(t *testing.T) {
	t.Parallel()
	owner, console, id, actor := triageFixture(t)

	tx, err := owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), "UPDATE incidents SET status = 'closed' WHERE id = $1", id); err != nil {
		t.Fatal(err)
	}

	acknowledged := StatusAcknowledged
	done := make(chan error, 1)
	go func() {
		_, err := Triage(t.Context(), console, actor, id, Change{Status: &acknowledged})
		done <- err
	}()
	waitForLockWaiter(t, owner, done)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrStatusBackward) {
		t.Errorf("Triage() error = %v, want ErrStatusBackward", err)
	}
	if i, err := GetIncident(t.Context(), console, id); err != nil || i.Status != StatusClosed {
		t.Errorf("incident = %+v, %v; want it closed", i, err)
	}
}

// The schema checks what the triage writes: a status moving back fails also
// without the comparison of the triage, and the times of the status come from
// the database.
func TestTriage_ConsoleCannotChooseTheTimesOfTheStatus(t *testing.T) {
	t.Parallel()
	_, console, id, actor := triageFixture(t)

	closed := StatusClosed
	before := time.Now()
	i, err := Triage(t.Context(), console, actor, id, Change{Status: &closed})
	if err != nil || i.ClosedAt == nil || i.ClosedAt.Before(before.Add(-time.Minute)) || i.AcknowledgedAt != nil {
		t.Fatalf("Triage() = %+v, %v; want closed now, never acknowledged", i, err)
	}
	if _, err := console.Exec(t.Context(), "UPDATE incidents SET status = 'open' WHERE id = $1", id); constraintName(err) != "incidents_status_forward" {
		t.Errorf("reopening through the console role: error = %v, want incidents_status_forward", err)
	}
}

func constraintName(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}
