// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/platform/config"
	"nyktus.org/nyktus/internal/platform/schematest"
)

// days is a whole number of days as a duration.
func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

// expectInvalidParameter fails unless err is an invalid_parameter_value.
func expectInvalidParameter(t *testing.T, what string, err error) {
	t.Helper()
	var pgErr *pgconn.PgError
	// 22023 is invalid_parameter_value.
	if !errors.As(err, &pgErr) || pgErr.Code != "22023" {
		t.Errorf("%s: error = %v, want invalid_parameter_value", what, err)
	}
}

// count returns the result of a query for a number.
func count(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// Entries beyond the retention are deleted, and nothing younger.
func TestDeleteExpiredAuditEntries_RemovesOnlyEntriesBeyondTheRetention(t *testing.T) {
	t.Parallel()

	ownerURL, workerURL := schematest.Worker(t)
	owner := schematest.Open(t, ownerURL)
	const retention = 365
	for action, age := range map[string]time.Duration{
		"user.old":   days(retention) + margin,
		"user.young": days(retention) - margin,
		"user.new":   0,
	} {
		if _, err := owner.Exec(t.Context(), `
INSERT INTO audit_entries (occurred_at, action, outcome, actor_kind, auth_method, changed_fields)
VALUES (clock_timestamp() - $2::interval, $1, 'success', 'system', 'cli', '{}')`, action, age); err != nil {
			t.Fatalf("insert %s: %v", action, err)
		}
	}

	var removed int
	if err := schematest.Open(t, workerURL).QueryRow(t.Context(), "SELECT public.delete_expired_audit_entries($1, 100)", retention).Scan(&removed); err != nil {
		t.Fatalf("delete_expired_audit_entries() error = %v", err)
	}
	if removed != 1 {
		t.Errorf("delete_expired_audit_entries() = %d, want 1", removed)
	}
	if n := count(t, owner, "SELECT count(*) FROM audit_entries WHERE action = 'user.old'"); n != 0 {
		t.Error("the entry beyond the retention remains")
	}
	if n := count(t, owner, "SELECT count(*) FROM audit_entries WHERE action IN ('user.young', 'user.new')"); n != 2 {
		t.Errorf("%d entries within the retention remain, want 2", n)
	}
}

// The limits of the configuration hold in the database as well, so that a
// compromised worker cannot delete recent entries or events.
func TestDeleteExpired_RejectsRetentionsBeyondTheLimits(t *testing.T) {
	t.Parallel()

	_, workerURL := schematest.Worker(t)
	worker := schematest.Open(t, workerURL)
	for _, f := range []struct {
		function string
		lowest   int
	}{
		{"delete_expired_audit_entries", config.MinAuditRetentionDays},
		{"delete_expired_incident_data", config.MinEventRetentionDays},
	} {
		query := "SELECT public." + f.function + "($1, $2)"
		for _, retention := range []int{f.lowest, config.MaxRetentionDays} {
			if _, err := worker.Exec(t.Context(), query, retention, 1); err != nil {
				t.Errorf("%s(%d, 1) error = %v, want nil", f.function, retention, err)
			}
		}
		for _, retention := range []any{f.lowest - 1, config.MaxRetentionDays + 1, nil} {
			_, err := worker.Exec(t.Context(), query, retention, 1)
			expectInvalidParameter(t, fmt.Sprint(f.function, " with a retention of ", retention), err)
		}
		for _, batch := range []any{0, 10001, nil} {
			_, err := worker.Exec(t.Context(), query, config.MaxRetentionDays, batch)
			expectInvalidParameter(t, fmt.Sprint(f.function, " with a batch of ", batch), err)
		}
	}
}

// incidentData places the data of incidents for the tests of their retention,
// as the owner, and returns the identifiers by label.
type incidentData struct {
	owner *pgxpool.Pool
	t     *testing.T
}

// event records an event of resource that was recorded age ago, assigned to
// incident unless it is empty, and with its job if pending.
func (d incidentData) event(resource string, age time.Duration, incident string, pending bool) string {
	d.t.Helper()
	var id string
	err := d.owner.QueryRow(d.t.Context(), `
INSERT INTO events (resource_type, resource_id, honeytoken_type, severity, occurred_at, recorded_at, channel, method, client_ip,
	incident_id)
VALUES ('honeytoken', $1, 'web_url', 'medium', clock_timestamp() - $2::interval, clock_timestamp() - $2::interval, 'http', 'GET',
	'192.0.2.1', nullif($3, '')::uuid)
RETURNING id`, resource, age, incident).Scan(&id)
	if err != nil {
		d.t.Fatalf("insert event: %v", err)
	}
	if pending {
		if _, err := d.owner.Exec(d.t.Context(), "INSERT INTO event_jobs (event_id) VALUES ($1)", id); err != nil {
			d.t.Fatalf("insert job: %v", err)
		}
	}
	return id
}

// incident opens an incident of resource age ago with its alert and one
// delivery, and closes it closedAge ago unless closedAge is negative.
func (d incidentData) incident(resource string, age, closedAge time.Duration) string {
	d.t.Helper()
	var id string
	err := d.owner.QueryRow(d.t.Context(), `
INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at, opened_at, status, closed_at)
VALUES ('honeytoken', $1, 'medium', clock_timestamp() - $2::interval, clock_timestamp() - $2::interval, clock_timestamp() - $2::interval,
	CASE WHEN $3::interval < interval '0' THEN 'open' ELSE 'closed' END,
	CASE WHEN $3::interval < interval '0' THEN NULL ELSE clock_timestamp() - $3::interval END)
RETURNING id`, resource, age, closedAge).Scan(&id)
	if err != nil {
		d.t.Fatalf("insert incident: %v", err)
	}
	if _, err := d.owner.Exec(d.t.Context(), `
WITH alert AS (INSERT INTO alerts (incident_id, severity) VALUES ($1, 'medium') RETURNING incident_id)
INSERT INTO alert_deliveries (alert_id, channel_id, channel_type, channel_name, status, attempts, last_attempt_at, delivered_at)
SELECT incident_id, gen_random_uuid(), 'webhook', 'c', 'delivered', 1, clock_timestamp(), clock_timestamp() FROM alert`, id); err != nil {
		d.t.Fatalf("insert alert: %v", err)
	}
	return id
}

// test requests a test of a channel age ago, delivered unless pending.
func (d incidentData) test(age time.Duration, pending bool) string {
	d.t.Helper()
	var id string
	err := d.owner.QueryRow(d.t.Context(), `
INSERT INTO alert_deliveries (channel_id, channel_type, channel_name, status, attempts, last_attempt_at, delivered_at, created_at)
VALUES (gen_random_uuid(), 'webhook', 'c', CASE WHEN $2 THEN 'pending' ELSE 'delivered' END,
	CASE WHEN $2 THEN 0 ELSE 1 END, CASE WHEN $2 THEN NULL ELSE clock_timestamp() END,
	CASE WHEN $2 THEN NULL ELSE clock_timestamp() END, clock_timestamp() - $1::interval)
RETURNING id`, age, pending).Scan(&id)
	if err != nil {
		d.t.Fatalf("insert test: %v", err)
	}
	return id
}

// Events beyond the retention are deleted unless their job waits, closed
// incidents beyond it go with their alert and deliveries, and so do old tests
// of channels; everything younger, open incidents and waiting tests stay.
func TestDeleteExpiredIncidentData_RemovesOnlyDataBeyondTheRetention(t *testing.T) {
	t.Parallel()

	ownerURL, workerURL := schematest.Worker(t)
	owner := schematest.Open(t, ownerURL)
	d := incidentData{owner: owner, t: t}
	const retention = 180
	beyond, within := days(retention)+margin, days(retention)-margin
	const (
		closedOld   = "00000000-0000-4000-8000-000000000001"
		closedYoung = "00000000-0000-4000-8000-000000000002"
		open        = "00000000-0000-4000-8000-000000000003"
		unprocessed = "00000000-0000-4000-8000-000000000004"
		quietOpen   = "00000000-0000-4000-8000-000000000005"
		quietClosed = "00000000-0000-4000-8000-000000000006"
	)

	// Closed beyond the retention: the incident, its alert, its delivery and
	// its event go.
	oldIncident := d.incident(closedOld, beyond+time.Hour, beyond)
	oldEvent := d.event(closedOld, beyond+time.Hour, oldIncident, false)
	// Closed within the retention: its old event goes, the incident stays.
	youngIncident := d.incident(closedYoung, beyond+time.Hour, within)
	youngIncidentOldEvent := d.event(closedYoung, beyond, youngIncident, false)
	youngIncidentEvent := d.event(closedYoung, within, youngIncident, false)
	// Open for longer than the retention: old events go, the incident and
	// the recent events stay.
	openIncident := d.incident(open, beyond+time.Hour, -1)
	openOldEvent := d.event(open, beyond, openIncident, false)
	openEvent := d.event(open, 0, openIncident, false)
	// Incidents whose events are all beyond the retention stay as long as
	// they are open or closed within it.
	quietOpenIncident := d.incident(quietOpen, beyond+time.Hour, -1)
	d.event(quietOpen, beyond, quietOpenIncident, false)
	quietClosedIncident := d.incident(quietClosed, beyond+time.Hour, within)
	d.event(quietClosed, beyond, quietClosedIncident, false)
	// An old event whose job still waits stays.
	waiting := d.event(unprocessed, beyond, "", true)
	oldTest, youngTest, pendingTest := d.test(beyond, false), d.test(within, false), d.test(beyond, true)

	var removed int
	if err := schematest.Open(t, workerURL).QueryRow(t.Context(), "SELECT public.delete_expired_incident_data($1, 100)", retention).Scan(&removed); err != nil {
		t.Fatalf("delete_expired_incident_data() error = %v", err)
	}
	// Five events, one incident with its alert and delivery, one test.
	if removed != 9 {
		t.Errorf("delete_expired_incident_data() = %d, want 9", removed)
	}

	exists := func(table, column, id string) bool {
		return count(t, owner, "SELECT count(*) FROM "+table+" WHERE "+column+" = $1", id) == 1
	}
	for _, c := range []struct {
		what, table, column, id string
		want                    bool
	}{
		{"old event of a closed incident", "events", "id", oldEvent, false},
		{"incident closed beyond the retention", "incidents", "id", oldIncident, false},
		{"its alert", "alerts", "incident_id", oldIncident, false},
		{"its delivery", "alert_deliveries", "alert_id", oldIncident, false},
		{"old event of a recently closed incident", "events", "id", youngIncidentOldEvent, false},
		{"recent event of a recently closed incident", "events", "id", youngIncidentEvent, true},
		{"incident closed within the retention", "incidents", "id", youngIncident, true},
		{"its alert", "alerts", "incident_id", youngIncident, true},
		{"its delivery", "alert_deliveries", "alert_id", youngIncident, true},
		{"old event of an open incident", "events", "id", openOldEvent, false},
		{"recent event of an open incident", "events", "id", openEvent, true},
		{"open incident", "incidents", "id", openIncident, true},
		{"open incident without recent events", "incidents", "id", quietOpenIncident, true},
		{"incident closed within the retention without recent events", "incidents", "id", quietClosedIncident, true},
		{"old event whose job waits", "events", "id", waiting, true},
		{"old test", "alert_deliveries", "id", oldTest, false},
		{"recent test", "alert_deliveries", "id", youngTest, true},
		{"old test that waits", "alert_deliveries", "id", pendingTest, true},
	} {
		if got := exists(c.table, c.column, c.id); got != c.want {
			t.Errorf("%s: exists = %t, want %t", c.what, got, c.want)
		}
	}
	if n := count(t, owner, "SELECT event_count FROM incidents WHERE id = $1", openIncident); n != 1 {
		t.Errorf("event_count of the open incident = %d, want it unchanged", n)
	}
}

// An incident that a triage holds is skipped instead of waited for, and so is
// an event that another transaction holds, whose incident then stays.
func TestDeleteExpiredIncidentData_SkipsHeldIncidents(t *testing.T) {
	t.Parallel()

	ownerURL, workerURL := schematest.Worker(t)
	owner := schematest.Open(t, ownerURL)
	d := incidentData{owner: owner, t: t}
	beyond := days(config.MinEventRetentionDays) + margin
	held := d.incident("00000000-0000-4000-8000-000000000001", beyond, beyond)
	withEvent := d.incident("00000000-0000-4000-8000-000000000002", beyond, beyond)
	event := d.event("00000000-0000-4000-8000-000000000002", beyond, withEvent, false)

	tx, err := owner.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(t.Context()) })
	// As a triage locks an incident, and as something reading an event would.
	if _, err := tx.Exec(t.Context(), "SELECT FROM incidents WHERE id = $1 FOR NO KEY UPDATE", held); err != nil {
		t.Fatalf("lock incident: %v", err)
	}
	if _, err := tx.Exec(t.Context(), "SELECT FROM events WHERE id = $1 FOR UPDATE", event); err != nil {
		t.Fatalf("lock event: %v", err)
	}

	worker := schematest.Open(t, workerURL)
	var removed int
	// A wait would end on the lock timeout of the function with an error.
	if err := worker.QueryRow(t.Context(), "SELECT public.delete_expired_incident_data($1, 100)", config.MinEventRetentionDays).Scan(&removed); err != nil {
		t.Fatalf("delete_expired_incident_data() error = %v", err)
	}
	if removed != 0 {
		t.Errorf("delete_expired_incident_data() while both are held = %d, want 0", removed)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if err := worker.QueryRow(t.Context(), "SELECT public.delete_expired_incident_data($1, 100)", config.MinEventRetentionDays).Scan(&removed); err != nil {
		t.Fatalf("delete_expired_incident_data() error = %v", err)
	}
	// The event, then both incidents with their alerts and deliveries.
	if removed != 7 {
		t.Errorf("delete_expired_incident_data() after the release = %d, want 7", removed)
	}
}

// The functions find expired rows and quiet incidents by seeking into an index, also with the
// generic plan that PostgreSQL may choose for the statements of a function
// after a few calls, instead of reading every row that is still kept. The test
// counts the entries that each index returned: a seek returns those beyond the
// cutoff, a scan of the whole index every entry.
func TestDeleteExpired_SeeksIntoTheIndexesInTheGenericPlan(t *testing.T) {
	t.Parallel()

	ownerURL, _ := schematest.Worker(t)
	owner := schematest.Open(t, ownerURL)
	const kept = 200
	beyond := days(config.MaxRetentionDays) + margin
	if _, err := owner.Exec(t.Context(), `
INSERT INTO audit_entries (occurred_at, action, outcome, actor_kind, auth_method, changed_fields)
SELECT clock_timestamp() - CASE WHEN i = 0 THEN $1::interval ELSE interval '0' END, 'user.create', 'success', 'system', 'cli', '{}'
FROM generate_series(0, $2::int) AS i`, beyond, kept); err != nil {
		t.Fatalf("insert audit entries: %v", err)
	}
	if _, err := owner.Exec(t.Context(), `
INSERT INTO events (resource_type, resource_id, honeytoken_type, severity, occurred_at, recorded_at, channel, method)
SELECT 'honeytoken', gen_random_uuid(), 'web_url', 'medium', t, t, 'http', 'GET'
FROM generate_series(0, $2::int) AS i, LATERAL (SELECT clock_timestamp() - CASE WHEN i = 0 THEN $1::interval ELSE interval '0' END) AS c (t)`,
		beyond, kept); err != nil {
		t.Fatalf("insert events: %v", err)
	}
	if _, err := owner.Exec(t.Context(), `
INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at, opened_at, status, closed_at)
SELECT 'honeytoken', gen_random_uuid(), 'low', t, t, t, 'closed', t
FROM generate_series(0, $2::int) AS i, LATERAL (SELECT clock_timestamp() - CASE WHEN i = 0 THEN $1::interval ELSE interval '0' END) AS c (t)`,
		beyond, kept); err != nil {
		t.Fatalf("insert incidents: %v", err)
	}
	if _, err := owner.Exec(t.Context(), `
INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at, opened_at)
SELECT 'honeytoken', gen_random_uuid(), 'low', t, t, t
FROM generate_series(0, $2::int) AS i,
	LATERAL (SELECT clock_timestamp() - CASE WHEN i = 0 THEN $1::interval ELSE interval '0' END) AS c (t)`,
		days(config.MaxAutoCloseDays)+margin, kept); err != nil {
		t.Fatalf("insert open incidents: %v", err)
	}
	if _, err := owner.Exec(t.Context(), `
INSERT INTO alert_deliveries (channel_id, channel_type, channel_name, status, attempts, last_attempt_at, delivered_at, created_at)
SELECT gen_random_uuid(), 'webhook', 'c', 'delivered', 1, clock_timestamp(), clock_timestamp(),
	clock_timestamp() - CASE WHEN i = 0 THEN $1::interval ELSE interval '0' END
FROM generate_series(0, $2::int) AS i`, beyond, kept); err != nil {
		t.Fatalf("insert tests: %v", err)
	}

	// A connection of its own, closed afterwards: the settings below must not
	// reach a connection that other queries reuse.
	conn, err := pgx.Connect(t.Context(), ownerURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(t.Context())) }()
	indexes := []string{
		"audit_entries_occurred_at_id_idx", "events_recorded_at_id_idx", "incidents_closed_at_idx", "alert_deliveries_test_created_at_idx",
		"incidents_open_last_event_at_idx",
	}
	read := func() map[string]int64 {
		t.Helper()
		if _, err := conn.Exec(t.Context(), "SELECT pg_stat_force_next_flush(), pg_stat_clear_snapshot()"); err != nil {
			t.Fatalf("flush statistics: %v", err)
		}
		rows, err := conn.Query(t.Context(), "SELECT indexrelname::text, idx_tup_read FROM pg_stat_user_indexes WHERE indexrelname = ANY ($1)", indexes)
		if err != nil {
			t.Fatalf("read statistics: %v", err)
		}
		tuples := map[string]int64{}
		for rows.Next() {
			var name string
			var n int64
			if err := rows.Scan(&name, &n); err != nil {
				t.Fatalf("read statistics: %v", err)
			}
			tuples[name] = n
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("read statistics: %v", err)
		}
		return tuples
	}
	for _, statement := range []string{
		"SET plan_cache_mode = force_generic_plan",
		// The test tables are tiny; without this, a sequential scan would win.
		"SET enable_seqscan = off",
	} {
		if _, err := conn.Exec(t.Context(), statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	before := read()
	for call, retention := range map[string]int{
		"SELECT public.delete_expired_audit_entries($1, 1000)": config.MaxRetentionDays,
		"SELECT public.delete_expired_incident_data($1, 1000)": config.MaxRetentionDays,
		"SELECT public.close_inactive_incidents($1, 1000)":     config.MaxAutoCloseDays,
	} {
		if _, err := conn.Exec(t.Context(), call, retention); err != nil {
			t.Fatalf("%s: %v", call, err)
		}
	}
	after := read()
	for _, index := range indexes {
		if n := after[index] - before[index]; n < 1 || n > 10 {
			t.Errorf("%s returned %d entries, want the one beyond the cutoff, not all %d", index, n, kept+1)
		}
	}
}
