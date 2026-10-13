// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/schematest"
)

// workerGrants lists every privilege of the worker's group role, as
// heldPrivileges reports them, in byte order.
var workerGrants = []string{
	"alerts.incident_id: INSERT",
	"alerts.severity: INSERT",
	"alerts.techniques: INSERT",
	"attack_technique_ids_valid(text[]): EXECUTE",
	"event_jobs.attempts: UPDATE",
	"event_jobs.not_before: UPDATE",
	"event_jobs: DELETE",
	"event_jobs: SELECT",
	"events.incident_id: UPDATE",
	"events: SELECT",
	"incidents.event_count: UPDATE",
	"incidents.first_event_at: INSERT",
	"incidents.first_event_at: UPDATE",
	"incidents.last_event_at: INSERT",
	"incidents.last_event_at: UPDATE",
	"incidents.resource_id: INSERT",
	"incidents.resource_type: INSERT",
	"incidents.severity: INSERT",
	"incidents.severity: UPDATE",
	"incidents.techniques: INSERT",
	"incidents.techniques: UPDATE",
	"incidents: SELECT",
	"schema public: USAGE",
}

// heldPrivileges reports every privilege of a group role on the schema and its
// objects: privileges on a whole table, privileges on a column that the role
// does not hold on its whole table, on sequences and on functions.
func heldPrivileges(t *testing.T, dbURL, role string) []string {
	t.Helper()
	rows, err := schematest.Open(t, dbURL).Query(t.Context(), `
SELECT c.relname || ': ' || p.privilege
FROM pg_class AS c
CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p (privilege)
WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
	AND has_table_privilege($1, c.oid, p.privilege)
UNION ALL
SELECT c.relname || '.' || a.attname || ': ' || p.privilege
FROM pg_class AS c
JOIN pg_attribute AS a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS p (privilege)
WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
	AND has_column_privilege($1, c.oid, a.attnum, p.privilege)
	AND NOT has_table_privilege($1, c.oid, p.privilege)
UNION ALL
SELECT c.relname || ': USAGE, SELECT, UPDATE'
FROM pg_class AS c
WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'S'
	AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege($1, c.oid, 'USAGE, SELECT, UPDATE') END
UNION ALL
SELECT f.oid::regprocedure::text || ': EXECUTE'
FROM pg_proc AS f
WHERE f.pronamespace = 'public'::regnamespace AND has_function_privilege($1, f.oid, 'EXECUTE')
UNION ALL
SELECT 'schema public: ' || p.privilege
FROM unnest(ARRAY['USAGE', 'CREATE']) AS p (privilege)
WHERE has_schema_privilege($1, 'public', p.privilege)
`, role)
	if err != nil {
		t.Fatalf("query privileges: %v", err)
	}
	held, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("query privileges: %v", err)
	}
	slices.Sort(held)
	return held
}

func TestWorkerRole_PassesLeastPrivilegeCheck(t *testing.T) {
	t.Parallel()

	_, workerURL := schematest.Worker(t)
	if err := db.CheckLeastPrivilege(t.Context(), schematest.Open(t, workerURL)); err != nil {
		t.Errorf("CheckLeastPrivilege() error = %v, want nil", err)
	}
}

func TestWorkerRole_HoldsExactlyItsGrants(t *testing.T) {
	t.Parallel()

	if held := heldPrivileges(t, schematest.New(t), schematest.WorkerRole); !slices.Equal(held, workerGrants) {
		t.Errorf("nyktus_worker holds\n%s\nwant\n%s", strings.Join(held, "\n"), strings.Join(workerGrants, "\n"))
	}
}

// The worker reads events and writes incidents, but whoever takes over its host
// must not reach the inventory, the accounts or the audit log, nor rewrite
// evidence: events, closed incidents and alerts.
func TestWorkerRole_HasOnlyGrantedPrivileges(t *testing.T) {
	t.Parallel()

	ownerURL, workerURL := schematest.Worker(t)
	dbtest.Exec(t, ownerURL,
		"INSERT INTO honeytokens (type, name, trigger_value) VALUES ('web_url', 'h', repeat('a', 26))",
		"SELECT * FROM record_honeytoken_request(repeat('a', 26), 'GET', NULL, '', '', '')",
	)
	pool := schematest.Open(t, workerURL)

	allowed := []string{
		"SELECT count(*) FROM event_jobs",
		"UPDATE event_jobs SET attempts = attempts + 1, not_before = clock_timestamp()",
		"SELECT count(*) FROM events",
		"INSERT INTO incidents (resource_type, resource_id, severity, techniques, first_event_at, last_event_at) SELECT resource_type, resource_id, 'medium', techniques, occurred_at, occurred_at FROM events",
		"UPDATE incidents SET severity = 'high', techniques = '{T1078}', event_count = 2, first_event_at = first_event_at, last_event_at = last_event_at",
		"SELECT count(*) FROM incidents",
		"UPDATE events SET incident_id = (SELECT id FROM incidents)",
		"INSERT INTO alerts (incident_id, severity, techniques) SELECT id, severity, techniques FROM incidents",
		"SELECT public.attack_technique_ids_valid('{T1078}')",
		"DELETE FROM event_jobs",
	}
	for _, statement := range allowed {
		if _, err := pool.Exec(t.Context(), statement); err != nil {
			t.Errorf("%s: error = %v, want nil", statement, err)
		}
	}

	denied := []string{
		"SELECT * FROM schema_migrations",
		"CREATE TABLE extra (id int)",
		"SELECT count(*) FROM honeytokens",
		"SELECT count(*) FROM users",
		"SELECT count(*) FROM api_keys",
		"SELECT count(*) FROM sessions",
		"SELECT count(*) FROM audit_entries",
		"INSERT INTO event_jobs (event_id) SELECT id FROM events",
		"UPDATE event_jobs SET created_at = now()",
		"TRUNCATE event_jobs",
		"INSERT INTO events (resource_type, resource_id, honeytoken_type, occurred_at, recorded_at, channel, method) VALUES ('honeytoken', gen_random_uuid(), 'web_url', now(), now(), 'http', 'GET')",
		"UPDATE events SET techniques = '{}'",
		"UPDATE events SET client_ip = NULL",
		"DELETE FROM events",
		"INSERT INTO incidents (id, resource_type, resource_id, severity, first_event_at, last_event_at) VALUES (gen_random_uuid(), 'honeytoken', gen_random_uuid(), 'low', now(), now())",
		"INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at, status, closed_at) VALUES ('honeytoken', gen_random_uuid(), 'low', now(), now(), 'closed', now())",
		"INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at, opened_at) VALUES ('honeytoken', gen_random_uuid(), 'low', now(), now(), now())",
		"UPDATE incidents SET status = 'closed', closed_at = now()",
		"UPDATE incidents SET notes = 'n'",
		"UPDATE incidents SET severity_override = 'info'",
		"UPDATE incidents SET techniques_override = '{}'",
		"UPDATE incidents SET resource_id = gen_random_uuid()",
		"DELETE FROM incidents",
		"TRUNCATE incidents",
		"INSERT INTO alerts (incident_id, severity, created_at) SELECT id, severity, now() FROM incidents",
		"UPDATE alerts SET severity = 'low'",
		"SELECT count(*) FROM alerts",
		"DELETE FROM alerts",
		"SELECT * FROM public.record_honeytoken_request(repeat('a', 26), 'GET', NULL, '', '', '')",
		"SELECT * FROM public.record_dns_query(repeat('a', 26), 'd.example.com', '', 'A', 'udp', NULL, interval '0')",
		"SELECT public.honeytoken_event_limit_reached(gen_random_uuid())",
		"SELECT public.audit_field_names_valid('{name}')",
		"SELECT public.set_updated_at()",
		"SELECT public.incidents_keep_status_forward()",
	}
	for _, statement := range denied {
		expectDenied(t, pool, statement)
	}
}

// Default privileges that an operator set for the owner also apply when they
// name the worker's group role. The migration must remove them, including on the
// table of the migration runner, which exists before the migration runs.
func TestApply_IgnoresDefaultPrivilegesOfTheWorker(t *testing.T) {
	t.Parallel()

	dbURL := dbtest.New(t)
	schematest.GroupRoles(t)
	worker := pgx.Identifier{schematest.WorkerRole}.Sanitize()
	dbtest.Exec(t, dbURL,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "+worker,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO "+worker,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO "+worker,
	)
	if err := apply(t, dbURL, load(t)); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if held := heldPrivileges(t, dbURL, schematest.WorkerRole); !slices.Equal(held, workerGrants) {
		t.Errorf("nyktus_worker holds\n%s\nwant\n%s", strings.Join(held, "\n"), strings.Join(workerGrants, "\n"))
	}
}

// The migration verifies the privileges of the worker in both directions, so a
// grant that is missing or wider than intended stops it.
func TestApply_VerifiesThePrivilegesOfTheWorker(t *testing.T) {
	t.Parallel()

	const grant = "GRANT UPDATE (incident_id) ON public.events TO nyktus_worker;"
	tests := []struct {
		name, replacement, want string
	}{
		{name: "missing", replacement: "", want: "nyktus_worker lacks privileges (events.incident_id: UPDATE)"},
		{name: "wider", replacement: "GRANT UPDATE ON public.events TO nyktus_worker;", want: "nyktus_worker has more privileges than granted (events: UPDATE, events.accept_language: UPDATE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			all := load(t)
			found := false
			for i := range all {
				if strings.Contains(all[i].SQL, grant) {
					all[i].SQL = strings.Replace(all[i].SQL, grant, tt.replacement, 1)
					found = true
				}
			}
			if !found {
				t.Fatalf("the migrations do not contain %q", grant)
			}
			dbURL := dbtest.New(t)
			schematest.GroupRoles(t)
			if err := apply(t, dbURL, all); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Apply() error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

// incidentSchema is a migrated database with one honeytoken that has an event,
// connected as the owner, for tests of the constraints of incidents.
func incidentSchema(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ownerURL := schematest.New(t)
	dbtest.Exec(t, ownerURL,
		"INSERT INTO honeytokens (type, name, trigger_value) VALUES ('web_url', 'h', repeat('a', 26))",
		"SELECT * FROM record_honeytoken_request(repeat('a', 26), 'GET', NULL, '', '', '')",
	)
	return schematest.Open(t, ownerURL)
}

// insertIncident opens an incident for resource with status and returns its
// identifier.
func insertIncident(t *testing.T, pool *pgxpool.Pool, resource, status string) (string, error) {
	t.Helper()
	var id string
	err := pool.QueryRow(t.Context(), `
INSERT INTO incidents (resource_type, resource_id, status, severity, first_event_at, last_event_at, acknowledged_at, closed_at)
VALUES ('honeytoken', $1, $2, 'low', now(), now(),
	CASE WHEN $2 = 'acknowledged' THEN clock_timestamp() END, CASE WHEN $2 = 'closed' THEN clock_timestamp() END)
RETURNING id`, resource, status).Scan(&id)
	return id, err
}

func constraintOf(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}

func TestSchema_AtMostOneOpenIncidentPerResource(t *testing.T) {
	t.Parallel()
	pool := incidentSchema(t)

	const resource, other = "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"
	for _, status := range []string{"closed", "closed", "acknowledged"} {
		if _, err := insertIncident(t, pool, resource, status); err != nil {
			t.Fatalf("insert %s incident: %v", status, err)
		}
	}
	// An acknowledged incident is still open.
	if _, err := insertIncident(t, pool, resource, "open"); constraintOf(err) != "incidents_open_resource_key" {
		t.Errorf("second open incident: error = %v, want incidents_open_resource_key", err)
	}
	if _, err := insertIncident(t, pool, other, "open"); err != nil {
		t.Errorf("open incident of another resource: %v", err)
	}
}

// A closed incident is never opened again, and no status moves back.
func TestSchema_IncidentStatusOnlyMovesForward(t *testing.T) {
	t.Parallel()
	pool := incidentSchema(t)

	tests := []struct {
		from, to string
		allowed  bool
	}{
		{from: "open", to: "acknowledged", allowed: true},
		{from: "open", to: "closed", allowed: true},
		{from: "acknowledged", to: "closed", allowed: true},
		{from: "acknowledged", to: "open"},
		{from: "closed", to: "open"},
		{from: "closed", to: "acknowledged"},
	}
	for _, tt := range tests {
		id, err := insertIncident(t, pool, "00000000-0000-4000-8000-000000000001", tt.from)
		if err != nil {
			t.Fatalf("insert %s incident: %v", tt.from, err)
		}
		_, err = pool.Exec(t.Context(), `
UPDATE incidents SET status = $2,
	acknowledged_at = CASE WHEN $2 = 'open' THEN NULL ELSE coalesce(acknowledged_at, clock_timestamp()) END,
	closed_at = CASE WHEN $2 = 'closed' THEN coalesce(closed_at, clock_timestamp()) END
WHERE id = $1`, id, tt.to)
		switch {
		case tt.allowed && err != nil:
			t.Errorf("%s -> %s: error = %v, want nil", tt.from, tt.to, err)
		case !tt.allowed && constraintOf(err) != "incidents_keep_status_forward":
			t.Errorf("%s -> %s: error = %v, want incidents_keep_status_forward", tt.from, tt.to, err)
		}
		// Every incident is closed at the end, so that the next one can open.
		if _, err := pool.Exec(t.Context(), "UPDATE incidents SET status = 'closed', closed_at = coalesce(closed_at, clock_timestamp()) WHERE id = $1", id); err != nil {
			t.Fatalf("close incident: %v", err)
		}
	}
}

func TestSchema_ChecksIncidents(t *testing.T) {
	t.Parallel()
	pool := incidentSchema(t)

	const insert = `INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at) VALUES ('honeytoken', gen_random_uuid(), 'low', now(), now())`
	tests := []struct {
		name, statement, constraint string
	}{
		{"unknown status", "UPDATE incidents SET status = 'resolved'", "incidents_status_check"},
		{"closed without time", "UPDATE incidents SET status = 'closed'", "incidents_status_times_check"},
		{"acknowledged without time", "UPDATE incidents SET status = 'acknowledged'", "incidents_status_times_check"},
		{"open with closing time", "UPDATE incidents SET closed_at = now()", "incidents_status_times_check"},
		{"closed before opened", "UPDATE incidents SET status = 'closed', closed_at = opened_at - interval '1 second'", "incidents_status_times_check"},
		{"info as severity", "UPDATE incidents SET severity = 'info'", "incidents_severity_check"},
		{"unknown override", "UPDATE incidents SET severity_override = 'urgent'", "incidents_severity_override_check"},
		{"invalid technique", "UPDATE incidents SET techniques = '{T1}'", "incidents_techniques_check"},
		{"too many overrides", "UPDATE incidents SET techniques_override = ARRAY(SELECT 'T' || (1000 + i) FROM generate_series(1, 21) AS i)", "incidents_techniques_override_check"},
		{"control character in notes", "UPDATE incidents SET notes = E'a\\x07'", "incidents_notes_check"},
		{"notes too long", "UPDATE incidents SET notes = repeat('a', 10001)", "incidents_notes_check"},
		{"no events", "UPDATE incidents SET event_count = 0", "incidents_event_count_check"},
		{"last event before first", "UPDATE incidents SET last_event_at = first_event_at - interval '1 second'", "incidents_event_times_check"},
		{"unknown resource type", "UPDATE incidents SET resource_type = 'artifact'", "incidents_resource_type_check"},
	}
	for _, tt := range tests {
		if _, err := pool.Exec(t.Context(), insert); err != nil {
			t.Fatalf("insert incident: %v", err)
		}
		if _, err := pool.Exec(t.Context(), tt.statement); constraintOf(err) != tt.constraint {
			t.Errorf("%s: error = %v, want %s", tt.name, err, tt.constraint)
		}
		if _, err := pool.Exec(t.Context(), "DELETE FROM incidents"); err != nil {
			t.Fatalf("delete incidents: %v", err)
		}
	}

	// Notes may span several lines.
	if _, err := pool.Exec(t.Context(), insert); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if _, err := pool.Exec(t.Context(), "UPDATE incidents SET notes = E'a\\r\\n\\tb'"); err != nil {
		t.Errorf("notes with line breaks: %v", err)
	}
}

// An incident has exactly one alert, and an event belongs to an incident that
// exists.
func TestSchema_OneAlertPerIncident(t *testing.T) {
	t.Parallel()
	pool := incidentSchema(t)

	id, err := insertIncident(t, pool, "00000000-0000-4000-8000-000000000001", "open")
	if err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	const alert = "INSERT INTO alerts (incident_id, severity) VALUES ($1, 'low')"
	if _, err := pool.Exec(t.Context(), alert, id); err != nil {
		t.Fatalf("insert alert: %v", err)
	}
	if _, err := pool.Exec(t.Context(), alert, id); constraintOf(err) != "alerts_pkey" {
		t.Errorf("second alert: error = %v, want alerts_pkey", err)
	}
	if _, err := pool.Exec(t.Context(), "INSERT INTO alerts (incident_id, severity) VALUES (gen_random_uuid(), 'low')"); constraintOf(err) != "alerts_incident_id_fkey" {
		t.Errorf("alert without incident: error = %v, want alerts_incident_id_fkey", err)
	}
	if _, err := pool.Exec(t.Context(), "UPDATE events SET incident_id = gen_random_uuid()"); constraintOf(err) != "events_incident_id_fkey" {
		t.Errorf("event of a missing incident: error = %v, want events_incident_id_fkey", err)
	}
}
