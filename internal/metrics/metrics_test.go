// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/platform/schematest"
)

// Values of the inventory and personal data that the test places in the
// database, none of which may appear in the metrics.
const (
	honeytokenName = "inventory-name-qx"
	clientIP       = "203.0.113.77"
	userAgent      = "agent-of-a-person-qx"
	notes          = "notes-of-an-analyst-qx"
	channelName    = "channel-name-qx"
	honeypotName   = "honeypot-name-qx"
	attackerName   = "attacker-name-qx"
	attackerIP     = "198.51.100.78"
	clientVersion  = "client-version-qx"
)

// placeState writes a honeytoken with an event and its job, three honeypots of
// the three states, one of which reported a session, an open and an
// acknowledged incident, a pending and a dead delivery, and a run of a
// periodic task, as the owner.
func placeState(t *testing.T, owner *pgxpool.Pool) {
	t.Helper()
	for _, statement := range []string{
		"INSERT INTO honeytokens (type, name, severity, trigger_value) VALUES ('web_url', '" + honeytokenName + "', 'medium', repeat('a', 26))",
		"SELECT * FROM record_honeytoken_request(repeat('a', 26), 'GET', '" + clientIP + "', '" + userAgent + "', '', '', '')",
		`INSERT INTO honeypots (service, name, severity, secret_hash, secret_sealed, created_at, last_seen_at) VALUES
('ssh', '` + honeypotName + `', 'medium', sha256('a'), sha256('a'), now() - interval '2 hours', NULL),
('ssh', '` + honeypotName + `', 'medium', sha256('b'), sha256('b'), now() - interval '2 hours', now() - interval '1 minute'),
('ldap', '` + honeypotName + `', 'medium', sha256('c'), sha256('c'), now() - interval '2 hours', now() - interval '1 hour')`,
		`SELECT * FROM record_honeypot_session(sha256('b'), gen_random_uuid(), interval '0', 10, '` + attackerIP + `', 22, 'login_attempt',
'` + clientVersion + `', NULL, NULL, NULL, NULL, '[{"username":"` + attackerName + `","password_length":3}]', '[]')`,
		`INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at, notes, resource_name)
SELECT 'honeytoken', id, 'high', now(), now(), '` + notes + `', name FROM honeytokens`,
		`INSERT INTO incidents (resource_type, resource_id, status, severity, first_event_at, last_event_at, acknowledged_at, resource_name)
VALUES ('honeytoken', gen_random_uuid(), 'acknowledged', 'low', now(), now(), clock_timestamp(), 'Name')`,
		"INSERT INTO alerts (incident_id, severity) SELECT id, severity FROM incidents",
		`INSERT INTO alert_deliveries (alert_id, channel_id, channel_type, channel_name, not_before)
SELECT incident_id, gen_random_uuid(), 'webhook', '` + channelName + `', clock_timestamp() - interval '90 seconds' FROM alerts WHERE severity = 'high'`,
		`INSERT INTO alert_deliveries (alert_id, channel_id, channel_type, channel_name, status, attempts, last_attempt_at, last_error)
SELECT incident_id, gen_random_uuid(), 'slack', '` + channelName + `', 'dead', 10, clock_timestamp(), 'timeout' FROM alerts WHERE severity = 'low'`,
		"UPDATE periodic_tasks SET last_succeeded_at = clock_timestamp(), last_rows = 5 WHERE name = 'delete_expired_sign_in_data'",
	} {
		if _, err := owner.Exec(t.Context(), statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

// response is what a client received.
type response struct {
	status int
	header http.Header
	body   string
}

// get serves GET /api/v1/metrics through the handler on q, over a real server.
func get(t *testing.T, q *pgxpool.Pool) response {
	t.Helper()
	srv := httptest.NewServer(Handler(slog.New(slog.DiscardHandler), q))
	t.Cleanup(srv.Close)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: string(body)}
}

// sampleLine is a sample in the text format: a name, at most one label of a
// fixed name or the labels of the build information, and a number.
var sampleLine = regexp.MustCompile(`^(nyktus_[a-z_]+)(\{([a-z_]+)="([^"]*)"\}|\{version="[^"]*",go_version="[^"]*"\})? (-?[0-9.e+]+)$`)

// The console reads the metrics with its own login, through the function of
// the database, and gets the state of the queues, the incidents and the
// periodic tasks.
func TestHandler_ReportsTheState(t *testing.T) {
	t.Parallel()

	ownerURL, consoleURL := schematest.Console(t)
	placeState(t, schematest.Open(t, ownerURL))
	resp := get(t, schematest.Open(t, consoleURL))
	if resp.status != http.StatusOK || resp.header.Get("Content-Type") != contentType || resp.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("GET = %d, %q, %q; want 200 with the text format, not stored", resp.status, resp.header.Get("Content-Type"), resp.header.Get("Cache-Control"))
	}
	text := resp.body
	for _, want := range []string{
		"nyktus_event_jobs 2\n",
		"nyktus_event_jobs_due 2\n",
		"nyktus_event_jobs_retrying 0\n",
		`nyktus_alert_deliveries{status="pending"} 1` + "\n",
		`nyktus_alert_deliveries{status="dead"} 1` + "\n",
		`nyktus_incidents{status="open"} 1` + "\n",
		`nyktus_incidents{status="acknowledged"} 1` + "\n",
		`nyktus_honeypots{status="never"} 1` + "\n",
		`nyktus_honeypots{status="online"} 1` + "\n",
		`nyktus_honeypots{status="offline"} 1` + "\n",
		`nyktus_periodic_task_last_rows{task="delete_expired_sign_in_data"} 5` + "\n",
		`nyktus_periodic_task_last_failure_timestamp_seconds{task="delete_expired_sign_in_data"} 0` + "\n",
		"# TYPE nyktus_build_info gauge\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics lack %q:\n%s", want, text)
		}
	}
	// The pending delivery has been due for 90 seconds.
	m := regexp.MustCompile(`(?m)^nyktus_alert_deliveries_oldest_due_age_seconds ([0-9.e+]+)$`).FindStringSubmatch(text)
	if m == nil {
		t.Errorf("no age of the oldest due delivery:\n%s", text)
	} else if age, err := strconv.ParseFloat(m[1], 64); err != nil || age < 90 || age > 600 {
		t.Errorf("oldest due delivery waited %s seconds, want about 90", m[1])
	}
	// Every metric that the package describes is reported.
	for _, f := range append(families, family{name: "build_info"}) {
		if !regexp.MustCompile(`(?m)^nyktus_` + f.name + `[ {]`).MatchString(text) {
			t.Errorf("no sample of nyktus_%s:\n%s", f.name, text)
		}
	}
}

// The metrics reveal neither the inventory nor personal data: no name, address,
// header, note or identifier appears, and labels hold only fixed states and
// the names of the periodic tasks.
func TestHandler_ReportsNoInventoryOrPersonalData(t *testing.T) {
	t.Parallel()

	ownerURL, consoleURL := schematest.Console(t)
	owner := schematest.Open(t, ownerURL)
	placeState(t, owner)
	text := get(t, schematest.Open(t, consoleURL)).body
	for _, secret := range []string{
		honeytokenName, clientIP, userAgent, notes, channelName, strings.Repeat("a", 26),
		honeypotName, attackerName, attackerIP, clientVersion, "ssh", "ldap",
	} {
		if strings.Contains(text, secret) {
			t.Errorf("metrics contain %q:\n%s", secret, text)
		}
	}
	if uuid := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-`).FindString(text); uuid != "" {
		t.Errorf("metrics contain an identifier %q:\n%s", uuid, text)
	}

	rows, err := owner.Query(t.Context(), "SELECT name FROM periodic_tasks")
	if err != nil {
		t.Fatal(err)
	}
	tasks, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string][]string{
		"status": {"pending", "dead", "open", "acknowledged", "never", "online", "offline"},
		"task":   tasks,
	}
	for line := range strings.SplitSeq(strings.TrimSuffix(text, "\n"), "\n") {
		if strings.HasPrefix(line, "# HELP nyktus_") || strings.HasPrefix(line, "# TYPE nyktus_") {
			continue
		}
		m := sampleLine.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("line %q is no sample of the expected form", line)
			continue
		}
		if name, value := m[3], m[4]; name != "" && !slices.Contains(allowed[name], value) {
			t.Errorf("line %q has a label outside the fixed values", line)
		}
	}
}

// A metric of the database that the package does not describe, or a label that
// it does not describe, fails the read,
// so that a change of the function cannot slip past the review of what leaves
// through it.
func TestRead_RejectsUnknownMetrics(t *testing.T) {
	t.Parallel()

	owner := schematest.Open(t, schematest.New(t))
	if _, err := owner.Exec(t.Context(), `
CREATE OR REPLACE FUNCTION public.read_metrics() RETURNS TABLE (metric text, label text, value double precision)
	LANGUAGE sql AS $$ SELECT 'client_addresses', '203.0.113.77', 1::double precision $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := read(t.Context(), owner); err == nil || !strings.Contains(err.Error(), "unknown metric") {
		t.Errorf("read() error = %v, want an unknown metric", err)
	}
	if resp := get(t, owner); resp.status != http.StatusInternalServerError || strings.Contains(resp.body, "203.0.113.77") {
		t.Errorf("GET = %d, %s; want a generic 500", resp.status, resp.body)
	}

	// A known metric with a label that it does not have.
	if _, err := owner.Exec(t.Context(), `
CREATE OR REPLACE FUNCTION public.read_metrics() RETURNS TABLE (metric text, label text, value double precision)
	LANGUAGE sql AS $$ SELECT 'event_jobs', '203.0.113.77', 1::double precision $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := read(t.Context(), owner); err == nil || !strings.Contains(err.Error(), "with label") {
		t.Errorf("read() error = %v, want an unexpected label", err)
	}
}

// Label values are escaped as the text format requires, so that a value can
// never end a label or a line.
func TestWrite_EscapesLabels(t *testing.T) {
	t.Parallel()

	out := format(map[string][]sample{"incidents": {{label: "a\"b\\c\nd", value: 1}}})
	if want := `nyktus_incidents{status="a\"b\\c\nd"} 1` + "\n"; !strings.Contains(out, want) {
		t.Errorf("output lacks %q:\n%s", want, out)
	}
}
