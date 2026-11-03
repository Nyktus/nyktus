// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package trigger

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/schematest"
)

func randomSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomSessionID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// honeypotRow describes a honeypot to create.
type honeypotRow struct {
	service    string
	enabled    bool
	techniques []string
	severity   string
	scenarioID *string
}

// honeypot creates a honeypot with a new secret and returns its identifier and
// secret.
func (f fixture) honeypot(t *testing.T, row honeypotRow) (id, secret string) {
	t.Helper()
	if row.service == "" {
		row.service = "ssh"
	}
	if row.severity == "" {
		row.severity = "medium"
	}
	if row.techniques == nil {
		row.techniques = []string{}
	}
	secret = randomSecret(t)
	err := f.owner.QueryRow(t.Context(), `
INSERT INTO honeypots (service, name, enabled, techniques, severity, scenario_id, secret_hash, secret_sealed)
VALUES ($1, 'h', $2, $3, $4, $5, $6, $6)
RETURNING id`, row.service, row.enabled, row.techniques, row.severity, row.scenarioID, SecretHash(secret)).Scan(&id)
	if err != nil {
		t.Fatalf("create honeypot: %v", err)
	}
	return id, secret
}

func enabled(service string) honeypotRow { return honeypotRow{service: service, enabled: true} }

func (f fixture) newSession(t *testing.T) Session {
	t.Helper()
	return Session{
		ID: randomSessionID(t), Age: 2 * time.Second, Duration: 3 * time.Second,
		ClientIP: netip.MustParseAddr("203.0.113.9"), Port: 22,
		Attempts: []Attempt{{Username: "root", PasswordLength: intPtr(8)}},
	}
}

func (f fixture) lastSeen(t *testing.T, id string) (at *time.Time, version *string) {
	t.Helper()
	if err := f.owner.QueryRow(t.Context(), "SELECT last_seen_at, sensor_version FROM honeypots WHERE id = $1", id).Scan(&at, &version); err != nil {
		t.Fatal(err)
	}
	return at, version
}

func (f fixture) session(t *testing.T, secret string, s Session) ReportResult {
	t.Helper()
	res, err := f.store.RecordSession(t.Context(), SecretHash(secret), s)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}
	return res
}

func (f fixture) setBack(t *testing.T, d time.Duration) {
	t.Helper()
	if _, err := f.owner.Exec(t.Context(), "UPDATE events SET occurred_at = occurred_at - $1::interval, recorded_at = recorded_at - $1::interval", d); err != nil {
		t.Fatal(err)
	}
}

func TestStore_RecordsASessionOfAnEnabledHoneypot(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	var scenarioID string
	if err := f.owner.QueryRow(t.Context(), `INSERT INTO scenarios (name) VALUES ('s') RETURNING id`).Scan(&scenarioID); err != nil {
		t.Fatal(err)
	}
	id, secret := f.honeypot(t, honeypotRow{service: "ssh", enabled: true, techniques: []string{"T1078", "T1110"}, severity: "high", scenarioID: &scenarioID})
	s := f.newSession(t)
	s.ClientVersion = "SSH-2.0-OpenSSH_9.6"
	s.Attempts = []Attempt{
		{Username: "root", PasswordLength: intPtr(8)},
		{Username: "admin", KeyFingerprint: "SHA256:" + strings.Repeat("A", 43)},
		{Username: "", PasswordLength: intPtr(0)},
	}
	res := f.session(t, secret, s)
	if want := (ReportResult{Outcome: ReportRecorded, HoneypotID: id, Service: "ssh"}); res != want {
		t.Fatalf("RecordSession() = %+v, want %+v", res, want)
	}

	var (
		resourceType, channel, eventType, service, severity, clientVersion string
		resourceID, sessionID, scenario                                    string
		techniques                                                         []string
		ip                                                                 netip.Addr
		port, duration, jobs                                               int
		age                                                                float64
	)
	err := f.owner.QueryRow(t.Context(), `
SELECT e.resource_type, e.resource_id, e.scenario_id, e.channel, e.sensor_event_type, e.sensor_service, e.severity,
	e.sensor_client_version, e.sensor_session_id, e.techniques, e.client_ip, e.sensor_port, e.sensor_duration_ms,
	extract(epoch FROM e.recorded_at - e.occurred_at)::float8, (SELECT count(*) FROM event_jobs AS j WHERE j.event_id = e.id)
FROM events AS e`).Scan(&resourceType, &resourceID, &scenario, &channel, &eventType, &service, &severity, &clientVersion,
		&sessionID, &techniques, &ip, &port, &duration, &age, &jobs)
	if err != nil {
		t.Fatalf("read event: %v", err)
	}
	if resourceType != "honeypot" || resourceID != id || scenario != scenarioID || channel != "sensor" || eventType != "login_attempt" ||
		service != "ssh" || severity != "high" || clientVersion != "SSH-2.0-OpenSSH_9.6" ||
		strings.ReplaceAll(sessionID, "-", "") != s.ID || ip != s.ClientIP || port != 22 || duration != 3000 || age != 2 || jobs != 1 {
		t.Errorf("event = %s %s %s %s %s %s %s %q %s %v %d %d %v, %d jobs", resourceType, resourceID, scenario, channel, eventType,
			service, severity, clientVersion, sessionID, ip, port, duration, age, jobs)
	}
	// The techniques of the kind of event come first, then those of the honeypot.
	if want := []string{"T1110", "T1021.004", "T1078"}; !slices.Equal(techniques, want) {
		t.Errorf("techniques = %v, want %v", techniques, want)
	}

	rows, err := f.owner.Query(t.Context(), `SELECT ordinal, username, password_length, key_fingerprint FROM event_attempts ORDER BY ordinal`)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		Ordinal     int
		Username    string
		Length      *int
		Fingerprint *string
	}
	got, err := pgx.CollectRows(rows, pgx.RowToStructByPos[row])
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	if len(got) != 3 ||
		got[0].Ordinal != 1 || got[0].Username != "root" || got[0].Length == nil || *got[0].Length != 8 || got[0].Fingerprint != nil ||
		got[1].Ordinal != 2 || got[1].Username != "admin" || got[1].Length != nil || got[1].Fingerprint == nil || *got[1].Fingerprint != fingerprint ||
		got[2].Ordinal != 3 || got[2].Username != "" || got[2].Length == nil || *got[2].Length != 0 || got[2].Fingerprint != nil {
		t.Errorf("attempts = %+v, want root with 8, admin with a key, and an empty name with 0", got)
	}
}

// The service decides which fields a session can hold and which techniques its
// kinds of event suggest, and every pair of service and event type that the
// code knows is stored.
func TestStore_RecordsEveryKindOfEvent(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	attempt := []Attempt{{Username: "u", PasswordLength: intPtr(1)}}
	for _, service := range []string{"ssh", "telnet", "postgres", "ldap"} {
		_, secret := f.honeypot(t, enabled(service))
		sessions := map[EventType]Session{
			EventConnection:   {Attempts: []Attempt{}},
			EventLoginAttempt: {Attempts: attempt},
		}
		if service == "ldap" {
			sessions[EventDirectoryQuery] = Session{Attempts: attempt, Query: &Query{BaseDN: "", Filter: "(objectClass=*)"}}
		}
		if service == "ssh" {
			s := sessions[EventLoginAttempt]
			s.ClientVersion = "SSH-2.0-x"
			sessions[EventLoginAttempt] = s
		}
		if service == "postgres" {
			s := sessions[EventLoginAttempt]
			s.Database, s.ApplicationName = "postgres", "psql"
			sessions[EventLoginAttempt] = s
		}
		for event, s := range sessions {
			s.ID, s.ClientIP, s.Port = randomSessionID(t), netip.MustParseAddr("2001:db8::1"), 1234
			res := f.session(t, secret, s)
			if res.Outcome != ReportRecorded {
				t.Errorf("%s %s: outcome = %s, want recorded", service, event, res.Outcome)
				continue
			}
			var techniques []string
			err := f.owner.QueryRow(t.Context(), "SELECT techniques FROM events WHERE sensor_session_id = $1", s.ID).Scan(&techniques)
			if err != nil || !slices.Equal(techniques, KindTechniques(service, event)) {
				t.Errorf("%s %s: techniques = %v, %v; want %v", service, event, techniques, err, KindTechniques(service, event))
			}
		}
	}
}

// A session whose fields do not fit the service of the honeypot is not stored,
// and the database says so with an outcome instead of a failing check, which
// would write the row with the captured values to its log. Each case breaks one
// rule.
func TestStore_DoesNotRecordASessionThatDoesNotFitTheService(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	attempt := []Attempt{{Username: "u"}}
	query := &Query{BaseDN: "dc=example", Filter: "(cn=*)"}
	tests := []struct {
		name    string
		service string
		edit    func(s *Session)
	}{
		{"directory query to ssh", "ssh", func(s *Session) { s.Query = query }},
		{"directory query to postgres", "postgres", func(s *Session) { s.Query = query }},
		{"database to ssh", "ssh", func(s *Session) { s.Database = "postgres" }},
		{"application name to ldap", "ldap", func(s *Session) { s.ApplicationName = "psql" }},
		{"client version to postgres", "postgres", func(s *Session) { s.ClientVersion = "SSH-2.0-x" }},
		{"client version to telnet", "telnet", func(s *Session) { s.ClientVersion = "x" }},
	}
	for _, tt := range tests {
		_, secret := f.honeypot(t, enabled(tt.service))
		s := f.newSession(t)
		s.Attempts = attempt
		tt.edit(&s)
		if res := f.session(t, secret, s); res.Outcome != ReportInvalid {
			t.Errorf("%s: outcome = %s, want invalid", tt.name, res.Outcome)
		}
	}
	if n := f.count(t, "SELECT count(*) FROM events"); n != 0 {
		t.Errorf("%d events, want none", n)
	}
}

// The function checks that the type the trigger names fits the content, in case
// a compromised trigger names another. Each case breaks one rule.
func TestStore_DoesNotRecordAnEventTypeThatDoesNotFitTheContent(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, secret := f.honeypot(t, enabled("ldap"))
	call := func(eventType string, attempts string, baseDN, filter *string) string {
		t.Helper()
		var outcome string
		err := f.owner.QueryRow(t.Context(), `
SELECT outcome FROM public.record_honeypot_session($1, gen_random_uuid(), interval '0', 0, '192.0.2.1', 389, $2, NULL, NULL, NULL, $3, $4, $5::jsonb)`,
			SecretHash(secret), eventType, baseDN, filter, attempts).Scan(&outcome)
		if err != nil {
			t.Fatalf("record session: %v", err)
		}
		return outcome
	}
	dn, filter := "dc=example", "(cn=*)"
	tests := []struct {
		name      string
		eventType string
		attempts  string
		baseDN    *string
		filter    *string
		want      string
	}{
		{"connection", "connection", `[]`, nil, nil, "recorded"},
		{"login attempt", "login_attempt", `[{"username":"u"}]`, nil, nil, "recorded"},
		{"directory query", "directory_query", `[]`, &dn, &filter, "recorded"},
		{"unknown type", "scan", `[]`, nil, nil, "invalid"},
		{"connection with an attempt", "connection", `[{"username":"u"}]`, nil, nil, "invalid"},
		{"connection with a query", "connection", `[]`, &dn, &filter, "invalid"},
		{"login attempt without an attempt", "login_attempt", `[]`, nil, nil, "invalid"},
		{"login attempt with a query", "login_attempt", `[{"username":"u"}]`, &dn, &filter, "invalid"},
		{"login attempt with a base", "login_attempt", `[{"username":"u"}]`, &dn, nil, "invalid"},
		{"directory query without a query", "directory_query", `[]`, nil, nil, "invalid"},
		{"directory query without a filter", "directory_query", `[]`, &dn, nil, "invalid"},
		{"directory query without a base", "directory_query", `[]`, nil, &filter, "invalid"},
		{"filter without a base", "connection", `[]`, nil, &filter, "invalid"},
		{"seven attempts", "login_attempt", `[{"username":"u"},{"username":"u"},{"username":"u"},{"username":"u"},{"username":"u"},{"username":"u"},{"username":"u"}]`, nil, nil, "invalid"},
		{"attempts that are no list", "login_attempt", `{"username":"u"}`, nil, nil, "invalid"},
	}
	for _, tt := range tests {
		if got := call(tt.eventType, tt.attempts, tt.baseDN, tt.filter); got != tt.want {
			t.Errorf("%s: outcome = %s, want %s", tt.name, got, tt.want)
		}
	}
	if n := f.count(t, "SELECT count(*) FROM events WHERE sensor_event_type = 'directory_query'"); n != 1 {
		t.Errorf("%d directory queries stored, want 1", n)
	}
}

// A secret that belongs to no honeypot records nothing and changes nothing: not
// a wrong one, not one that was replaced, not the old one of a honeypot whose
// secret was rotated.
func TestStore_WrongRotatedAndOldSecretsRecordNothing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, old := f.honeypot(t, enabled("ssh"))
	s := f.newSession(t)
	rotated := randomSecret(t)
	if _, err := f.owner.Exec(t.Context(), "UPDATE honeypots SET secret_hash = $2 WHERE id = $1", id, SecretHash(rotated)); err != nil {
		t.Fatal(err)
	}

	for name, secret := range map[string]string{"wrong": randomSecret(t), "old": old, "the hash itself": string(SecretHash(old))} {
		if res := f.session(t, secret, s); res != (ReportResult{Outcome: ReportUnknown}) {
			t.Errorf("%s secret: RecordSession() = %+v, want unknown", name, res)
		}
		res, err := f.store.RecordHeartbeat(t.Context(), SecretHash(secret), Heartbeat{SensorVersion: "0.1.0"})
		if err != nil || res != (ReportResult{Outcome: ReportUnknown}) {
			t.Errorf("%s secret: RecordHeartbeat() = %+v, %v; want unknown", name, res, err)
		}
	}
	if n := f.count(t, "SELECT count(*) FROM events"); n != 0 {
		t.Errorf("%d events, want none", n)
	}
	if at, version := f.lastSeen(t, id); at != nil || version != nil {
		t.Errorf("honeypot reported at %v with version %v, want no report", at, version)
	}

	// The new secret works.
	if res := f.session(t, rotated, s); res.Outcome != ReportRecorded {
		t.Errorf("RecordSession(new secret) = %+v, want recorded", res)
	}
}

func TestStore_DisabledHoneypotRecordsNoSessionButAHeartbeat(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, secret := f.honeypot(t, honeypotRow{service: "ssh", enabled: false})
	res := f.session(t, secret, f.newSession(t))
	if want := (ReportResult{Outcome: ReportDisabled, HoneypotID: id, Service: "ssh"}); res != want {
		t.Errorf("RecordSession() = %+v, want %+v", res, want)
	}
	if n := f.count(t, "SELECT count(*) FROM events"); n != 0 {
		t.Errorf("%d events, want none", n)
	}
	// A session that is turned away does not show that the sensor runs.
	if at, _ := f.lastSeen(t, id); at != nil {
		t.Errorf("honeypot reported at %v after a session that was not recorded", *at)
	}

	res, err := f.store.RecordHeartbeat(t.Context(), SecretHash(secret), Heartbeat{SensorVersion: "0.1.0"})
	if want := (ReportResult{Outcome: ReportRecorded, HoneypotID: id, Service: "ssh"}); err != nil || res != want {
		t.Errorf("RecordHeartbeat() = %+v, %v; want %+v", res, err, want)
	}
	if at, version := f.lastSeen(t, id); at == nil || version == nil || *version != "0.1.0" {
		t.Errorf("honeypot reported at %v with version %v, want a report with 0.1.0", at, version)
	}
}

// A heartbeat is a sign of life and nothing else: it never records an event, a
// job, an incident or an alert, whatever honeypot it names.
func TestStore_HeartbeatNeverRecordsAnEvent(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, enabledSecret := f.honeypot(t, enabled("ssh"))
	_, disabledSecret := f.honeypot(t, honeypotRow{service: "ldap"})
	for _, secret := range []string{enabledSecret, disabledSecret, randomSecret(t)} {
		for _, version := range []string{"", "0.1.0", "0.1.1"} {
			if _, err := f.store.RecordHeartbeat(t.Context(), SecretHash(secret), Heartbeat{SensorVersion: version}); err != nil {
				t.Fatalf("RecordHeartbeat() error = %v", err)
			}
		}
	}
	for _, table := range []string{"events", "event_jobs", "event_attempts", "incidents", "alerts", "alert_deliveries"} {
		if n := f.count(t, "SELECT count(*) FROM "+table); n != 0 {
			t.Errorf("%s holds %d rows after heartbeats, want none", table, n)
		}
	}
}

// The time of the last report moves at most once a minute, so that a sensor
// that reports in a loop does not write the row of its honeypot every time; a
// new version is still taken at once.
func TestStore_HeartbeatMovesTheReportAtMostOncePerMinute(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, secret := f.honeypot(t, enabled("telnet"))
	beat := func(version string) {
		t.Helper()
		if res, err := f.store.RecordHeartbeat(t.Context(), SecretHash(secret), Heartbeat{SensorVersion: version}); err != nil || res.Outcome != ReportRecorded {
			t.Fatalf("RecordHeartbeat() = %+v, %v", res, err)
		}
	}
	beat("0.1.0")
	first, _ := f.lastSeen(t, id)

	beat("0.1.0")
	if again, _ := f.lastSeen(t, id); !again.Equal(*first) {
		t.Errorf("last report moved from %v to %v within a minute", first, again)
	}
	// A heartbeat without a version keeps the one that is known.
	beat("")
	if _, version := f.lastSeen(t, id); version == nil || *version != "0.1.0" {
		t.Errorf("version = %v after a heartbeat without one, want 0.1.0", version)
	}
	beat("0.2.0")
	if _, version := f.lastSeen(t, id); version == nil || *version != "0.2.0" {
		t.Errorf("version = %v, want 0.2.0 at once", version)
	}

	// 59 seconds later the report still stands; 61 seconds later it moves.
	for _, tt := range []struct {
		back  string
		moves bool
	}{{"59 seconds", false}, {"61 seconds", true}} {
		if _, err := f.owner.Exec(t.Context(), "UPDATE honeypots SET last_seen_at = clock_timestamp() - $2::interval, created_at = created_at - interval '1 hour' WHERE id = $1", id, tt.back); err != nil {
			t.Fatal(err)
		}
		before, _ := f.lastSeen(t, id)
		beat("0.2.0")
		after, _ := f.lastSeen(t, id)
		if moved := !after.Equal(*before); moved != tt.moves {
			t.Errorf("a heartbeat %s after the last: moved = %v, want %v", tt.back, moved, tt.moves)
		}
	}
}

// A session that is accepted proves that a sensor is alive, as a heartbeat
// does: one that is stored, one that the limit turns away and one that arrives
// twice.
func TestStore_AcceptedSessionCountsAsAHeartbeat(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, secret := f.honeypot(t, enabled("ssh"))
	s := f.newSession(t)
	f.session(t, secret, s)
	if at, _ := f.lastSeen(t, id); at == nil {
		t.Fatal("honeypot has no report after a session")
	}

	reset := func() {
		t.Helper()
		if _, err := f.owner.Exec(t.Context(), "UPDATE honeypots SET last_seen_at = NULL WHERE id = $1", id); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	if res := f.session(t, secret, s); res.Outcome != ReportDuplicate {
		t.Fatalf("outcome = %s, want duplicate", res.Outcome)
	}
	if at, _ := f.lastSeen(t, id); at == nil {
		t.Error("a session that arrived twice does not count as a report")
	}

	for range 10 {
		f.session(t, secret, f.newSession(t))
	}
	reset()
	if res := f.session(t, secret, f.newSession(t)); res.Outcome != ReportLimited {
		t.Fatalf("outcome = %s, want limited", res.Outcome)
	}
	if at, _ := f.lastSeen(t, id); at == nil {
		t.Error("a session beyond the limit does not count as a report")
	}

	// A session that is not valid does not.
	bad := f.newSession(t)
	bad.Database = "postgres"
	reset()
	if res := f.session(t, secret, bad); res.Outcome != ReportInvalid {
		t.Fatalf("outcome = %s, want invalid", res.Outcome)
	}
	if at, _ := f.lastSeen(t, id); at != nil {
		t.Error("an invalid session counts as a report")
	}
}

// A report that reaches the trigger twice, or a session that two requests send
// at the same moment, is stored once.
func TestStore_SessionIdentifierIsStoredOnce(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, secret := f.honeypot(t, enabled("ssh"))
	s := f.newSession(t)
	if res := f.session(t, secret, s); res.Outcome != ReportRecorded {
		t.Fatalf("first RecordSession() = %s", res.Outcome)
	}
	if res := f.session(t, secret, s); res.Outcome != ReportDuplicate {
		t.Errorf("second RecordSession() = %s, want duplicate", res.Outcome)
	}
	// The identifier belongs to the honeypot: another one may use it.
	_, other := f.honeypot(t, enabled("ssh"))
	if res := f.session(t, other, s); res.Outcome != ReportRecorded {
		t.Errorf("RecordSession(other honeypot) = %s, want recorded", res.Outcome)
	}

	concurrent := f.newSession(t)
	const requests = 8
	start := make(chan struct{})
	outcomes := make(chan ReportOutcome, requests)
	var wg sync.WaitGroup
	for range requests {
		wg.Go(func() {
			<-start
			res, err := f.store.RecordSession(t.Context(), SecretHash(secret), concurrent)
			if err != nil {
				t.Error(err)
			}
			outcomes <- res.Outcome
		})
	}
	close(start)
	wg.Wait()
	close(outcomes)
	counts := map[ReportOutcome]int{}
	for o := range outcomes {
		counts[o]++
	}
	if counts[ReportRecorded] != 1 || counts[ReportDuplicate] != requests-1 {
		t.Errorf("outcomes of %d concurrent requests = %v, want one recorded and the rest duplicates", requests, counts)
	}
	if n := f.count(t, "SELECT count(*) FROM events WHERE sensor_session_id = $1", concurrent.ID); n != 1 {
		t.Errorf("%d events for the session, want 1", n)
	}
	if n := f.count(t, "SELECT count(*) FROM event_jobs AS j JOIN events AS e ON e.id = j.event_id WHERE e.sensor_session_id = $1", concurrent.ID); n != 1 {
		t.Errorf("%d jobs for the session, want 1", n)
	}
	if n := f.count(t, "SELECT count(*) FROM event_attempts AS a JOIN events AS e ON e.id = a.event_id WHERE e.sensor_session_id = $1", concurrent.ID); n != 1 {
		t.Errorf("%d attempts for the session, want 1", n)
	}
}

// At most ten events per honeypot and minute are stored, and the limit is per
// honeypot.
func TestStore_LimitsEventsPerHoneypotAndMinute(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, secret := f.honeypot(t, enabled("ssh"))
	_, other := f.honeypot(t, enabled("ssh"))
	for i := range 12 {
		res := f.session(t, secret, f.newSession(t))
		want := ReportRecorded
		if i >= 10 {
			want = ReportLimited
		}
		if res.Outcome != want || res.HoneypotID != id {
			t.Errorf("session %d: outcome = %s, want %s", i, res.Outcome, want)
		}
	}
	if res := f.session(t, other, f.newSession(t)); res.Outcome != ReportRecorded {
		t.Errorf("other honeypot: outcome = %s, want recorded", res.Outcome)
	}

	// The window is a minute: events 59 seconds old still count, 61 seconds old
	// no longer.
	f.setBack(t, 59*time.Second)
	if res := f.session(t, secret, f.newSession(t)); res.Outcome != ReportLimited {
		t.Errorf("59 seconds later: outcome = %s, want limited", res.Outcome)
	}
	f.setBack(t, 2*time.Second)
	if res := f.session(t, secret, f.newSession(t)); res.Outcome != ReportRecorded {
		t.Errorf("61 seconds later: outcome = %s, want recorded", res.Outcome)
	}
	if n := f.count(t, "SELECT count(*) FROM events WHERE resource_id = $1", id); n != 11 {
		t.Errorf("%d events, want 11", n)
	}
}

// The sensor says how long ago the session began; the database keeps it between
// zero and five minutes.
func TestStore_AgeOfASessionIsKeptWithinFiveMinutes(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	tests := []struct {
		name string
		age  time.Duration
		want time.Duration
	}{
		{"negative", -time.Second, 0},
		{"zero", 0, 0},
		{"one second", time.Second, time.Second},
		{"just under five minutes", 5*time.Minute - time.Millisecond, 5*time.Minute - time.Millisecond},
		{"five minutes", 5 * time.Minute, 5 * time.Minute},
		{"just over five minutes", 5*time.Minute + time.Millisecond, 5 * time.Minute},
		{"an hour", time.Hour, 5 * time.Minute},
	}
	for _, tt := range tests {
		// A honeypot of its own keeps the limit of events out of the way.
		_, secret := f.honeypot(t, enabled("telnet"))
		s := f.newSession(t)
		s.Age = tt.age
		f.session(t, secret, s)
		var got time.Duration
		var micros int64
		err := f.owner.QueryRow(t.Context(), `SELECT (extract(epoch FROM recorded_at - occurred_at) * 1000000)::bigint FROM events WHERE sensor_session_id = $1`, s.ID).Scan(&micros)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		got = time.Duration(micros) * time.Microsecond
		if got != tt.want {
			t.Errorf("%s: event began %v before it was recorded, want %v", tt.name, got, tt.want)
		}
	}
}

// If the job cannot be written, neither the event nor its attempts are: a
// recorded event without a job must be impossible.
func TestStore_SessionIsNeverStoredWithoutItsJob(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, secret := f.honeypot(t, enabled("ssh"))
	f.session(t, secret, f.newSession(t))
	if _, err := f.owner.Exec(t.Context(), "ALTER TABLE event_jobs ADD CONSTRAINT event_jobs_reject CHECK (false) NOT VALID"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RecordSession(t.Context(), SecretHash(secret), f.newSession(t)); err == nil {
		t.Fatal("RecordSession() succeeded although the job could not be written")
	}

	if n := f.count(t, "SELECT count(*) FROM events"); n != 1 {
		t.Errorf("%d events, want only the one with a job", n)
	}
	if n := f.count(t, "SELECT count(*) FROM events AS e WHERE NOT EXISTS (SELECT FROM event_jobs AS j WHERE j.event_id = e.id)"); n != 0 {
		t.Errorf("%d events without a job", n)
	}
	if n := f.count(t, "SELECT count(*) FROM event_attempts"); n != 1 {
		t.Errorf("%d attempts, want only those of the event with a job", n)
	}
}

// No password is stored, whatever reaches the function: the table has no column
// for one, and a member of an attempt that the function does not know is
// ignored. Nothing a password could be hides in the rows either.
func TestStore_PasswordIsNeverStored(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, secret := f.honeypot(t, enabled("ssh"))
	const password = "hunter2-hunter2"
	var outcome string
	err := f.owner.QueryRow(t.Context(), `
SELECT outcome FROM public.record_honeypot_session($1, gen_random_uuid(), interval '0', 0, '192.0.2.1', 22, 'login_attempt', NULL, NULL, NULL, NULL, NULL,
	jsonb_build_array(jsonb_build_object('username', 'root', 'password_length', 15, 'password', $2::text, 'secret', $2::text)))`,
		SecretHash(secret), password).Scan(&outcome)
	if err != nil || outcome != "recorded" {
		t.Fatalf("record session = %s, %v", outcome, err)
	}

	var columns []string
	rows, err := f.owner.Query(t.Context(), `SELECT column_name FROM information_schema.columns WHERE table_name = 'event_attempts' ORDER BY ordinal_position`)
	if err != nil {
		t.Fatal(err)
	}
	if columns, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		t.Fatal(err)
	}
	if want := []string{"event_id", "ordinal", "username", "password_length", "key_fingerprint"}; !slices.Equal(columns, want) {
		t.Errorf("columns of event_attempts = %v, want %v", columns, want)
	}
	if n := f.count(t, "SELECT count(*) FROM (SELECT row_to_json(e)::text AS j FROM events AS e UNION ALL SELECT row_to_json(a)::text FROM event_attempts AS a) AS r WHERE j LIKE '%hunter2%'"); n != 0 {
		t.Errorf("%d rows contain the password", n)
	}
}

// pgError returns the database error behind err.
func pgError(err error) *pgconn.PgError {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr
	}
	return nil
}

// The schema is the last line of defense for the text of a session: whatever
// the sensor sends, the function stores no control character and no character
// that reorders or hides text, and no value beyond its length, even if the
// trigger skips its cleaning. Each case breaks one rule, and nothing of the
// session is left behind.
func TestStore_ChecksEveryTextFieldOfASession(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	fields := []struct {
		name, service, constraint string
		maxBytes                  int
		set                       func(s *Session, v string)
	}{
		{"client version", "ssh", "events_sensor_client_version_check", 128, func(s *Session, v string) { s.ClientVersion = v }},
		{"database", "postgres", "events_sensor_database_check", 64, func(s *Session, v string) { s.Database = v }},
		{"application name", "postgres", "events_sensor_application_name_check", 64, func(s *Session, v string) { s.ApplicationName = v }},
		{"base", "ldap", "events_sensor_base_dn_check", 256, func(s *Session, v string) { s.Query = &Query{BaseDN: v, Filter: "(a=b)"} }},
		{"filter", "ldap", "events_sensor_filter_check", 256, func(s *Session, v string) { s.Query = &Query{BaseDN: "dc=a", Filter: v} }},
		{"user name", "telnet", "event_attempts_username_check", 256, func(s *Session, v string) { s.Attempts = []Attempt{{Username: v}} }},
	}
	refused := map[string]rune{
		"control character":  0x01,
		"delete":             0x7f,
		"C1 control":         0x85,
		"soft hyphen":        0xad,
		"zero width space":   0x200b,
		"line separator":     0x2028,
		"right-to-left":      0x202e,
		"isolate":            0x2066,
		"byte order mark":    0xfeff,
		"tag character":      0xe0041,
		"arabic letter mark": 0x61c,
	}
	for _, field := range fields {
		_, secret := f.honeypot(t, enabled(field.service))
		try := func(value string) error {
			s := f.newSession(t)
			s.Attempts = []Attempt{{Username: "u"}}
			field.set(&s, value)
			_, err := f.store.RecordSession(t.Context(), SecretHash(secret), s)
			return err
		}
		if err := try(strings.Repeat("a", field.maxBytes)); err != nil {
			t.Errorf("%s of %d bytes: %v", field.name, field.maxBytes, err)
		}
		if err := try(strings.Repeat("a", field.maxBytes-1) + string(rune(0xe9))); pgError(err) == nil || pgError(err).ConstraintName != field.constraint {
			t.Errorf("%s of %d bytes: error = %v, want a violation of %s", field.name, field.maxBytes+1, err, field.constraint)
		}
		for name, r := range refused {
			err := try("a" + string(r) + "b")
			if pgError(err) == nil || pgError(err).ConstraintName != field.constraint {
				t.Errorf("%s with %s: error = %v, want a violation of %s", field.name, name, err, field.constraint)
				continue
			}
			// The error reaches the log of the trigger, so it must not carry
			// what the attacker typed.
			if strings.Contains(err.Error(), "a"+string(r)+"b") {
				t.Errorf("%s with %s: the error %q contains the value", field.name, name, err)
			}
		}
		// People write other scripts too.
		if err := try(string([]rune{0x4e2d, 0x6587, 0x1f600})); err != nil {
			t.Errorf("%s in another script: %v", field.name, err)
		}
	}
	// What was refused left nothing behind.
	if n := f.count(t, "SELECT count(*) FROM events AS e WHERE NOT EXISTS (SELECT FROM event_jobs AS j WHERE j.event_id = e.id)"); n != 0 {
		t.Errorf("%d events without a job", n)
	}
}

// The checks of the session columns and of the attempts hold for whoever writes
// the rows, not only for the function. Each case breaks one rule of an
// otherwise valid row.
func TestSchema_ChecksSessionColumnsAndAttempts(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// The columns of an event of a session, in the order of insert.
	const insert = `
INSERT INTO events (resource_type, resource_id, severity, occurred_at, recorded_at, channel, client_ip, sensor_session_id,
	sensor_service, sensor_event_type, sensor_port, sensor_duration_ms, sensor_client_version, sensor_database,
	sensor_application_name, sensor_base_dn, sensor_filter, honeytoken_type, method, resource_name)
VALUES ($1, gen_random_uuid(), 'medium', now(), now(), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 'Name')`
	base := []any{"honeypot", "sensor", "192.0.2.1", randomSessionID(t), "ssh", "login_attempt", 22, 1000, nil, nil, nil, nil, nil, nil, nil}
	index := map[string]int{
		"resource_type": 0, "channel": 1, "client_ip": 2, "session": 3, "service": 4, "event_type": 5, "port": 6,
		"duration": 7, "client_version": 8, "database": 9, "application_name": 10, "base_dn": 11, "filter": 12, "honeytoken_type": 13, "method": 14,
	}
	with := func(changes map[string]any) []any {
		args := slices.Clone(base)
		args[index["session"]] = randomSessionID(t)
		for name, v := range changes {
			args[index[name]] = v
		}
		return args
	}

	if _, err := f.owner.Exec(t.Context(), insert, with(nil)...); err != nil {
		t.Fatalf("a valid session event: %v", err)
	}
	tests := []struct {
		name       string
		changes    map[string]any
		constraint string
	}{
		{"honeypot over http", map[string]any{"channel": "http", "method": "GET"}, "events_sensor_check"},
		{"honeytoken over the sensor channel", map[string]any{"resource_type": "honeytoken", "honeytoken_type": "web_url"}, "events_sensor_check"},
		{"no session identifier", map[string]any{"session": nil}, "events_sensor_check"},
		{"no service", map[string]any{"service": nil}, "events_sensor_check"},
		{"no event type", map[string]any{"event_type": nil}, "events_sensor_check"},
		{"no port", map[string]any{"port": nil}, "events_sensor_check"},
		{"no duration", map[string]any{"duration": nil}, "events_sensor_check"},
		{"no address", map[string]any{"client_ip": nil}, "events_sensor_check"},
		{"unknown service", map[string]any{"service": "smtp"}, "events_sensor_service_check"},
		{"unknown event type", map[string]any{"event_type": "scan"}, "events_sensor_event_type_check"},
		{"port 0", map[string]any{"port": 0}, "events_sensor_port_check"},
		{"port 65536", map[string]any{"port": 65536}, "events_sensor_port_check"},
		{"negative duration", map[string]any{"duration": -1}, "events_sensor_duration_ms_check"},
		{"duration beyond five minutes", map[string]any{"duration": 300001}, "events_sensor_duration_ms_check"},
		{"directory query to ssh", map[string]any{"event_type": "directory_query", "base_dn": "dc=a", "filter": "(a=b)"}, "events_sensor_fields_check"},
		{"directory query without a base", map[string]any{"service": "ldap", "event_type": "directory_query", "filter": "(a=b)"}, "events_sensor_fields_check"},
		{"directory query without a filter", map[string]any{"service": "ldap", "event_type": "directory_query", "base_dn": "dc=a"}, "events_sensor_fields_check"},
		{"base without a directory query", map[string]any{"service": "ldap", "base_dn": "dc=a", "filter": "(a=b)"}, "events_sensor_fields_check"},
		{"database to ssh", map[string]any{"database": "postgres"}, "events_sensor_fields_check"},
		{"application name to ldap", map[string]any{"service": "ldap", "application_name": "psql"}, "events_sensor_fields_check"},
		{"client version to postgres", map[string]any{"service": "postgres", "client_version": "x"}, "events_sensor_fields_check"},
	}
	for _, tt := range tests {
		_, err := f.owner.Exec(t.Context(), insert, with(tt.changes)...)
		if pgError(err) == nil || pgError(err).Code != "23514" || pgError(err).ConstraintName != tt.constraint {
			t.Errorf("%s: error = %v, want a violation of %s", tt.name, err, tt.constraint)
		}
	}

	// One session is stored once per honeypot, by the constraint itself.
	var resourceID string
	if err := f.owner.QueryRow(t.Context(), "SELECT resource_id FROM events").Scan(&resourceID); err != nil {
		t.Fatal(err)
	}
	var sessionID string
	if err := f.owner.QueryRow(t.Context(), "SELECT sensor_session_id FROM events").Scan(&sessionID); err != nil {
		t.Fatal(err)
	}
	_, err := f.owner.Exec(t.Context(), `
INSERT INTO events (resource_type, resource_id, severity, occurred_at, recorded_at, channel, client_ip, sensor_session_id,
	sensor_service, sensor_event_type, sensor_port, sensor_duration_ms, resource_name)
VALUES ('honeypot', $1, 'medium', now(), now(), 'sensor', '192.0.2.1', $2, 'ssh', 'connection', 22, 0, 'Name')`, resourceID, sessionID)
	if pgError(err) == nil || pgError(err).Code != "23505" || pgError(err).ConstraintName != "events_sensor_session_key" {
		t.Errorf("session stored twice: error = %v, want a violation of events_sensor_session_key", err)
	}

	// Attempts.
	var eventID string
	if err := f.owner.QueryRow(t.Context(), "SELECT id FROM events").Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	const attempt = `INSERT INTO event_attempts (event_id, ordinal, username, password_length, key_fingerprint) VALUES ($1, $2, $3, $4, $5)`
	if _, err := f.owner.Exec(t.Context(), attempt, eventID, 6, "u", 65535, "SHA256:"+strings.Repeat("a", 43)); err != nil {
		t.Fatalf("a valid attempt: %v", err)
	}
	attempts := []struct {
		name       string
		args       []any
		constraint string
	}{
		{"ordinal 0", []any{eventID, 0, "u", nil, nil}, "event_attempts_ordinal_check"},
		{"ordinal 7", []any{eventID, 7, "u", nil, nil}, "event_attempts_ordinal_check"},
		{"negative length", []any{eventID, 1, "u", -1, nil}, "event_attempts_password_length_check"},
		{"length beyond 65535", []any{eventID, 1, "u", 65536, nil}, "event_attempts_password_length_check"},
		{"fingerprint of MD5", []any{eventID, 1, "u", nil, "MD5:aa:bb:cc"}, "event_attempts_key_fingerprint_check"},
		{"fingerprint too short", []any{eventID, 1, "u", nil, "SHA256:" + strings.Repeat("a", 42)}, "event_attempts_key_fingerprint_check"},
		{"fingerprint with a space", []any{eventID, 1, "u", nil, "SHA256:" + strings.Repeat("a", 42) + " "}, "event_attempts_key_fingerprint_check"},
		{"ordinal twice", []any{eventID, 6, "u", nil, nil}, "event_attempts_pkey"},
	}
	for _, tt := range attempts {
		_, err := f.owner.Exec(t.Context(), attempt, tt.args...)
		if pgError(err) == nil || pgError(err).ConstraintName != tt.constraint {
			t.Errorf("%s: error = %v, want a violation of %s", tt.name, err, tt.constraint)
		}
	}
	// An attempt belongs to its event and leaves with it.
	if _, err := f.owner.Exec(t.Context(), "DELETE FROM events"); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, "SELECT count(*) FROM event_attempts"); n != 0 {
		t.Errorf("%d attempts remain after their events were deleted", n)
	}
}

// Events are evidence: they keep the service, the severity, the techniques and
// the scenario of the honeypot as they were, and outlive its deletion.
func TestStore_SessionEventsOutliveChangesAndDeletion(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, secret := f.honeypot(t, honeypotRow{service: "ssh", enabled: true, techniques: []string{"T1078"}, severity: "critical"})
	f.session(t, secret, f.newSession(t))
	if _, err := f.owner.Exec(t.Context(), "UPDATE honeypots SET techniques = '{T1083}', severity = 'low' WHERE id = $1", id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(t.Context(), "DELETE FROM honeypots WHERE id = $1", id); err != nil {
		t.Fatalf("delete honeypot with events: %v", err)
	}
	if n := f.count(t, "SELECT count(*) FROM events WHERE resource_id = $1 AND severity = 'critical' AND techniques = '{T1110,T1021.004,T1078}' AND sensor_service = 'ssh'", id); n != 1 {
		t.Errorf("%d events with the values at the time of the session, want 1", n)
	}
}

// A session freezes the scenario of its honeypot when it ends.
func TestStore_SessionFreezesTheScenario(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	var first string
	if err := f.owner.QueryRow(t.Context(), `INSERT INTO scenarios (name) VALUES ('a') RETURNING id`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	id, secret := f.honeypot(t, enabled("ssh"))
	for _, scenario := range []*string{nil, &first} {
		if _, err := f.owner.Exec(t.Context(), `UPDATE honeypots SET scenario_id = $2 WHERE id = $1`, id, scenario); err != nil {
			t.Fatal(err)
		}
		f.session(t, secret, f.newSession(t))
	}
	if _, err := f.owner.Exec(t.Context(), `UPDATE honeypots SET scenario_id = NULL WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	rows, err := f.owner.Query(t.Context(), `SELECT coalesce(scenario_id::text, '') FROM events ORDER BY recorded_at`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"", first}; !slices.Equal(got, want) {
		t.Errorf("scenarios of the events = %v, want %v", got, want)
	}
}

// The techniques of an event never exceed the limit of the column, even if the
// honeypot already holds twenty: the techniques of the kind of event come first.
func TestStore_EventTechniquesStayWithinTheLimit(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	var techniques []string
	rows, err := f.owner.Query(t.Context(), `SELECT 'T' || (1100 + n)::text FROM generate_series(1, 20) AS n`)
	if err != nil {
		t.Fatal(err)
	}
	if techniques, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		t.Fatal(err)
	}
	_, secret := f.honeypot(t, honeypotRow{service: "ssh", enabled: true, techniques: techniques})
	if res := f.session(t, secret, f.newSession(t)); res.Outcome != ReportRecorded {
		t.Fatalf("outcome = %s, want recorded", res.Outcome)
	}
	var got []string
	if err := f.owner.QueryRow(t.Context(), "SELECT techniques FROM events").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 20 || got[0] != "T1110" || got[1] != "T1021.004" {
		t.Errorf("techniques = %v, want 20 starting with those of the kind of event", got)
	}
}

// A login of the trigger that reaches the inventory of honeypots, the attempts
// of a session or the function of the status keeps the trigger from starting.
func TestCheckPrivileges_RefusesALoginThatReachesTheInventory(t *testing.T) {
	t.Parallel()

	ownerURL, _ := schematest.Trigger(t)
	tests := []struct {
		name, grant, want string
	}{
		{"honeypots", "GRANT SELECT (secret_hash) ON public.honeypots TO %s", "tables [honeypots]"},
		{"attempts", "GRANT SELECT ON public.event_attempts TO %s", "tables [event_attempts]"},
		{"status function", "GRANT EXECUTE ON FUNCTION public.honeypot_status(timestamptz) TO %s", "execute [honeypot_status(timestamp with time zone)]"},
	}
	for _, tt := range tests {
		name, loginURL := dbtest.Role(t, ownerURL, tt.name, "IN ROLE "+pgx.Identifier{schematest.TriggerRole}.Sanitize())
		dbtest.Exec(t, ownerURL, strings.ReplaceAll(tt.grant, "%s", pgx.Identifier{name}.Sanitize()))
		err := CheckPrivileges(t.Context(), schematest.Open(t, loginURL))
		if !errors.Is(err, db.ErrRolePrivileges) || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: CheckPrivileges() = %v, want ErrRolePrivileges containing %q", tt.name, err, tt.want)
		}
	}
}

// The invariant over the real database role: a sensor cannot tell a secret of
// an enabled honeypot from a wrong one, one of a disabled or a deleted
// honeypot, a failing database, a session from a heartbeat or a report of
// another version, by status, headers or body. Only the database differs.
func TestTrigger_IdenticalReportResponsesWithTheDatabase(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, enabledSecret := f.honeypot(t, enabled("ssh"))
	_, disabledSecret := f.honeypot(t, honeypotRow{service: "ssh"})
	deletedID, deletedSecret := f.honeypot(t, enabled("ssh"))
	if _, err := f.owner.Exec(t.Context(), "DELETE FROM honeypots WHERE id = $1", deletedID); err != nil {
		t.Fatal(err)
	}
	limitedID, limitedSecret := f.honeypot(t, enabled("ssh"))
	for range 10 {
		f.session(t, limitedSecret, f.newSession(t))
	}
	_ = limitedID

	srv, _ := newReportingServer(t, &fakeRecorder{}, f.store)
	closed := schematest.Open(t, schematest.New(t))
	closed.Close()
	failing, _ := newReportingServer(t, &fakeRecorder{}, NewStore(closed))

	want := fetch(t, srv, http.MethodPost, "/", nil, nil)
	session := func(id string) []byte {
		return mutated(t, "session_ssh.json", func(m map[string]any) { m["session_id"] = id })
	}
	heartbeat := golden(t, "heartbeat.json")
	cases := map[string]response{}
	for name, secret := range map[string]string{
		"enabled": enabledSecret, "disabled": disabledSecret, "deleted": deletedSecret, "limited": limitedSecret,
		"wrong": randomSecret(t),
	} {
		cases[name+" session"] = fetch(t, srv, http.MethodPost, "/", bytes.NewReader(session(randomSessionID(t))), bearer(secret))
		cases[name+" heartbeat"] = fetch(t, srv, http.MethodPost, "/", bytes.NewReader(heartbeat), bearer(secret))
	}
	cases["duplicate session"] = fetch(t, srv, http.MethodPost, "/", bytes.NewReader(session("11111111111111111111111111111111")), bearer(enabledSecret))
	cases["duplicate session again"] = fetch(t, srv, http.MethodPost, "/", bytes.NewReader(session("11111111111111111111111111111111")), bearer(enabledSecret))
	cases["session that does not fit"] = fetch(t, srv, http.MethodPost, "/", bytes.NewReader(mutated(t, "session_postgres.json", func(map[string]any) {})), bearer(enabledSecret))
	cases["database failure"] = fetch(t, failing, http.MethodPost, "/", bytes.NewReader(session(randomSessionID(t))), bearer(enabledSecret))
	cases["unsupported version"] = fetch(t, srv, http.MethodPost, "/",
		bytes.NewReader(mutated(t, "session_ssh.json", func(m map[string]any) { m["version"] = 2 })), bearer(enabledSecret))
	for name, got := range cases {
		if !got.equal(want) {
			t.Errorf("%s: response %+v, want %+v", name, got, want)
		}
	}

	// Only the sessions of the honeypot that was enabled and not at its limit,
	// and its duplicate once, were recorded.
	if n := f.count(t, "SELECT count(*) FROM events WHERE sensor_session_id = '11111111-1111-1111-1111-111111111111'"); n != 1 {
		t.Errorf("%d events for the session sent twice, want 1", n)
	}
	if n := f.count(t, "SELECT count(*) FROM events WHERE resource_id <> $1", limitedID); n != 2 {
		t.Errorf("%d events beyond those of the limited honeypot, want 2", n)
	}
}

// The function checks the version of a sensor itself, so that a failing check
// does not write the row of the honeypot to the log of the database. A version
// of the wrong form is not applied, and the heartbeat does not count.
func TestStore_HeartbeatWithAVersionOfTheWrongFormIsNotApplied(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, secret := f.honeypot(t, enabled("ssh"))
	for _, version := range []string{"0.1 beta", "", strings.Repeat("1", 33), "-1"} {
		var outcome string
		if err := f.owner.QueryRow(t.Context(), `SELECT outcome FROM public.record_honeypot_heartbeat($1, $2)`, SecretHash(secret), version).Scan(&outcome); err != nil {
			t.Fatalf("version %q: %v", version, err)
		}
		if outcome != "invalid" {
			t.Errorf("version %q: outcome = %s, want invalid", version, outcome)
		}
	}
	if at, version := f.lastSeen(t, id); at != nil || version != nil {
		t.Errorf("honeypot reported at %v with version %v after versions of the wrong form", at, version)
	}
	if res, err := f.store.RecordHeartbeat(t.Context(), SecretHash(secret), Heartbeat{SensorVersion: strings.Repeat("1", 32)}); err != nil || res.Outcome != ReportRecorded {
		t.Errorf("a version of 32 characters: %+v, %v; want recorded", res, err)
	}
}

// waitForLockWait returns once a session of the test database waits for a lock.
func (f fixture) waitForLockWait(t *testing.T) {
	t.Helper()
	for {
		var waiting bool
		err := f.owner.QueryRow(t.Context(), `
SELECT EXISTS (
	SELECT FROM pg_stat_activity
	WHERE datname = current_database() AND wait_event_type = 'Lock'
)`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		if t.Context().Err() != nil {
			t.Fatal("no session waits for a lock")
		}
	}
}

// A secret that the console replaces while a report is being recorded does not
// reach the honeypot: the old secret stops working at once, and it cannot mark
// the honeypot as reported again after the replacement has cleared the report.
func TestStore_SecretReplacedWhileReportingIsNotAccepted(t *testing.T) {
	t.Parallel()

	for _, kind := range []string{"heartbeat", "session"} {
		f := newFixture(t)
		id, old := f.honeypot(t, enabled("ssh"))
		tx, err := f.owner.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), "UPDATE honeypots SET secret_hash = $2 WHERE id = $1", id, SecretHash(randomSecret(t))); err != nil {
			t.Fatal(err)
		}

		outcome := make(chan ReportResult, 1)
		go func() {
			var res ReportResult
			var err error
			if kind == "heartbeat" {
				res, err = f.store.RecordHeartbeat(t.Context(), SecretHash(old), Heartbeat{SensorVersion: "9.9"})
			} else {
				res, err = f.store.RecordSession(t.Context(), SecretHash(old), f.newSession(t))
			}
			if err != nil {
				t.Error(err)
			}
			outcome <- res
		}()
		f.waitForLockWait(t)
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}

		if res := <-outcome; res.Outcome != ReportUnknown {
			t.Errorf("%s with the old secret: outcome = %s, want unknown", kind, res.Outcome)
		}
		if at, version := f.lastSeen(t, id); at != nil || version != nil {
			t.Errorf("%s with the old secret: honeypot reported at %v with version %v, want no report", kind, at, version)
		}
		if n := f.count(t, "SELECT count(*) FROM events"); n != 0 {
			t.Errorf("%s with the old secret: %d events, want none", kind, n)
		}
	}
}

// The events of honeytokens have no session identifier, so the index that
// keeps a session from being stored twice holds the sessions only, not a NULL
// entry for every request of a honeytoken.
func TestSchema_SessionIndexCoversOnlySessions(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	var def string
	if err := f.owner.QueryRow(t.Context(), `SELECT pg_get_indexdef('public.events_sensor_session_key'::regclass)`).Scan(&def); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(def, "UNIQUE") || !strings.Contains(def, "WHERE (sensor_session_id IS NOT NULL)") {
		t.Errorf("index = %s, want a unique index of the sessions only", def)
	}
}

// A session keeps the names of its honeypot and of its scenario as they were
// when it ended, so that the incident can name what was triggered after the
// honeypot is renamed or deleted.
func TestStore_SessionFreezesTheNames(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	var sc string
	if err := f.owner.QueryRow(t.Context(), `INSERT INTO scenarios (name) VALUES ('Finance') RETURNING id`).Scan(&sc); err != nil {
		t.Fatal(err)
	}
	id, secret := f.honeypot(t, enabled("ssh"))
	if _, err := f.owner.Exec(t.Context(), `UPDATE honeypots SET name = 'Jump host', scenario_id = $2 WHERE id = $1`, id, sc); err != nil {
		t.Fatal(err)
	}
	f.session(t, secret, f.newSession(t))
	if _, err := f.owner.Exec(t.Context(), `UPDATE honeypots SET name = 'Renamed', scenario_id = NULL WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(t.Context(), `UPDATE scenarios SET name = 'Other' WHERE id = $1`, sc); err != nil {
		t.Fatal(err)
	}
	f.session(t, secret, f.newSession(t))

	if n := f.count(t, `SELECT count(*) FROM events WHERE resource_id = $1 AND resource_name = 'Jump host' AND scenario_name = 'Finance'`, id); n != 1 {
		t.Errorf("%d events with the names at the time of the session, want 1", n)
	}
	if n := f.count(t, `SELECT count(*) FROM events WHERE resource_id = $1 AND resource_name = 'Renamed' AND scenario_name IS NULL`, id); n != 1 {
		t.Errorf("%d events of the renamed honeypot without a scenario, want 1", n)
	}
}
