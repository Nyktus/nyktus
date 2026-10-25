// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dns

import (
	"bytes"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/miekg/dns"

	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/schematest"
)

// fixture holds a migrated database, a pool of the owner to set up and inspect
// rows, and a store that connects with the DNS role's database role.
type fixture struct {
	owner *pgxpool.Pool
	store *Store
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ownerURL, dnsURL := schematest.DNS(t)
	return fixture{owner: schematest.Open(t, ownerURL), store: NewStore(schematest.Open(t, dnsURL))}
}

// honeytoken creates a honeytoken with a new trigger value and returns its
// identifier and value.
func (f fixture) honeytoken(t *testing.T, typ string, enabled bool, techniques []string) (id, value string) {
	t.Helper()
	if techniques == nil {
		techniques = []string{}
	}
	err := f.owner.QueryRow(t.Context(), `
INSERT INTO honeytokens (type, name, enabled, techniques, severity, trigger_value)
VALUES ($1, 'h', $2, $3, 'medium', translate(left(replace(gen_random_uuid()::text, '-', ''), 26), '0189', 'wxyz'))
RETURNING id, trigger_value`, typ, enabled, techniques).Scan(&id, &value)
	if err != nil {
		t.Fatalf("create honeytoken: %v", err)
	}
	if !isTriggerValue(value) {
		t.Fatalf("created trigger value %q is not one", value)
	}
	return id, value
}

func (f fixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := f.owner.QueryRow(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func dnsQuery(v string) Query {
	return Query{Value: v, Zone: zone, Prefix: "", QType: "A", Transport: "udp", Resolver: netip.MustParseAddr("198.51.100.53")}
}

// The DNS role refuses to start with a login that can do more than record
// queries, or that cannot record them. db.CheckFunctionOnly covers every
// privilege; this test checks that the DNS role names its own role and
// function.
func TestCheckPrivileges(t *testing.T) {
	t.Parallel()

	ownerURL, dnsURL := schematest.DNS(t)
	if err := CheckPrivileges(t.Context(), schematest.Open(t, dnsURL)); err != nil {
		t.Errorf("CheckPrivileges(dns) = %v, want nil", err)
	}
	for _, role := range []string{schematest.ConsoleRole, schematest.TriggerRole} {
		_, roleURL := dbtest.Role(t, ownerURL, role, "IN ROLE "+pgx.Identifier{role}.Sanitize())
		if err := CheckPrivileges(t.Context(), schematest.Open(t, roleURL)); !errors.Is(err, db.ErrRolePrivileges) || !strings.Contains(err.Error(), "cannot execute public.record_dns_query(") {
			t.Errorf("CheckPrivileges(%s) = %v, want ErrRolePrivileges for record_dns_query", role, err)
		}
	}
}

func TestStore_RecordsAQueryOfAnEnabledHoneytoken(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, v := f.honeytoken(t, "dns", true, []string{"T1046"})
	q := Query{Value: v, Zone: "e.example.org", Prefix: "vpn.db?1", QType: "TYPE65280", Transport: "tcp", Resolver: netip.MustParseAddr("2001:db8::53")}
	res, err := f.store.Record(t.Context(), q)
	if err != nil || res.Outcome != OutcomeRecorded || res.HoneytokenID != id {
		t.Fatalf("Record() = %+v, %v; want recorded for %s", res, err, id)
	}
	n := f.count(t, `
SELECT count(*) FROM events AS e JOIN event_jobs AS j ON j.event_id = e.id
WHERE e.resource_type = 'honeytoken' AND e.resource_id = $1 AND e.honeytoken_type = 'dns'
	AND e.techniques = '{T1046}' AND e.channel = 'dns' AND e.client_ip = '2001:db8::53'
	AND e.dns_zone = 'e.example.org' AND e.dns_prefix = 'vpn.db?1' AND e.dns_qtype = 'TYPE65280'
	AND e.dns_transport = 'tcp' AND e.method IS NULL AND e.user_agent = ''`, id)
	if n != 1 {
		t.Errorf("%d matching events with a job, want 1", n)
	}
}

// Every type of honeytoken records its DNS queries: only whoever found a value
// knows it, whatever the type.
func TestStore_RecordsQueriesOfEveryType(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	for _, typ := range []string{"web_url", "web_image", "dns"} {
		id, v := f.honeytoken(t, typ, true, nil)
		if res, err := f.store.Record(t.Context(), dnsQuery(v)); err != nil || res.Outcome != OutcomeRecorded || res.HoneytokenID != id {
			t.Errorf("%s: Record() = %+v, %v; want recorded", typ, res, err)
		}
	}
}

func TestStore_UnknownAndDisabledValuesAreNotRecorded(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, disabled := f.honeytoken(t, "dns", false, nil)
	if res, err := f.store.Record(t.Context(), dnsQuery(disabled)); err != nil || res.Outcome != OutcomeDisabled || res.HoneytokenID != id {
		t.Errorf("Record(disabled) = %+v, %v; want disabled", res, err)
	}
	if res, err := f.store.Record(t.Context(), dnsQuery(strings.Repeat("a", 26))); err != nil || res.Outcome != OutcomeUnknown || res.HoneytokenID != "" {
		t.Errorf("Record(unknown) = %+v, %v; want unknown", res, err)
	}
	if n := f.count(t, "SELECT count(*) FROM events"); n != 0 {
		t.Errorf("%d events, want none", n)
	}
}

// The limit of events per honeytoken and minute counts HTTP requests and DNS
// queries together, so that a flood over one channel cannot add to a flood over
// the other.
func TestStore_SharesTheLimitWithHTTP(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, v := f.honeytoken(t, "dns", true, nil)
	for range 6 {
		var outcome string
		err := f.owner.QueryRow(t.Context(),
			"SELECT outcome FROM public.record_honeytoken_request($1, 'GET', NULL, '', '', '', '')", v).Scan(&outcome)
		if err != nil || outcome != "recorded" {
			t.Fatalf("HTTP request = %q, %v; want recorded", outcome, err)
		}
	}
	for i := range 6 {
		want := OutcomeRecorded
		if i >= 4 {
			want = OutcomeLimited
		}
		if res, err := f.store.Record(t.Context(), dnsQuery(v)); err != nil || res.Outcome != want || res.HoneytokenID != id {
			t.Errorf("query %d: Record() = %+v, %v; want %s", i, res, err, want)
		}
	}
	if n := f.count(t, "SELECT count(*) FROM events WHERE resource_id = $1", id); n != 10 {
		t.Errorf("%d events, want 10", n)
	}
}

// An event is never stored without the job that processes it: if the job
// cannot be written, the event is not written either.
func TestStore_EventIsNeverStoredWithoutItsJob(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, v := f.honeytoken(t, "dns", true, nil)
	if _, err := f.store.Record(t.Context(), dnsQuery(v)); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if _, err := f.owner.Exec(t.Context(), "ALTER TABLE event_jobs ADD CONSTRAINT event_jobs_reject CHECK (false) NOT VALID"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Record(t.Context(), dnsQuery(v)); err == nil {
		t.Fatal("Record() succeeded although the job could not be written")
	}
	if n := f.count(t, "SELECT count(*) FROM events"); n != 1 {
		t.Errorf("%d events, want only the one with a job", n)
	}
	if n := f.count(t, "SELECT count(*) FROM events AS e WHERE NOT EXISTS (SELECT FROM event_jobs AS j WHERE j.event_id = e.id)"); n != 0 {
		t.Errorf("%d events without a job", n)
	}
}

// The schema accepts what the handler produces from the worst names a client
// can send: the longest prefix of replaced characters, every type of query and
// an unknown resolver.
func TestStore_AcceptsWhatTheHandlerProduces(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, v := f.honeytoken(t, "dns", true, nil)
	label := strings.Repeat(`\000`, 63)
	prefix := prefixOf([]string{label, label, label, label})
	if len(prefix) != maxPrefixLength {
		t.Fatalf("prefix of %d bytes, want the longest", len(prefix))
	}
	h := New(testOptions(f.store))
	zoneName := strings.Repeat(strings.Repeat("z", 63)+".", 3) + "example1"
	for _, tt := range []Query{
		{Value: v, Zone: zoneName, Prefix: prefix, QType: qtypeName(0), Transport: "udp"},
		{Value: v, Zone: zone, Prefix: prefix, QType: qtypeName(dns.TypeNSAPPTR), Transport: "tcp"},
		{Value: v, Zone: zone, Prefix: "", QType: qtypeName(65535), Transport: "udp"},
	} {
		if res, err := h.recorder.Record(t.Context(), tt); err != nil || res.Outcome != OutcomeRecorded {
			t.Errorf("Record(%+v) = %+v, %v; want recorded", tt, res, err)
		}
	}
	if n := f.count(t, "SELECT count(*) FROM events WHERE client_ip IS NULL"); n != 3 {
		t.Errorf("%d events without an address, want 3", n)
	}
}

// The invariant over the real database role: a client cannot tell an enabled
// DNS honeytoken from an unknown, disabled or failing one, or from a value of
// another type, by any part of the answer.
func TestDNS_IdenticalAnswersWithTheDatabase(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, enabled := f.honeytoken(t, "dns", true, nil)
	_, disabled := f.honeytoken(t, "dns", false, nil)
	_, url := f.honeytoken(t, "web_url", true, nil)

	var logs syncBuffer
	o := testOptions(f.store)
	o.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	s := startServer(t, o)
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(logs.String())
		}
	})
	closed := schematest.Open(t, schematest.New(t))
	closed.Close()
	failing := startServer(t, testOptions(NewStore(closed)))

	for _, network := range []string{"udp", "tcp"} {
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeANY} {
			ask := func(srv server, v string) []byte {
				name := v + "." + zone + "."
				return normalized(t, exchange(t, srv, network, question(name, qtype)), name)
			}
			want := ask(s, strings.Repeat("a", 26))
			for name, got := range map[string][]byte{
				"enabled":          ask(s, enabled),
				"disabled":         ask(s, disabled),
				"other type":       ask(s, url),
				"database failure": ask(failing, enabled),
			} {
				if !bytes.Equal(got, want) {
					t.Errorf("%s %s, %s: answer differs from an unknown value", network, dns.TypeToString[qtype], name)
				}
			}
		}
	}
	s.stop()
	if n := f.count(t, "SELECT count(*) FROM events WHERE channel = 'dns'"); n != 16 {
		t.Errorf("%d events, want 16: two networks, four types and two enabled values", n)
	}
}

// The event keeps the time the query arrived, from how long it waited, within
// the five minutes that the database accepts: a negative delay counts as none,
// a longer one as five minutes.
func TestStore_KeepsTheTimeOfReceiptWithinTheWindow(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	for _, tt := range []struct {
		name      string
		received  time.Duration // before now; negative is in the future
		wantDelay time.Duration // how long before writing the event occurred
	}{
		{"now", 0, 0},
		{"four minutes ago", 4 * time.Minute, 4 * time.Minute},
		{"negative delay", -time.Hour, 0},
		{"ten minutes ago", 10 * time.Minute, 5 * time.Minute},
	} {
		id, v := f.honeytoken(t, "dns", true, nil)
		q := dnsQuery(v)
		q.ReceivedAt = time.Now().Add(-tt.received)
		if res, err := f.store.Record(t.Context(), q); err != nil || res.Outcome != OutcomeRecorded {
			t.Fatalf("%s: Record() = %+v, %v", tt.name, res, err)
		}
		var delay time.Duration
		if err := f.owner.QueryRow(t.Context(), "SELECT recorded_at - occurred_at FROM events WHERE resource_id = $1", id).Scan(&delay); err != nil {
			t.Fatal(err)
		}
		if diff := delay - tt.wantDelay; diff < -2*time.Second || diff > 2*time.Second {
			t.Errorf("%s: event occurred %v before it was written, want about %v", tt.name, delay, tt.wantDelay)
		}
	}
}

// The limit counts the time of writing, which the DNS role cannot choose:
// events that claim to have occurred minutes ago still count.
func TestStore_LimitCountsTheTimeOfWriting(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, v := f.honeytoken(t, "dns", true, nil)
	q := dnsQuery(v)
	q.ReceivedAt = time.Now().Add(-4 * time.Minute)
	for i := range 11 {
		want := OutcomeRecorded
		if i >= 10 {
			want = OutcomeLimited
		}
		if res, err := f.store.Record(t.Context(), q); err != nil || res.Outcome != want {
			t.Errorf("query %d: Record() = %+v, %v; want %s", i, res, err, want)
		}
	}
}

// An event keeps the scenario that its honeytoken belonged to when it was
// queried, or none, so that the worker correlates it by that scenario even if
// the honeytoken changes its scenario before the event is processed.
func TestStore_EventFreezesTheScenario(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, v := f.honeytoken(t, "dns", true, nil)
	var sc string
	if err := f.owner.QueryRow(t.Context(), `INSERT INTO scenarios (name) VALUES ('a') RETURNING id`).Scan(&sc); err != nil {
		t.Fatal(err)
	}
	if res, err := f.store.Record(t.Context(), dnsQuery(v)); err != nil || res.Outcome != OutcomeRecorded {
		t.Fatalf("Record() alone = %+v, %v", res, err)
	}
	if _, err := f.owner.Exec(t.Context(), `UPDATE honeytokens SET scenario_id = $2 WHERE id = $1`, id, sc); err != nil {
		t.Fatal(err)
	}
	if res, err := f.store.Record(t.Context(), dnsQuery(v)); err != nil || res.Outcome != OutcomeRecorded {
		t.Fatalf("Record() in the scenario = %+v, %v", res, err)
	}
	if _, err := f.owner.Exec(t.Context(), `UPDATE honeytokens SET scenario_id = NULL WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}

	if n := f.count(t, `SELECT count(*) FROM events WHERE resource_id = $1 AND scenario_id IS NULL`, id); n != 1 {
		t.Errorf("%d events without a scenario, want 1", n)
	}
	if n := f.count(t, `SELECT count(*) FROM events WHERE resource_id = $1 AND scenario_id = $2`, id, sc); n != 1 {
		t.Errorf("%d events in the scenario, want 1", n)
	}
}

// An event keeps the names of its honeytoken and of its scenario as they were
// when it was queried, so that the incident can name what was triggered after
// the honeytoken is renamed or deleted.
func TestStore_EventFreezesTheNames(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, v := f.honeytoken(t, "dns", true, nil)
	var sc string
	if err := f.owner.QueryRow(t.Context(), `INSERT INTO scenarios (name) VALUES ('Finance') RETURNING id`).Scan(&sc); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(t.Context(), `UPDATE honeytokens SET name = 'Wiki', scenario_id = $2 WHERE id = $1`, id, sc); err != nil {
		t.Fatal(err)
	}
	if res, err := f.store.Record(t.Context(), dnsQuery(v)); err != nil || res.Outcome != OutcomeRecorded {
		t.Fatalf("Record() in the scenario = %+v, %v", res, err)
	}
	if _, err := f.owner.Exec(t.Context(), `UPDATE honeytokens SET name = 'Renamed', scenario_id = NULL WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(t.Context(), `UPDATE scenarios SET name = 'Other' WHERE id = $1`, sc); err != nil {
		t.Fatal(err)
	}
	if res, err := f.store.Record(t.Context(), dnsQuery(v)); err != nil || res.Outcome != OutcomeRecorded {
		t.Fatalf("Record() alone = %+v, %v", res, err)
	}

	if n := f.count(t, `SELECT count(*) FROM events WHERE resource_id = $1 AND resource_name = 'Wiki' AND scenario_name = 'Finance'`, id); n != 1 {
		t.Errorf("%d events with the names at the time of the query, want 1", n)
	}
	if n := f.count(t, `SELECT count(*) FROM events WHERE resource_id = $1 AND resource_name = 'Renamed' AND scenario_name IS NULL`, id); n != 1 {
		t.Errorf("%d events of the renamed honeytoken without a scenario, want 1", n)
	}
}
