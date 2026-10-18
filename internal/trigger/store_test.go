// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package trigger

import (
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/schematest"
)

// fixture holds a migrated database, a pool of the owner to set up and inspect
// rows, and a store that connects with the trigger's database role.
type fixture struct {
	owner *pgxpool.Pool
	store *Store
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ownerURL, triggerURL := schematest.Trigger(t)
	return fixture{owner: schematest.Open(t, ownerURL), store: NewStore(schematest.Open(t, triggerURL))}
}

// honeytoken creates a honeytoken with a new trigger value and returns its
// identifier and value.
func (f fixture) honeytoken(t *testing.T, typ string, enabled bool, redirect *string, techniques []string) (id, value string) {
	t.Helper()
	if techniques == nil {
		techniques = []string{}
	}
	err := f.owner.QueryRow(t.Context(), `
INSERT INTO honeytokens (type, name, enabled, redirect_url, techniques, severity, trigger_value)
VALUES ($1, 'h', $2, $3, $4, 'medium', translate(left(replace(gen_random_uuid()::text, '-', ''), 26), '0189', 'wxyz'))
RETURNING id, trigger_value`, typ, enabled, redirect, techniques).Scan(&id, &value)
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

func ptr(s string) *string { return &s }

// The trigger refuses to start with a login that can do more than record
// requests, or that cannot record them. db.CheckFunctionOnly covers every
// privilege; this test checks that the trigger names its own role and function.
func TestCheckPrivileges(t *testing.T) {
	t.Parallel()

	ownerURL, triggerURL := schematest.Trigger(t)
	if err := CheckPrivileges(t.Context(), schematest.Open(t, triggerURL)); err != nil {
		t.Errorf("CheckPrivileges(trigger) = %v, want nil", err)
	}

	_, consoleURL := dbtest.Role(t, ownerURL, "console", "IN ROLE "+pgx.Identifier{schematest.ConsoleRole}.Sanitize())
	if err := CheckPrivileges(t.Context(), schematest.Open(t, consoleURL)); !errors.Is(err, db.ErrRolePrivileges) || !strings.Contains(err.Error(), "cannot execute") {
		t.Errorf("CheckPrivileges(console) = %v, want ErrRolePrivileges containing %q", err, "cannot execute")
	}
}

func TestStore_RecordsARequestOfAnEnabledHoneytoken(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, value := f.honeytoken(t, "web_url", true, ptr("https://wiki.example.com/"), []string{"T1213", "T1083"})
	res, err := f.store.Record(t.Context(), Request{
		Value: value, Method: http.MethodGet, ClientIP: netip.MustParseAddr("2001:db8::7"),
		UserAgent: "curl/8.0", Referer: "https://intranet.example.com/", AcceptLanguage: "de",
	})
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if want := (Result{Outcome: OutcomeRecorded, HoneytokenID: id, RedirectURL: "https://wiki.example.com/"}); res != want {
		t.Errorf("Record() = %+v, want %+v", res, want)
	}

	var (
		resourceType, typ, method, userAgent, referer, acceptLanguage string
		resourceID                                                    string
		techniques                                                    []string
		ip                                                            netip.Addr
		jobs                                                          int
	)
	err = f.owner.QueryRow(t.Context(), `
SELECT e.resource_type, e.resource_id, e.honeytoken_type, e.techniques, e.client_ip, e.method, e.user_agent, e.referer,
	e.accept_language, (SELECT count(*) FROM event_jobs AS j WHERE j.event_id = e.id)
FROM events AS e`).Scan(&resourceType, &resourceID, &typ, &techniques, &ip, &method, &userAgent, &referer, &acceptLanguage, &jobs)
	if err != nil {
		t.Fatalf("read event: %v", err)
	}
	if resourceType != "honeytoken" || resourceID != id || typ != "web_url" || !slices.Equal(techniques, []string{"T1213", "T1083"}) ||
		ip != netip.MustParseAddr("2001:db8::7") || method != "GET" || userAgent != "curl/8.0" ||
		referer != "https://intranet.example.com/" || acceptLanguage != "de" || jobs != 1 {
		t.Errorf("event = %s %s %s %v %v %s %q %q %q, %d jobs", resourceType, resourceID, typ, techniques, ip, method,
			userAgent, referer, acceptLanguage, jobs)
	}
}

func TestStore_UnknownAndDisabledValuesAreNotRecorded(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	res, err := f.store.Record(t.Context(), Request{Value: strings.Repeat("a", 26), Method: http.MethodGet})
	if err != nil || res != (Result{Outcome: OutcomeUnknown}) {
		t.Errorf("Record(unknown) = %+v, %v; want unknown", res, err)
	}

	// A disabled honeytoken keeps redirecting to its target, so that disabling
	// it changes nothing that a client sees.
	id, value := f.honeytoken(t, "web_url", false, ptr("https://wiki.example.com/"), nil)
	res, err = f.store.Record(t.Context(), Request{Value: value, Method: http.MethodGet})
	if want := (Result{Outcome: OutcomeDisabled, HoneytokenID: id, RedirectURL: "https://wiki.example.com/"}); err != nil || res != want {
		t.Errorf("Record(disabled) = %+v, %v; want %+v", res, err, want)
	}

	if n := f.count(t, "SELECT count(*) FROM events"); n != 0 {
		t.Errorf("%d events, want none", n)
	}
}

// A flood of requests for one known value must not fill the database. Beyond
// the limit, requests are reported as limited, without an event.
func TestStore_LimitsEventsPerHoneytokenAndMinute(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, value := f.honeytoken(t, "web_image", true, nil, nil)
	_, other := f.honeytoken(t, "web_image", true, nil, nil)
	for i := range 12 {
		res, err := f.store.Record(t.Context(), Request{Value: value, Method: http.MethodGet})
		want := OutcomeRecorded
		if i >= 10 {
			want = OutcomeLimited
		}
		if err != nil || res.Outcome != want || res.HoneytokenID != id {
			t.Errorf("request %d: Record() = %+v, %v; want %s", i, res, err, want)
		}
	}
	// The limit applies per honeytoken.
	if res, err := f.store.Record(t.Context(), Request{Value: other, Method: http.MethodGet}); err != nil || res.Outcome != OutcomeRecorded {
		t.Errorf("Record(other) = %+v, %v; want recorded", res, err)
	}

	// Events older than a minute no longer count.
	if _, err := f.owner.Exec(t.Context(), "UPDATE events SET occurred_at = occurred_at - interval '61 seconds', recorded_at = recorded_at - interval '61 seconds'"); err != nil {
		t.Fatal(err)
	}
	if res, err := f.store.Record(t.Context(), Request{Value: value, Method: http.MethodHead}); err != nil || res.Outcome != OutcomeRecorded {
		t.Errorf("Record() after a minute = %+v, %v; want recorded", res, err)
	}
	if n := f.count(t, "SELECT count(*) FROM events WHERE resource_id = $1", id); n != 11 {
		t.Errorf("%d events, want 11", n)
	}
}

// The window of the limit must seek into the index, including in the generic
// plan that PostgreSQL may switch to for the statement in the function.
func TestStore_LimitUsesTheIndex(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	conn, err := f.owner.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(t.Context(), "SET plan_cache_mode = force_generic_plan"); err != nil {
		t.Fatal(err)
	}
	// The statement as the function runs it, with the identifier as a
	// parameter.
	if _, err := conn.Exec(t.Context(), `
PREPARE recent (uuid) AS
SELECT count(*) FROM (
	SELECT FROM public.events AS e
	WHERE e.resource_id = $1
		AND e.resource_type = 'honeytoken'
		AND e.recorded_at >= statement_timestamp() - interval '1 minute'
	LIMIT 10
) AS recent`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(t.Context(), "SET enable_seqscan = off"); err != nil {
		t.Fatal(err)
	}
	rows, err := conn.Query(t.Context(), "EXPLAIN EXECUTE recent (gen_random_uuid())")
	if err != nil {
		t.Fatal(err)
	}
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), "Index Cond: ((resource_id = $1) AND (recorded_at >= (statement_timestamp()") {
		t.Errorf("plan does not seek into the index by honeytoken and time:\n%s", plan.String())
	}
}

// An event is never stored without the job that processes it: if the job
// cannot be written, the event is not written either.
func TestStore_EventIsNeverStoredWithoutItsJob(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, value := f.honeytoken(t, "web_url", true, nil, nil)
	if _, err := f.store.Record(t.Context(), Request{Value: value, Method: http.MethodGet}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if _, err := f.owner.Exec(t.Context(), "ALTER TABLE event_jobs ADD CONSTRAINT event_jobs_reject CHECK (false) NOT VALID"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Record(t.Context(), Request{Value: value, Method: http.MethodGet}); err == nil {
		t.Fatal("Record() succeeded although the job could not be written")
	}

	if n := f.count(t, "SELECT count(*) FROM events"); n != 1 {
		t.Errorf("%d events, want only the one with a job", n)
	}
	if n := f.count(t, "SELECT count(*) FROM events AS e WHERE NOT EXISTS (SELECT FROM event_jobs AS j WHERE j.event_id = e.id)"); n != 0 {
		t.Errorf("%d events without a job", n)
	}
}

// Events are evidence: they keep the type and the techniques of the honeytoken
// as it was when it was requested, and outlive its deletion.
func TestStore_EventsOutliveChangesAndDeletion(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, value := f.honeytoken(t, "web_url", true, nil, []string{"T1213"})
	if _, err := f.store.Record(t.Context(), Request{Value: value, Method: http.MethodGet}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if _, err := f.owner.Exec(t.Context(), "UPDATE honeytokens SET techniques = '{T1083}' WHERE id = $1", id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(t.Context(), "DELETE FROM honeytokens WHERE id = $1", id); err != nil {
		t.Fatalf("delete honeytoken with events: %v", err)
	}
	if n := f.count(t, "SELECT count(*) FROM events WHERE resource_id = $1 AND techniques = '{T1213}' AND honeytoken_type = 'web_url'", id); n != 1 {
		t.Errorf("%d events with the techniques at the time of the request, want 1", n)
	}
}

// The schema accepts what the handler produces from the worst headers a client
// can send: the longest values, made of characters that the handler replaces.
func TestStore_AcceptsWhatTheHandlerProduces(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, value := f.honeytoken(t, "web_url", true, nil, nil)
	// The characters that the schema refuses by name, one of each group.
	refused := string([]rune{0x85, 0xad, 0x61c, 0x180e, 0x200b, 0x2028, 0x202e, 0x2066, 0xfeff, 0xfff9, 0xe0041})
	worst := strings.Repeat("\x01\xff\u00e4\U0001F600a"+refused, 1000)
	res, err := f.store.Record(t.Context(), Request{
		Value: value, Method: http.MethodHead,
		UserAgent:      untrusted(worst, maxUserAgentBytes),
		Referer:        untrusted(worst, maxRefererBytes),
		AcceptLanguage: untrusted(worst, maxAcceptLanguageBytes),
	})
	if err != nil || res.Outcome != OutcomeRecorded {
		t.Errorf("Record() = %+v, %v; want recorded", res, err)
	}
	if n := f.count(t, "SELECT count(*) FROM events WHERE client_ip IS NULL"); n != 1 {
		t.Errorf("%d events without an address, want 1", n)
	}
}

// The invariant over the real database role: a client cannot tell an enabled
// honeytoken from an unknown, disabled or failing one, or from one of another
// type, by status, headers or body.
func TestTrigger_IdenticalResponsesWithTheDatabase(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, enabledURL := f.honeytoken(t, "web_url", true, nil, nil)
	_, disabledURL := f.honeytoken(t, "web_url", false, nil, nil)
	_, enabledImage := f.honeytoken(t, "web_image", true, nil, nil)
	_, disabledImage := f.honeytoken(t, "web_image", false, nil, nil)

	srv, _ := newServer(t, f.store)
	closed := schematest.Open(t, schematest.New(t))
	closed.Close()
	failing, _ := newServer(t, NewStore(closed))

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, suffix := range []string{"", ".gif"} {
			want := fetch(t, srv, method, "/"+strings.Repeat("a", 26)+suffix, nil, nil)
			for name, got := range map[string]response{
				"enabled url":         fetch(t, srv, method, "/"+enabledURL+suffix, nil, nil),
				"disabled url":        fetch(t, srv, method, "/"+disabledURL+suffix, nil, nil),
				"enabled image":       fetch(t, srv, method, "/"+enabledImage+suffix, nil, nil),
				"disabled image":      fetch(t, srv, method, "/"+disabledImage+suffix, nil, nil),
				"database failure":    fetch(t, failing, method, "/"+enabledURL+suffix, nil, nil),
				"no value in the URL": fetch(t, srv, method, "/favicon.ico"+suffix, nil, nil),
			} {
				if !got.equal(want) {
					t.Errorf("%s %q, %s: response %+v, want %+v", method, suffix, name, got, want)
				}
			}
		}
	}
	// Requests of enabled honeytokens are recorded whatever the form of the URL.
	if n := f.count(t, "SELECT count(*) FROM events"); n != 8 {
		t.Errorf("%d events, want 8", n)
	}
}

// An event keeps the scenario that its honeytoken belonged to when it was
// requested, or none, so that the worker correlates it by that scenario even
// if the honeytoken changes its scenario before the event is processed.
func TestStore_EventFreezesTheScenario(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, value := f.honeytoken(t, "web_url", true, nil, nil)
	var first, second string
	if err := f.owner.QueryRow(t.Context(), `INSERT INTO scenarios (name) VALUES ('a') RETURNING id`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if err := f.owner.QueryRow(t.Context(), `INSERT INTO scenarios (name) VALUES ('b') RETURNING id`).Scan(&second); err != nil {
		t.Fatal(err)
	}
	record := func(scenarioID *string) {
		t.Helper()
		if _, err := f.owner.Exec(t.Context(), `UPDATE honeytokens SET scenario_id = $2 WHERE id = $1`, id, scenarioID); err != nil {
			t.Fatal(err)
		}
		if res, err := f.store.Record(t.Context(), Request{Value: value, Method: http.MethodGet}); err != nil || res.Outcome != OutcomeRecorded {
			t.Fatalf("Record() = %+v, %v", res, err)
		}
	}
	record(nil)
	record(&first)
	record(&second)
	if _, err := f.owner.Exec(t.Context(), `UPDATE honeytokens SET scenario_id = NULL WHERE id = $1`, id); err != nil {
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
	if want := []string{"", first, second}; !slices.Equal(got, want) {
		t.Errorf("scenarios of the events = %v, want %v", got, want)
	}
}
