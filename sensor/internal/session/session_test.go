// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"bytes"
	"log/slog"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock/clocktest"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/secret"
	"nyktus.org/nyktus/sensor/internal/session"
)

const sampleSecret = "Abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"

var (
	honeypot = &session.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: "telnet", Secret: sampleSecret}
	remote   = netip.MustParseAddrPort("203.0.113.9:51000")
	local    = netip.MustParseAddrPort("10.0.0.5:2323")
)

func start(t *testing.T, clk *clocktest.Fake) *session.Session {
	t.Helper()
	s, err := session.Start(clk, honeypot, remote, local)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSession_Report_NamesTheAddressAndThePortTheAttackerReached(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	s := start(t, clk)
	clk.Advance(1500 * time.Millisecond)
	s.End()
	clk.Advance(500 * time.Millisecond)

	got, ok := s.Report(clk.Elapsed())
	if !ok {
		t.Fatal("Report() = not ok, want a report")
	}
	if got.Version != 2 || got.Type != "session" || got.ClientIP != "203.0.113.9" || got.Port != 2323 {
		t.Errorf("Report() = %+v, want version 2, type session, the client and the local port", got)
	}
	if got.AgeMS != 2000 || got.DurationMS != 1500 {
		t.Errorf("age = %d ms, duration = %d ms; want 2000 and 1500", got.AgeMS, got.DurationMS)
	}
	if got.Attempts == nil || len(got.Attempts) != 0 {
		t.Errorf("attempts = %#v, want an empty list that is not nil", got.Attempts)
	}
}

// The age counts from the beginning of the session, not from the start of the
// sensor, and the duration from the beginning to the end.
func TestSession_Report_MeasuresFromTheBeginningOfTheSession(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	clk.Advance(10 * time.Second)
	s := start(t, clk)
	clk.Advance(time.Second)
	s.End()
	clk.Advance(2 * time.Second)

	got, ok := s.Report(clk.Elapsed())
	if !ok || got.AgeMS != 3000 || got.DurationMS != 1000 {
		t.Errorf("Report() = %+v, %v; want an age of 3000 ms and a duration of 1000 ms", got, ok)
	}
}

func TestSession_ID_IsRandomHexadecimal(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	pattern := regexp.MustCompile(`^[0-9a-f]{32}$`)
	seen := map[string]bool{}
	for range 100 {
		id := start(t, clk).ID()
		if !pattern.MatchString(id) {
			t.Fatalf("ID() = %q, want 32 lowercase hexadecimal digits", id)
		}
		if seen[id] {
			t.Fatalf("ID() = %q twice", id)
		}
		seen[id] = true
	}
}

func TestSession_Report_AgeFollowsTheMonotonicClockNotTheWallClock(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	s := start(t, clk)
	s.End()
	// An operator or a time service sets the clock back by an hour while the
	// session waits for delivery.
	clk.SetWall(-time.Hour)
	clk.Advance(2 * time.Second)

	got, ok := s.Report(clk.Elapsed())
	if !ok || got.AgeMS != 2000 {
		t.Errorf("Report() = %+v, %v; want the age of 2000 ms that the monotonic clock measured", got, ok)
	}
}

func TestSession_Report_AgeGrowsWithEveryCall(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	s := start(t, clk)
	s.End()
	first, _ := s.Report(clk.Elapsed())
	clk.Advance(9 * time.Second)
	second, _ := s.Report(clk.Elapsed())
	if first.AgeMS != 0 || second.AgeMS != 9000 {
		t.Errorf("ages = %d, %d; want 0 and 9000: a repeated report is older by the pause", first.AgeMS, second.AgeMS)
	}
}

func TestSession_Report_OlderThanFiveMinutes_IsRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		age  time.Duration
		want bool
	}{
		{name: "exactly five minutes", age: 5 * time.Minute, want: true},
		{name: "one millisecond more", age: 5*time.Minute + time.Millisecond},
		{name: "an hour", age: time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			clk := clocktest.New()
			s := start(t, clk)
			s.End()
			clk.Advance(tt.age)
			got, ok := s.Report(clk.Elapsed())
			if ok != tt.want {
				t.Errorf("Report() = %+v, %v; want ok = %v", got, ok, tt.want)
			}
			if ok && got.AgeMS != 300000 {
				t.Errorf("age = %d ms, want 300000", got.AgeMS)
			}
		})
	}
}

func TestSession_Report_BeforeTheEnd_UsesTheTimeOfTheReport(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	s := start(t, clk)
	clk.Advance(3 * time.Second)
	got, ok := s.Report(clk.Elapsed())
	if !ok || got.DurationMS != 3000 {
		t.Errorf("Report() = %+v, %v; want a duration of 3000 ms", got, ok)
	}
}

func TestSession_End_Twice_KeepsTheFirstEnd(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	s := start(t, clk)
	clk.Advance(time.Second)
	s.End()
	clk.Advance(time.Minute)
	s.End()
	got, _ := s.Report(clk.Elapsed())
	if got.DurationMS != 1000 {
		t.Errorf("duration = %d ms, want 1000", got.DurationMS)
	}
}

func TestSession_EndAt_EndsAtTheGivenTime(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	s := start(t, clk)
	clk.Advance(time.Minute)
	s.EndAt(2 * time.Second)
	s.EndAt(5 * time.Second)
	got, _ := s.Report(clk.Elapsed())
	if got.DurationMS != 2000 {
		t.Errorf("duration = %d ms, want 2000, the first end", got.DurationMS)
	}
}

func TestSession_AddAttempt_KeepsAtMostSix(t *testing.T) {
	t.Parallel()

	s := start(t, clocktest.New())
	for i := range 6 {
		if !s.AddAttempt(report.Attempt{Username: "u"}) {
			t.Fatalf("AddAttempt() #%d = false, want true", i+1)
		}
	}
	if s.AddAttempt(report.Attempt{Username: "seventh"}) {
		t.Error("AddAttempt() #7 = true, want false")
	}
	if got := s.Attempts(); got != 6 {
		t.Errorf("Attempts() = %d, want 6", got)
	}
}

func TestSession_Report_IsACopy(t *testing.T) {
	t.Parallel()

	s := start(t, clocktest.New())
	s.AddAttempt(report.Attempt{Username: "root"})
	s.End()
	got, _ := s.Report(0)
	got.Attempts[0].Username = "changed"
	again, _ := s.Report(0)
	if again.Attempts[0].Username != "root" {
		t.Errorf("username = %q after the first report was changed, want root", again.Attempts[0].Username)
	}
}

func TestSession_Start_NormalizesTheClientAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		remote string
		want   string
	}{
		{name: "IPv4", remote: "203.0.113.9:1", want: "203.0.113.9"},
		{name: "IPv4 mapped into IPv6", remote: "[::ffff:203.0.113.9]:1", want: "203.0.113.9"},
		// The server refuses an address with a zone, and with it the report.
		{name: "link-local address with a zone", remote: "[fe80::1%eth0]:1", want: "fe80::1"},
		{name: "IPv6", remote: "[2001:db8::7]:1", want: "2001:db8::7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, err := session.Start(clocktest.New(), honeypot, netip.MustParseAddrPort(tt.remote), local)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := s.Report(0)
			if got.ClientIP != tt.want {
				t.Errorf("ClientIP = %q, want %q", got.ClientIP, tt.want)
			}
		})
	}
}

// What the attacker typed reaches no log: not through the session, not
// through the honeypot, and never the secret.
func TestSession_Logged_HoldsNoInputAndNoSecret(t *testing.T) {
	t.Parallel()

	s := start(t, clocktest.New())
	n := 14
	s.AddAttempt(report.Attempt{Username: "mallory-typed-this", PasswordLength: &n})
	var logged bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	logger.Info("test", s.Attr(), slog.Any("value", s), slog.Any("secret", secret.Secret(sampleSecret)))
	logger.Info("test", honeypot.Attr(), slog.Any("value", honeypot))

	out := logged.String()
	for _, forbidden := range []string{"mallory-typed-this", sampleSecret} {
		if strings.Contains(out, forbidden) {
			t.Errorf("log %s holds %q", out, forbidden)
		}
	}
	for _, want := range []string{honeypot.ID, `"service":"telnet"`, `"event_type":"login_attempt"`, `"attempts":1`} {
		if !strings.Contains(out, want) {
			t.Errorf("log %s lacks %s", out, want)
		}
	}
}

func TestSession_EventType(t *testing.T) {
	t.Parallel()

	s := start(t, clocktest.New())
	if got := s.EventType(); got != "connection" {
		t.Errorf("EventType() = %q before any login, want connection", got)
	}
	s.AddAttempt(report.Attempt{Username: "root"})
	if got := s.EventType(); got != "login_attempt" {
		t.Errorf("EventType() = %q after a login, want login_attempt", got)
	}
	s.SetQuery(report.Query{BaseDN: "", Filter: "(objectClass=*)"})
	if got := s.EventType(); got != "directory_query" {
		t.Errorf("EventType() = %q after a search, want directory_query", got)
	}
}

func TestSession_SetQuery_KeepsTheFirstSearchAndAnEmptyBase(t *testing.T) {
	t.Parallel()

	s := start(t, clocktest.New())
	if !s.SetQuery(report.Query{BaseDN: "", Filter: "(a=b)"}) {
		t.Fatal("SetQuery() = false for the first search")
	}
	if s.SetQuery(report.Query{BaseDN: "dc=example", Filter: "(c=d)"}) {
		t.Error("SetQuery() = true for a second search, want false")
	}
	s.End()
	got, _ := s.Report(0)
	if got.Query == nil || *got.Query != (report.Query{BaseDN: "", Filter: "(a=b)"}) {
		t.Errorf("Query = %+v, want the first search with the empty base", got.Query)
	}
	got.Query.Filter = "changed"
	again, _ := s.Report(0)
	if again.Query.Filter != "(a=b)" {
		t.Errorf("filter = %q after the first report was changed, want (a=b)", again.Query.Filter)
	}
}

func TestSession_SetStartup_IsInTheReport(t *testing.T) {
	t.Parallel()

	s := start(t, clocktest.New())
	s.SetStartup("app", "psql")
	s.End()
	got, _ := s.Report(0)
	if got.Database != "app" || got.ApplicationName != "psql" {
		t.Errorf("database = %q, application name = %q, want app and psql", got.Database, got.ApplicationName)
	}
}

// A tool call is the highest stage, and a session keeps its first six.
func TestSession_AddToolCall_KeepsAtMostSixAndIsTheHighestStage(t *testing.T) {
	t.Parallel()

	s := start(t, clocktest.New())
	for i := range 6 {
		if !s.AddToolCall(report.ToolCall{ToolName: "t", Arguments: strconv.Itoa(i)}) {
			t.Fatalf("call %d refused", i)
		}
	}
	if s.AddToolCall(report.ToolCall{ToolName: "seventh"}) {
		t.Error("a seventh call was kept")
	}
	if got := s.EventType(); got != "tool_call" {
		t.Errorf("EventType() = %q, want tool_call", got)
	}
	r, ok := s.Report(0)
	if !ok || len(r.ToolCalls) != 6 || r.ToolCalls[5].Arguments != "5" {
		t.Fatalf("report = %+v, want the first six", r)
	}
	r.ToolCalls[0].ToolName = "changed"
	if again, _ := s.Report(0); again.ToolCalls[0].ToolName != "t" {
		t.Error("the report shares its calls with the session")
	}
}

// A session without tool calls leaves the member out, as the server of the
// previous version does not know it.
func TestSession_WithoutToolCalls_HasNoMember(t *testing.T) {
	t.Parallel()

	r, _ := start(t, clocktest.New()).Report(0)
	if r.ToolCalls != nil {
		t.Errorf("tool calls = %v, want nil", r.ToolCalls)
	}
}
