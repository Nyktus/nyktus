// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package reporter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock/clocktest"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/reporter"
	"nyktus.org/nyktus/sensor/internal/secret"
	"nyktus.org/nyktus/sensor/internal/session"
)

const (
	secretOne = "Abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"
	secretTwo = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

var honeypotOne = &session.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: "telnet", Secret: secret.Secret(secretOne)}

// request is what the trigger received.
type request struct {
	method        string
	path          string
	authorization string
	contentType   string
	body          []byte
}

// transport is a client transport that records the requests and fails the
// first ones.
type transport struct {
	mu        sync.Mutex
	requests  []request
	failFirst int
	status    int
	// notify, if set, receives a value for every request.
	notify chan struct{}
}

func (tr *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	if tr.notify != nil {
		defer func() { tr.notify <- struct{}{} }()
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.requests = append(tr.requests, request{
		method:        r.Method,
		path:          r.URL.Path,
		authorization: r.Header.Get("Authorization"),
		contentType:   r.Header.Get("Content-Type"),
		body:          body,
	})
	if len(tr.requests) <= tr.failFirst {
		return nil, errors.New("connection refused")
	}
	status := tr.status
	if status == 0 {
		status = http.StatusFound
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: r}, nil
}

func (tr *transport) calls() []request {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return append([]request(nil), tr.requests...)
}

func (tr *transport) client() *http.Client {
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type fixture struct {
	t     *testing.T
	clock *clocktest.Fake
	tr    *transport
	logs  *bytes.Buffer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{t: t, clock: clocktest.New(), tr: &transport{}, logs: &bytes.Buffer{}}
}

func (f *fixture) reporter(opts reporter.Options) *reporter.Reporter {
	f.t.Helper()
	opts.URL = "https://trigger.example.com/"
	opts.Clock = f.clock
	opts.Logger = slog.New(slog.NewJSONHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if opts.Client == nil {
		opts.Client = f.tr.client()
	}
	return reporter.New(opts)
}

// session returns a finished session of the first honeypot that began at the
// current time.
func (f *fixture) session(username string) *session.Session {
	f.t.Helper()
	s, err := session.Start(f.clock, honeypotOne, netip.MustParseAddrPort("203.0.113.9:51000"), netip.MustParseAddrPort("10.0.0.5:23"))
	if err != nil {
		f.t.Fatal(err)
	}
	n := 7
	s.AddAttempt(report.Attempt{Username: username, PasswordLength: &n})
	s.End()
	return s
}

func shutdown(t *testing.T, r *reporter.Reporter) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	r.Shutdown(ctx)
}

func ageOf(t *testing.T, req request) int64 {
	t.Helper()
	var s report.Session
	if err := json.Unmarshal(req.body, &s); err != nil {
		t.Fatal(err)
	}
	return s.AgeMS
}

func TestReporter_Session_IsPostedWithTheSecretAsBearer(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	r := f.reporter(reporter.Options{})
	r.Start()
	r.Submit(f.session("root"))
	shutdown(t, r)

	calls := f.tr.calls()
	if len(calls) != 1 {
		t.Fatalf("%d requests, want 1", len(calls))
	}
	got := calls[0]
	if got.method != http.MethodPost || got.path != "/" || got.authorization != "Bearer "+secretOne || got.contentType != "application/json" {
		t.Errorf("request = %+v, want POST / with the secret as bearer and JSON", got)
	}
	// The sensor names neither the service nor the severity, techniques or
	// kind of event, and sends no password.
	var members map[string]any
	if err := json.Unmarshal(got.body, &members); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"service", "severity", "techniques", "event_type", "type_of_event"} {
		if _, ok := members[key]; ok {
			t.Errorf("report names %s, want only what the sensor saw", key)
		}
	}
	var s report.Session
	if err := json.Unmarshal(got.body, &s); err != nil {
		t.Fatal(err)
	}
	if s.Version != 2 || s.Type != "session" || s.ClientIP != "203.0.113.9" || s.Port != 23 ||
		len(s.Attempts) != 1 || s.Attempts[0].Username != "root" || s.Attempts[0].PasswordLength == nil || *s.Attempts[0].PasswordLength != 7 {
		t.Errorf("report = %+v, want the session that was queued", s)
	}
	if st := r.TakeStats(); st.Sent != 1 {
		t.Errorf("Sent = %d, want 1", st.Sent)
	}
}

// What an attacker types is sent as it is: written as an HTML encoder does, six
// calls would be larger than the trigger reads and the session would be lost.
func TestReporter_Session_IsSentWithoutHTMLEscapes(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	r := f.reporter(reporter.Options{})
	r.Start()
	s := f.session("<&>")
	for range report.MaxToolCalls {
		s.AddToolCall(report.ToolCall{ToolName: "<t>", Arguments: strings.Repeat("<", report.MaxToolArguments)})
	}
	r.Submit(s)
	shutdown(t, r)

	calls := f.tr.calls()
	if len(calls) != 1 {
		t.Fatalf("%d requests, want 1", len(calls))
	}
	if body := calls[0].body; len(body) > report.MaxBody || !bytes.Contains(body, []byte(`"username":"<&>"`)) {
		t.Errorf("body of %d bytes: %.120s", len(body), body)
	}
}

func TestReporter_TransportFailure_RepeatsThreeTimesWithGrowingPauses(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.tr.failFirst = 1000
	r := f.reporter(reporter.Options{})
	r.Start()
	r.Submit(f.session("root"))

	// 1 s, 3 s and 9 s of pause, and the clock is the only thing that
	// moves them.
	for i, pause := range []time.Duration{time.Second, 3 * time.Second, 9 * time.Second} {
		f.clock.BlockUntil(1)
		if got := len(f.tr.calls()); got != i+1 {
			t.Fatalf("%d requests before pause %d, want %d", got, i+1, i+1)
		}
		f.clock.Advance(pause - time.Nanosecond)
		if f.clock.Pending() != 1 {
			t.Fatalf("pause %d ended before %v", i+1, pause)
		}
		f.clock.Advance(time.Nanosecond)
	}
	shutdown(t, r)

	if got := len(f.tr.calls()); got != 4 {
		t.Errorf("%d requests, want the first and three repetitions", got)
	}
	if st := r.TakeStats(); st.Failed != 1 || st.Sent != 0 {
		t.Errorf("stats = %+v, want one session that failed", st)
	}
}

// A repeated report is as much older as the pause before it.
func TestReporter_Repetition_ReportsTheGrownAge(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.tr.failFirst = 2
	r := f.reporter(reporter.Options{})
	r.Start()
	r.Submit(f.session("root"))

	f.clock.BlockUntil(1)
	f.clock.Advance(time.Second)
	f.clock.BlockUntil(1)
	f.clock.Advance(3 * time.Second)
	shutdown(t, r)

	calls := f.tr.calls()
	if len(calls) != 3 {
		t.Fatalf("%d requests, want 3", len(calls))
	}
	for i, want := range []int64{0, 1000, 4000} {
		if got := ageOf(t, calls[i]); got != want {
			t.Errorf("age of request %d = %d ms, want %d", i+1, got, want)
		}
	}
	if st := r.TakeStats(); st.Sent != 1 || st.Failed != 0 {
		t.Errorf("stats = %+v, want the session delivered", st)
	}
}

// The trigger answers every report alike, so whatever it answers, the report
// was delivered.
func TestReporter_AnyAnswer_IsNotRepeated(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusOK, http.StatusFound, http.StatusNotFound, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusNotImplemented} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.tr.status = status
			r := f.reporter(reporter.Options{})
			r.Start()
			r.Submit(f.session("root"))
			shutdown(t, r)

			if got := len(f.tr.calls()); got != 1 {
				t.Errorf("%d requests after the answer %d, want 1", got, status)
			}
			if st := r.TakeStats(); st.Sent != 1 || st.Failed != 0 {
				t.Errorf("stats = %+v, want the session delivered", st)
			}
		})
	}
}

// The trigger never answers with a gateway failure. A proxy in front of it
// does when it cannot pass the request on, and then the request did not reach
// the trigger, like one that was refused.
func TestReporter_GatewayFailure_IsRepeatedLikeATransportFailure(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.tr.status = status
			r := f.reporter(reporter.Options{Backoff: []time.Duration{time.Second}})
			r.Start()
			r.Submit(f.session("root"))
			f.clock.BlockUntil(1)
			f.clock.Advance(time.Second)
			shutdown(t, r)

			if got := len(f.tr.calls()); got != 2 {
				t.Errorf("%d requests after the answer %d, want the first and a repetition", got, status)
			}
			if st := r.TakeStats(); st.Failed != 1 || st.Sent != 0 {
				t.Errorf("stats = %+v, want the session counted as failed", st)
			}
		})
	}
}

func TestReporter_GatewayFailure_OfAHeartbeat_IsLoggedWithItsStatus(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.tr.status = http.StatusBadGateway
	r := f.reporter(reporter.Options{Backoff: []time.Duration{}})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.RunHeartbeats(ctx, "0.1.0", []*session.Honeypot{honeypotOne})
	}()
	f.clock.BlockUntil(1)
	cancel()
	<-done

	if logs := f.logs.String(); !strings.Contains(logs, "sensor: heartbeat not delivered") || !strings.Contains(logs, "status 502") {
		t.Errorf("log = %s, want the heartbeat reported as not delivered, with the status", logs)
	}
}

func TestReporter_Redirect_IsNotFollowed(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var elsewhere int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		mu.Lock()
		elsewhere++
		mu.Unlock()
	}))
	t.Cleanup(target.Close)
	var asked int
	trigger := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked++
		mu.Unlock()
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(trigger.Close)

	f := newFixture(t)
	r := reporter.New(reporter.Options{URL: trigger.URL + "/", Clock: f.clock, Logger: slog.New(slog.DiscardHandler)})
	r.Start()
	r.Submit(f.session("root"))
	shutdown(t, r)

	mu.Lock()
	defer mu.Unlock()
	if asked != 1 || elsewhere != 0 {
		t.Errorf("trigger asked %d times, redirect target %d times; want 1 and 0: the secret goes to the trigger only", asked, elsewhere)
	}
}

func TestReporter_QueueFull_CountsTheOverflow(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	r := f.reporter(reporter.Options{QueueSize: 2})
	for range 5 {
		r.Submit(f.session("root"))
	}
	r.Start()
	shutdown(t, r)

	if got := len(f.tr.calls()); got != 2 {
		t.Errorf("%d requests, want the 2 that fitted", got)
	}
	if st := r.TakeStats(); st.Overflow != 3 || st.Sent != 2 {
		t.Errorf("stats = %+v, want 3 overflowed and 2 sent", st)
	}
}

// Every honeypot has its own share of the queue: a flood at one does not take
// the places of another.
func TestReporter_QueueShare_IsKeptForEveryHoneypot(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	two := &session.Honeypot{ID: "11111111-2222-4333-8444-555555555555", Service: "telnet", Secret: secret.Secret(secretTwo)}
	r := f.reporter(reporter.Options{QueueSize: 2})
	for range 5 {
		r.Submit(f.session("flood"))
	}
	for range 2 {
		s, err := session.Start(f.clock, two, netip.MustParseAddrPort("203.0.113.9:51000"), netip.MustParseAddrPort("10.0.0.5:23"))
		if err != nil {
			t.Fatal(err)
		}
		s.End()
		r.Submit(s)
	}
	r.Start()
	shutdown(t, r)

	if st := r.TakeStats(); st.Overflow != 3 || st.Sent != 4 {
		t.Errorf("stats = %+v, want 3 sessions of the flood dropped and the 2 + 2 that fitted sent", st)
	}
	auths := map[string]int{}
	for _, c := range f.tr.calls() {
		auths[c.authorization]++
	}
	if auths["Bearer "+secretOne] != 2 || auths["Bearer "+secretTwo] != 2 {
		t.Errorf("requests per secret = %v, want 2 for each honeypot", auths)
	}
}

func TestReporter_QueueShare_IsFreedWhenASessionIsTaken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.tr.notify = make(chan struct{})
	r := f.reporter(reporter.Options{QueueSize: 1, Senders: 1})
	r.Start()
	for range 20 {
		r.Submit(f.session("root"))
		// A request means that the sender has taken the session, which frees
		// the place for the next.
		<-f.tr.notify
	}
	shutdown(t, r)
	if st := r.TakeStats(); st.Sent != 20 || st.Overflow != 0 {
		t.Errorf("stats = %+v, want all 20 sent one after the other", st)
	}
}

// The channel has room for the shares of 32 honeypots. A sensor with more must
// lose a session, not block with the lock held.
func TestReporter_MoreHoneypotsThanRoom_DropsInsteadOfBlocking(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	r := f.reporter(reporter.Options{QueueSize: 1})
	for i := range 33 {
		hp := &session.Honeypot{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i), Service: "telnet", Secret: secret.Secret(secretOne)}
		s, err := session.Start(f.clock, hp, netip.MustParseAddrPort("203.0.113.9:51000"), netip.MustParseAddrPort("10.0.0.5:23"))
		if err != nil {
			t.Fatal(err)
		}
		s.End()
		r.Submit(s)
	}
	r.Start()
	shutdown(t, r)

	if st := r.TakeStats(); st.Overflow != 1 || st.Sent != 32 {
		t.Errorf("stats = %+v, want 32 sent and the 33rd dropped", st)
	}
}

func TestReporter_Limits_AreTheDocumentedOnes(t *testing.T) {
	t.Parallel()

	if reporter.QueueSize != 256 || reporter.Senders != 4 || reporter.MaxRetries != 3 ||
		reporter.RequestTimeout != 10*time.Second || reporter.HeartbeatInterval != 5*time.Minute {
		t.Errorf("limits = %d, %d, %d, %v, %v; want 256, 4, 3, 10s, 5m",
			reporter.QueueSize, reporter.Senders, reporter.MaxRetries, reporter.RequestTimeout, reporter.HeartbeatInterval)
	}
}

func TestReporter_SessionOlderThanFiveMinutes_IsDroppedAndCounted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		wait     time.Duration
		wantSent bool
	}{
		{name: "exactly five minutes", wait: 5 * time.Minute, wantSent: true},
		{name: "one millisecond more", wait: 5*time.Minute + time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			r := f.reporter(reporter.Options{})
			r.Submit(f.session("root"))
			// The session waits in the queue, for example while the trigger
			// is down.
			f.clock.Advance(tt.wait)
			r.Start()
			shutdown(t, r)

			st := r.TakeStats()
			if gotSent := len(f.tr.calls()) == 1; gotSent != tt.wantSent {
				t.Errorf("sent = %v, want %v", gotSent, tt.wantSent)
			}
			if tt.wantSent && ageOf(t, f.tr.calls()[0]) != 300000 {
				t.Errorf("age = %d ms, want 300000", ageOf(t, f.tr.calls()[0]))
			}
			if wantExpired := map[bool]int{true: 0, false: 1}[tt.wantSent]; st.Expired != wantExpired {
				t.Errorf("Expired = %d, want %d", st.Expired, wantExpired)
			}
		})
	}
}

// A session that waited out its pauses until it was too old is not sent once
// more.
func TestReporter_Repetition_OfASessionThatBecameTooOld_IsDropped(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.tr.failFirst = 1000
	r := f.reporter(reporter.Options{Backoff: []time.Duration{5*time.Minute + time.Second}})
	r.Start()
	r.Submit(f.session("root"))
	f.clock.BlockUntil(1)
	f.clock.Advance(5*time.Minute + time.Second)
	shutdown(t, r)

	if got := len(f.tr.calls()); got != 1 {
		t.Errorf("%d requests, want only the first: the session was too old for the second", got)
	}
	if st := r.TakeStats(); st.Expired != 1 {
		t.Errorf("stats = %+v, want one expired session", st)
	}
}

func TestReporter_Shutdown_DeliversWhatIsQueued(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	r := f.reporter(reporter.Options{})
	r.Start()
	for range 20 {
		r.Submit(f.session("root"))
	}
	shutdown(t, r)

	if got := len(f.tr.calls()); got != 20 {
		t.Errorf("%d requests, want 20", got)
	}
}

func TestReporter_Submit_AfterShutdown_IsCounted(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	r := f.reporter(reporter.Options{})
	r.Start()
	shutdown(t, r)
	r.Submit(f.session("root"))
	shutdown(t, r)

	if got := len(f.tr.calls()); got != 0 {
		t.Errorf("%d requests after the shutdown, want none", got)
	}
	if st := r.TakeStats(); st.Shutdown != 1 {
		t.Errorf("stats = %+v, want one session counted as lost to the shutdown", st)
	}
}

// blocking is a transport whose requests last until their context ends, like
// a trigger that does not answer.
type blocking struct {
	entered chan struct{}
}

func (b blocking) RoundTrip(r *http.Request) (*http.Response, error) {
	b.entered <- struct{}{}
	<-r.Context().Done()
	return nil, r.Context().Err()
}

func TestReporter_Shutdown_EndsAtItsDeadline(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	b := blocking{entered: make(chan struct{}, 8)}
	r := f.reporter(reporter.Options{Client: &http.Client{Transport: b}, Senders: 2})
	r.Start()
	for range 5 {
		r.Submit(f.session("root"))
	}
	<-b.entered
	<-b.entered

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Shutdown(ctx)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown did not return at its deadline")
	}

	// Two sessions were in flight and three queued: all five are counted.
	if st := r.TakeStats(); st.Shutdown != 5 || st.Sent != 0 {
		t.Errorf("stats = %+v, want 5 sessions lost to the shutdown", st)
	}
}

func heartbeatOf(t *testing.T, req request) report.Heartbeat {
	t.Helper()
	var h report.Heartbeat
	dec := json.NewDecoder(bytes.NewReader(req.body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		t.Fatalf("decode heartbeat %s: %v", req.body, err)
	}
	return h
}

func TestReporter_Heartbeats_AtTheStartAndEveryFiveMinutesForEveryHoneypot(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	r := f.reporter(reporter.Options{})
	two := &session.Honeypot{ID: "11111111-2222-4333-8444-555555555555", Service: "telnet", Secret: secret.Secret(secretTwo)}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.RunHeartbeats(ctx, "0.1.0", []*session.Honeypot{honeypotOne, two})
	}()

	// Every honeypot has a loop of its own, and both wait for the next round.
	f.clock.BlockUntil(2)
	calls := f.tr.calls()
	if len(calls) != 2 {
		t.Fatalf("%d heartbeats at the start, want one for each honeypot", len(calls))
	}
	auths := map[string]bool{calls[0].authorization: true, calls[1].authorization: true}
	if !auths["Bearer "+secretOne] || !auths["Bearer "+secretTwo] {
		t.Errorf("authorizations = %q, %q; want the secret of each honeypot", calls[0].authorization, calls[1].authorization)
	}
	if h := heartbeatOf(t, calls[0]); h.Version != 2 || h.Type != "heartbeat" || h.SensorVersion != "0.1.0" {
		t.Errorf("heartbeat = %+v, want version 2, type heartbeat and the version of the sensor", h)
	}
	if got := string(calls[0].body); got != `{"version":2,"type":"heartbeat","sensor_version":"0.1.0"}` {
		t.Errorf("body = %s", got)
	}

	f.clock.Advance(5*time.Minute - time.Nanosecond)
	if got := len(f.tr.calls()); got != 2 || f.clock.Pending() != 2 {
		t.Fatalf("%d heartbeats just before five minutes, pending = %d; want 2 and 2", got, f.clock.Pending())
	}
	f.clock.Advance(time.Nanosecond)
	f.clock.BlockUntil(2)
	if got := len(f.tr.calls()); got != 4 {
		t.Errorf("%d heartbeats after five minutes, want 4", got)
	}

	cancel()
	<-done
	if got := len(f.tr.calls()); got != 4 {
		t.Errorf("%d heartbeats after the end, want 4", got)
	}
}

func TestReporter_Heartbeat_WithoutAVersion_NamesNone(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	r := f.reporter(reporter.Options{})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.RunHeartbeats(ctx, "", []*session.Honeypot{honeypotOne})
	}()
	f.clock.BlockUntil(1)
	cancel()
	<-done

	if got := string(f.tr.calls()[0].body); got != `{"version":2,"type":"heartbeat"}` {
		t.Errorf("body = %s", got)
	}
}

// An attacker who fills the queue cannot make the honeypot look offline.
func TestReporter_Heartbeats_DoNotUseTheQueue(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	r := f.reporter(reporter.Options{QueueSize: 1})
	for range 3 {
		r.Submit(f.session("root"))
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.RunHeartbeats(ctx, "0.1.0", []*session.Honeypot{honeypotOne})
	}()
	f.clock.BlockUntil(1)
	cancel()
	<-done

	if st := r.TakeStats(); st.Overflow != 2 {
		t.Fatalf("stats = %+v, want the queue full", st)
	}
	if got := len(f.tr.calls()); got != 1 {
		t.Errorf("%d heartbeats with a full queue, want 1", got)
	}
}

func TestReporter_Heartbeat_RepeatsTransportFailuresThreeTimes(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.tr.failFirst = 1000
	r := f.reporter(reporter.Options{})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.RunHeartbeats(ctx, "0.1.0", []*session.Honeypot{honeypotOne})
	}()
	for _, pause := range []time.Duration{time.Second, 3 * time.Second, 9 * time.Second} {
		f.clock.BlockUntil(1)
		f.clock.Advance(pause)
	}
	// The next wait is the one of five minutes.
	f.clock.BlockUntil(1)
	cancel()
	<-done

	if got := len(f.tr.calls()); got != 4 {
		t.Errorf("%d requests, want the first and three repetitions", got)
	}
	// An operator learns of a wrong address or certificate at once, not after
	// the next summary, and the record holds no secret.
	logs := f.logs.String()
	if got := strings.Count(logs, "sensor: heartbeat not delivered"); got != 1 {
		t.Errorf("%d records about the heartbeat, want 1: %s", got, logs)
	}
	for _, want := range []string{`"honeypot_id":"` + honeypotOne.ID + `"`, `"service":"telnet"`, "connection refused"} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %s: %s", want, logs)
		}
	}
	if strings.Contains(logs, secretOne) {
		t.Errorf("log holds the secret: %s", logs)
	}
}

// Neither the secret nor what an attacker typed reaches the log, also not on
// the path of a failure.
func TestReporter_Log_HoldsNoSecretAndNoInput(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.tr.failFirst = 1
	r := f.reporter(reporter.Options{})
	r.Start()
	r.Submit(f.session("mallory-typed-this"))
	f.clock.BlockUntil(1)
	f.clock.Advance(time.Second)
	shutdown(t, r)

	out := f.logs.String()
	if !strings.Contains(out, "sensor: report request failed") || !strings.Contains(out, "sensor: session reported") {
		t.Fatalf("log = %s, want the failed request and the reported session", out)
	}
	for _, forbidden := range []string{secretOne, "Bearer", "mallory-typed-this"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("log holds %q: %s", forbidden, out)
		}
	}
}

func TestNewHTTPClient_VerifiesTheCertificateOfTheTrigger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		trusted  bool
		wantSent bool
	}{
		{name: "a certificate that no authority signed"},
		{name: "a certificate of a trusted authority", trusted: true, wantSent: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var asked atomic.Int64
			srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { asked.Add(1) }))
			t.Cleanup(srv.Close)

			f := newFixture(t)
			opts := reporter.Options{URL: srv.URL + "/", Clock: f.clock, Logger: slog.New(slog.DiscardHandler)}
			if tt.trusted {
				opts.Client = srv.Client()
			} else {
				// The default client, without a pause: the failure is not
				// repeated.
				opts.Backoff = []time.Duration{}
			}
			r := reporter.New(opts)
			r.Start()
			r.Submit(f.session("root"))
			shutdown(t, r)

			st := r.TakeStats()
			if (st.Sent == 1) != tt.wantSent || (asked.Load() == 1) != tt.wantSent {
				t.Errorf("stats = %+v, the trigger was asked %d times; want the session delivered = %v", st, asked.Load(), tt.wantSent)
			}
		})
	}
}

func TestNewHTTPClient_Settings(t *testing.T) {
	t.Parallel()

	c := reporter.NewHTTPClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T", c.Transport)
	}
	if tr.Proxy != nil {
		t.Error("the client reads a proxy, want none: the secret would go to it")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion < 0x0303 || tr.TLSClientConfig.InsecureSkipVerify {
		t.Errorf("TLS config = %+v, want TLS 1.2 or later and a verified certificate", tr.TLSClientConfig)
	}
	if c.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", c.Timeout)
	}
	if c.CheckRedirect == nil {
		t.Error("CheckRedirect = nil, want a client that does not follow redirects")
	}
}
