// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sensor_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock/clocktest"
	"nyktus.org/nyktus/sensor/internal/config"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/sensor"
)

const (
	secretOne = "Abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"
	secretTwo = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	idOne     = "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d"
	idTwo     = "11111111-2222-4333-8444-555555555555"
	// deadline bounds every wait of a test, so that a fault fails it instead of
	// hanging it.
	deadline = 10 * time.Second
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type received struct {
	authorization string
	body          []byte
}

// trigger records what sensors send to it. Until release is closed, it does
// not answer.
type trigger struct {
	*httptest.Server
	requests chan received
	release  chan struct{}
}

func newTrigger(t *testing.T, blocked bool) *trigger {
	t.Helper()
	tr := &trigger{requests: make(chan received, 64), release: make(chan struct{})}
	if !blocked {
		close(tr.release)
	}
	tr.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		tr.requests <- received{authorization: r.Header.Get("Authorization"), body: body}
		select {
		case <-tr.release:
		case <-r.Context().Done():
		}
		http.Redirect(w, r, "https://example.org/", http.StatusFound)
	}))
	t.Cleanup(tr.Close)
	t.Cleanup(func() {
		select {
		case <-tr.release:
		default:
			close(tr.release)
		}
	})
	return tr
}

func (tr *trigger) next(t *testing.T) received {
	t.Helper()
	select {
	case r := <-tr.requests:
		return r
	case <-time.After(deadline):
		t.Fatal("the trigger received no report")
		return received{}
	}
}

// running is a sensor in the process.
type running struct {
	t      *testing.T
	clock  *clocktest.Fake
	logs   *syncBuffer
	addrs  map[string]net.Addr
	cancel context.CancelFunc
	// finished is closed when Run has returned, with its error in err.
	finished chan struct{}
	err      error
}

func parse(t *testing.T, triggerURL string, honeypots string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte("environment: development\ntrigger_url: " + triggerURL + "\nhoneypots:\n" + honeypots))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

const oneHoneypot = "  - id: " + idOne + "\n    service: telnet\n    listen: \"127.0.0.1:2323\"\n    secret: " + secretOne + "\n"

func start(t *testing.T, cfg *config.Config, tweak func(*sensor.Options)) *running {
	t.Helper()
	r := &running{t: t, clock: clocktest.New(), logs: &syncBuffer{}, addrs: map[string]net.Addr{}, finished: make(chan struct{})}
	// The configuration names ports, which it must, and the test takes free ones.
	for i := range cfg.Honeypots {
		cfg.Honeypots[i].Listen = "127.0.0.1:0"
	}
	var mu sync.Mutex
	listening := make(chan struct{}, len(cfg.Honeypots))
	opts := sensor.Options{
		Config:  cfg,
		Version: "0.1.0",
		Logger:  slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Clock:   r.clock,
		Listening: func(id string, addr net.Addr) {
			mu.Lock()
			r.addrs[id] = addr
			mu.Unlock()
			listening <- struct{}{}
		},
	}
	if tweak != nil {
		tweak(&opts)
	}
	ctx, cancel := context.WithCancel(t.Context())
	r.cancel = cancel
	go func() {
		r.err = sensor.Run(ctx, opts)
		close(r.finished)
	}()
	for range cfg.Honeypots {
		select {
		case <-listening:
		case <-r.finished:
			t.Fatalf("Run() = %v before the honeypots listened", r.err)
		case <-time.After(deadline):
			t.Fatal("the honeypots did not listen")
		}
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.finished:
		case <-time.After(deadline):
		}
	})
	return r
}

func (r *running) addr(id string) string {
	r.t.Helper()
	return r.addrs[id].String()
}

func (r *running) stop() error {
	r.t.Helper()
	r.cancel()
	select {
	case <-r.finished:
		return r.err
	case <-time.After(deadline):
		r.t.Fatal("Run did not return")
		return nil
	}
}

// client is an attacker.
type client struct {
	conn net.Conn
	r    *bufio.Reader
}

func connect(t *testing.T, addr string) *client {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: deadline}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(deadline))
	return &client{conn: conn, r: bufio.NewReader(conn)}
}

// until reads until the server has written s.
func (c *client) until(t *testing.T, s string) {
	t.Helper()
	var got []byte
	for !bytes.HasSuffix(got, []byte(s)) {
		b, err := c.r.ReadByte()
		if err != nil {
			t.Fatalf("read until %q: %v (got %q)", s, err, got)
		}
		got = append(got, b)
	}
}

func (c *client) send(t *testing.T, s string) {
	t.Helper()
	if _, err := io.WriteString(c.conn, s); err != nil {
		t.Fatal(err)
	}
}

func decodeSession(t *testing.T, rc received) report.Session {
	t.Helper()
	var s report.Session
	dec := json.NewDecoder(bytes.NewReader(rc.body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		t.Fatalf("decode %s: %v", rc.body, err)
	}
	return s
}

func TestRun_TelnetSession_IsReportedWithItsAttempts(t *testing.T) {
	t.Parallel()

	tr := newTrigger(t, false)
	r := start(t, parse(t, tr.URL, oneHoneypot), nil)

	// The honeypot says that it runs, with the secret of its honeypot.
	hb := tr.next(t)
	if hb.authorization != "Bearer "+secretOne || string(hb.body) != `{"version":1,"type":"heartbeat","sensor_version":"0.1.0"}` {
		t.Errorf("first report = %+v, want the heartbeat of the honeypot", hb)
	}

	c := connect(t, r.addr(idOne))
	c.until(t, "login: ")
	c.send(t, "mallory-typed-this\r\n")
	c.until(t, "Password: ")
	c.send(t, "hunter2-typed-this\r\n")
	c.until(t, "Login incorrect\r\nlogin: ")
	_ = c.conn.Close()

	rc := tr.next(t)
	s := decodeSession(t, rc)
	_, port, _ := net.SplitHostPort(r.addr(idOne))
	if rc.authorization != "Bearer "+secretOne || s.Version != 1 || s.Type != "session" || s.ClientIP != "127.0.0.1" || strconv.Itoa(s.Port) != port ||
		len(s.Attempts) != 1 || s.Attempts[0].Username != "mallory-typed-this" || s.Attempts[0].PasswordLength == nil || *s.Attempts[0].PasswordLength != 18 {
		t.Errorf("report = %+v (%s), want the session with one login", s, rc.authorization)
	}
	if strings.Contains(string(rc.body), "hunter2") {
		t.Errorf("report %s holds the password", rc.body)
	}
	if err := r.stop(); err != nil {
		t.Errorf("Run() = %v", err)
	}

	// Neither the secret nor what the attacker typed reaches the log.
	logs := r.logs.String()
	for _, forbidden := range []string{secretOne, "mallory-typed-this", "hunter2"} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("log holds %q: %s", forbidden, logs)
		}
	}
	for _, want := range []string{"sensor: honeypot listening", "sensor: started", "sensor: stopped", `"honeypot_id":"` + idOne + `"`, `"service":"telnet"`, `"event_type":"login_attempt"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %s: %s", want, logs)
		}
	}
}

// Every honeypot reports with its own secret.
func TestRun_TwoHoneypots_ReportWithTheirOwnSecrets(t *testing.T) {
	t.Parallel()

	tr := newTrigger(t, false)
	two := "  - id: " + idTwo + "\n    service: telnet\n    listen: \"127.0.0.1:2324\"\n    secret: " + secretTwo + "\n"
	r := start(t, parse(t, tr.URL, oneHoneypot+two), nil)

	got := map[string]bool{tr.next(t).authorization: true, tr.next(t).authorization: true}
	if !got["Bearer "+secretOne] || !got["Bearer "+secretTwo] {
		t.Errorf("heartbeats came with %v, want one for each honeypot", got)
	}

	c := connect(t, r.addr(idTwo))
	c.until(t, "login: ")
	_ = c.conn.Close()
	rc := tr.next(t)
	if rc.authorization != "Bearer "+secretTwo {
		t.Errorf("session reported with %q, want the secret of the honeypot that was reached", rc.authorization)
	}
	if s := decodeSession(t, rc); len(s.Attempts) != 0 {
		t.Errorf("attempts = %+v, want a session that only connected", s.Attempts)
	}
}

func TestRun_BannerAndPrompt_AreTheOnesOfTheConfiguration(t *testing.T) {
	t.Parallel()

	tr := newTrigger(t, false)
	custom := oneHoneypot + "    banner: \"User Access Verification\\r\\n\\r\\n\"\n    login_prompt: \"Username: \"\n"
	r := start(t, parse(t, tr.URL, custom), nil)

	c := connect(t, r.addr(idOne))
	c.until(t, "User Access Verification\r\n\r\nUsername: ")
}

func TestRun_DefaultBanner(t *testing.T) {
	t.Parallel()

	tr := newTrigger(t, false)
	r := start(t, parse(t, tr.URL, oneHoneypot), nil)

	c := connect(t, r.addr(idOne))
	c.until(t, "\r\nUbuntu 22.04.4 LTS\r\nlogin: ")
}

// The sensor delivers what an open session had done when it stops.
func TestRun_Stop_ReportsOpenSessions(t *testing.T) {
	t.Parallel()

	tr := newTrigger(t, false)
	r := start(t, parse(t, tr.URL, oneHoneypot), nil)
	tr.next(t) // the heartbeat

	c := connect(t, r.addr(idOne))
	c.until(t, "login: ")
	c.send(t, "root\r\n")
	c.until(t, "Password: ")

	if err := r.stop(); err != nil {
		t.Errorf("Run() = %v", err)
	}
	s := decodeSession(t, tr.next(t))
	if len(s.Attempts) != 1 || s.Attempts[0].Username != "root" || s.Attempts[0].PasswordLength != nil {
		t.Errorf("attempts = %+v, want the login without a password", s.Attempts)
	}
}

// A trigger that does not answer does not keep the sensor from stopping.
func TestRun_Stop_EndsAtTheDeadlineOfTheDrain(t *testing.T) {
	t.Parallel()

	tr := newTrigger(t, true)
	r := start(t, parse(t, tr.URL, oneHoneypot), func(o *sensor.Options) { o.DrainTimeout = 50 * time.Millisecond })
	tr.next(t) // the heartbeat, which is not answered

	c := connect(t, r.addr(idOne))
	c.until(t, "login: ")
	_ = c.conn.Close()
	tr.next(t) // the session, which is not answered either

	if err := r.stop(); err != nil {
		t.Errorf("Run() = %v", err)
	}
	if logs := r.logs.String(); !strings.Contains(logs, "sensor: reports not sent") || !strings.Contains(logs, `"shutdown":1`) {
		t.Errorf("log = %s, want the session counted as lost to the shutdown", logs)
	}
}

func TestRun_HoneypotThatCannotBind_EndsTheStart(t *testing.T) {
	t.Parallel()

	busy, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = busy.Close() })
	free, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freeAddr := free.Addr().String()
	_ = free.Close()

	tr := newTrigger(t, false)
	honeypots := "  - id: " + idOne + "\n    service: telnet\n    listen: \"" + freeAddr + "\"\n    secret: " + secretOne + "\n" +
		"  - id: " + idTwo + "\n    service: telnet\n    listen: \"" + busy.Addr().String() + "\"\n    secret: " + secretTwo + "\n"
	err = sensor.Run(t.Context(), sensor.Options{
		Config: parse(t, tr.URL, honeypots),
		Logger: slog.New(slog.DiscardHandler),
		Clock:  clocktest.New(),
	})
	if err == nil || !strings.Contains(err.Error(), idTwo) {
		t.Fatalf("Run() = %v, want an error that names the honeypot that could not bind", err)
	}
	// The first honeypot gave its port back: a sensor that runs some of its
	// honeypots is not started.
	again, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", freeAddr)
	if err != nil {
		t.Fatalf("the port of the first honeypot is still taken: %v", err)
	}
	_ = again.Close()
	select {
	case rc := <-tr.requests:
		t.Errorf("a sensor that did not start reported %s", rc.body)
	default:
	}
}

// What the sensor turned away is logged once for each interval, as counts.
func TestRun_RefusedConnections_AreLoggedOncePerInterval(t *testing.T) {
	t.Parallel()

	tr := newTrigger(t, false)
	r := start(t, parse(t, tr.URL, oneHoneypot), nil)
	// The heartbeat was sent and both loops wait.
	r.clock.BlockUntil(2)

	var held []*client
	for range 8 {
		c := connect(t, r.addr(idOne))
		c.until(t, "login: ")
		held = append(held, c)
	}
	ninth := connect(t, r.addr(idOne))
	if _, err := ninth.r.ReadByte(); err == nil {
		t.Fatal("the ninth connection of one source was served")
	}

	r.clock.Advance(time.Minute - time.Nanosecond)
	if strings.Contains(r.logs.String(), "connections refused") {
		t.Error("logged before the interval ended")
	}
	r.clock.Advance(time.Nanosecond)
	// The loop has logged and waits again: the heartbeat, the loop itself and
	// the limit of time of each open connection.
	r.clock.BlockUntil(2 + len(held))

	logs := r.logs.String()
	for _, want := range []string{"sensor: connections refused", `"too_many_from_source":1`, `"too_many":0`, `"honeypot_id":"` + idOne + `"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %s: %s", want, logs)
		}
	}
	_ = held
}

func TestDefaults_AreTheDocumentedOnes(t *testing.T) {
	t.Parallel()

	if sensor.DrainTimeout != 15*time.Second || sensor.StatsInterval != time.Minute {
		t.Errorf("DrainTimeout = %v, StatsInterval = %v; want 15s and 1m", sensor.DrainTimeout, sensor.StatsInterval)
	}
}

func TestRun_MissingDependencies_Panic(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("Run() did not panic without a configuration")
		}
	}()
	_ = sensor.Run(t.Context(), sensor.Options{})
}
