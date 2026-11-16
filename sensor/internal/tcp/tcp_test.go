// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package tcp_test

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"nyktus.org/nyktus/sensor/internal/clock/clocktest"
	"nyktus.org/nyktus/sensor/internal/conntest"
	"nyktus.org/nyktus/sensor/internal/guard"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/session"
	"nyktus.org/nyktus/sensor/internal/tcp"
)

const secretValue = "Abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"

var (
	remote = netip.MustParseAddrPort("203.0.113.9:51000")
	local  = netip.MustParseAddrPort("10.0.0.5:3389")
)

// play runs the honeypot against a client that sends script and returns the
// report of the finished session and the connection.
func play(t *testing.T, cfg tcp.Config, script []byte, tweak func(*conntest.Conn)) (report.Session, *conntest.Conn) {
	t.Helper()
	clk := clocktest.New()
	conn := conntest.New(script)
	if tweak != nil {
		tweak(conn)
	}
	hp := &session.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: "tcp", Secret: secretValue}
	s, err := session.Start(clk, hp, remote, local)
	if err != nil {
		t.Fatal(err)
	}
	tcp.New(cfg, clk).Serve(t.Context(), conn, s)
	s.End()
	rep, ok := s.Report(0)
	if !ok {
		t.Fatal("Report() = not ok")
	}
	return rep, conn
}

func TestServe_SilentPort_SaysNothingAndRecordsOnlyTheConnection(t *testing.T) {
	t.Parallel()

	rep, conn := play(t, tcp.Config{}, nil, nil)
	if got := conn.Written(); len(got) != 0 {
		t.Errorf("written = %q, want nothing", got)
	}
	if rep.Port != 3389 || rep.ClientIP != "203.0.113.9" || len(rep.Attempts) != 0 || rep.Query != nil || len(rep.ToolCalls) != 0 {
		t.Errorf("report = %+v, want the connection to port 3389 and nothing else", rep)
	}
}

func TestServe_Banner_IsSentFirstAndNothingElseEver(t *testing.T) {
	t.Parallel()

	_, conn := play(t, tcp.Config{Banner: "220 ready\r\n"}, []byte("EHLO example.org\r\n"), nil)
	if got := string(conn.Written()); got != "220 ready\r\n" {
		t.Errorf("written = %q, want the banner alone", got)
	}
}

// What a client sends is where credentials stand. None of it is kept, so that
// no report can carry it, and none of it is sent back.
func TestServe_WhatTheClientSends_IsNeitherKeptNorSentBack(t *testing.T) {
	t.Parallel()

	script := []byte("GET / HTTP/1.1\r\nAuthorization: Basic YWRtaW46aHVudGVyMg==\r\n\r\nCookie: mstshash=administrator\r\n")
	rep, conn := play(t, tcp.Config{}, script, nil)
	if got := conn.BytesRead(); got != len(script) {
		t.Errorf("read %d bytes, want all %d", got, len(script))
	}
	if got := conn.Written(); len(got) != 0 {
		t.Errorf("written = %q, want nothing", got)
	}
	data, err := report.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"YWRtaW46", "administrator", "mstshash", "hunter2", "HTTP/1.1"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("the report holds %q: %s", secret, data)
		}
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"attempts", "port", "client_ip", "version", "type", "session_id", "age_ms", "duration_ms"} {
		delete(fields, name)
	}
	if len(fields) != 0 {
		t.Errorf("the report holds more than the connection: %v", fields)
	}
}

func TestServe_AClientThatSendsTooMuch_IsStoppedAtTheLimitOfTheGuard(t *testing.T) {
	t.Parallel()

	_, conn := play(t, tcp.Config{}, bytes.Repeat([]byte("A"), 10*guard.MaxReadBytes), nil)
	if got := conn.BytesRead(); got != guard.MaxReadBytes {
		t.Errorf("read %d bytes, want %d", got, guard.MaxReadBytes)
	}
}

func TestServe_ReadsAndWritesThroughTheGuard(t *testing.T) {
	t.Parallel()

	_, conn := play(t, tcp.Config{Banner: "hello\r\n"}, []byte("x"), nil)
	if len(conn.ReadDeadlines()) == 0 {
		t.Error("the connection was read without an idle time")
	}
	if len(conn.WriteDeadlines()) == 0 {
		t.Error("the banner was written without a write deadline")
	}
}

func TestServe_BannerThatCannotBeWritten_EndsTheSessionWithoutReading(t *testing.T) {
	t.Parallel()

	_, conn := play(t, tcp.Config{Banner: "hello\r\n"}, []byte(strings.Repeat("x", 100)), func(c *conntest.Conn) { c.FailAfter(0) })
	if got := conn.BytesRead(); got != 0 {
		t.Errorf("read %d bytes after a failed banner, want none", got)
	}
}

func TestNew_WithoutAClock_Panics(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("New(nil clock) did not panic")
		}
	}()
	tcp.New(tcp.Config{}, nil)
}
