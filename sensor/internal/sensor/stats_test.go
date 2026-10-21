// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sensor

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock/clocktest"
	"nyktus.org/nyktus/sensor/internal/listener"
	"nyktus.org/nyktus/sensor/internal/reporter"
	"nyktus.org/nyktus/sensor/internal/session"
)

type panicking struct{}

func (panicking) Handle(context.Context, net.Conn) {
	// Zero where the compiler cannot see it.
	zero := len(os.Args[:0])
	_ = 1 / zero
}

// A service that fails on what an attacker sent is found by the record in the
// log: the honeypot, how many sessions, the kind of failure and where.
func TestLogStats_ServiceFailure_NamesTheFailureAndItsPlace(t *testing.T) {
	t.Parallel()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clk := clocktest.New()
	server := listener.New(listener.Options{Listener: ln, Handler: panicking{}, Clock: clk})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(t.Context(), "tcp", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	// The connection ends after the failure was counted.
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatal(err)
	}

	var logged bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	hp := &session.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: "telnet", Secret: "x"}
	rep := reporter.New(reporter.Options{URL: "http://127.0.0.1:1/", Clock: clk, Logger: logger})
	logStats(t.Context(), logger, rep, []bound{{hp: hp, server: server}})

	out := logged.String()
	for _, want := range []string{"sensor: sessions ended by a failure of the service", `"honeypot_id":"` + hp.ID + `"`, `"sessions":1`, "integer divide by zero", "stats_test.go"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q: %s", want, out)
		}
	}
}
