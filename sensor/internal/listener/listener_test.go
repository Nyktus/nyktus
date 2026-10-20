// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package listener

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock/clocktest"
)

// deadline bounds every wait of a test on a socket, so that a limit that does
// not hold fails the test instead of hanging it.
const deadline = 10 * time.Second

// holdHandler keeps every connection open until the test releases it.
type holdHandler struct {
	entered chan struct{}
	release chan struct{}
	handled atomic.Int64
}

func newHoldHandler() *holdHandler {
	return &holdHandler{entered: make(chan struct{}, 1024), release: make(chan struct{})}
}

func (h *holdHandler) Handle(ctx context.Context, _ net.Conn) {
	h.handled.Add(1)
	h.entered <- struct{}{}
	select {
	case <-h.release:
	case <-ctx.Done():
	}
}

// zero is 0 where the compiler cannot see it, so that a division by it is a
// failure at run time.
func zero() int { return 0 }

type handlerFunc func(ctx context.Context, conn net.Conn)

func (f handlerFunc) Handle(ctx context.Context, conn net.Conn) { f(ctx, conn) }

// serve starts a server on a loopback port and returns it with a function
// that stops it and waits.
func serve(t *testing.T, o Options) (*Server, func()) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o.Listener = ln
	if o.Clock == nil {
		o.Clock = clocktest.New()
	}
	srv := New(o)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.Serve(ctx)
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
	t.Cleanup(stop)
	return srv, stop
}

func dial(t *testing.T, srv *Server) net.Conn {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: deadline}).DialContext(t.Context(), "tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetReadDeadline(time.Now().Add(deadline))
	return conn
}

func waitEntered(t *testing.T, h *holdHandler, n int) {
	t.Helper()
	for range n {
		select {
		case <-h.entered:
		case <-time.After(deadline):
			t.Fatal("a connection was not handled")
		}
	}
}

// refused reports whether the server closed the connection without serving it.
func refused(t *testing.T, conn net.Conn) bool {
	t.Helper()
	_, err := conn.Read(make([]byte, 1))
	if errors.Is(err, io.EOF) {
		return true
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return false
	}
	return err != nil
}

func TestServer_ConnectionsBeyondTheLimit_AreRefusedAndCounted(t *testing.T) {
	t.Parallel()

	h := newHoldHandler()
	srv, _ := serve(t, Options{Handler: h, MaxConns: 2, MaxPerSource: 100})
	a, b := dial(t, srv), dial(t, srv)
	waitEntered(t, h, 2)

	c := dial(t, srv)
	if !refused(t, c) {
		t.Fatal("the third connection was served, want it refused")
	}
	if got := srv.TakeStats(); got.RefusedTotal != 1 || got.RefusedSource != 0 {
		t.Errorf("TakeStats() = %+v, want one connection refused because of the total", got)
	}
	if got := h.handled.Load(); got != 2 {
		t.Errorf("handled = %d, want 2", got)
	}
	_, _ = a, b
}

func TestServer_ConnectionsFromOneSourceBeyondTheLimit_AreRefusedAndCounted(t *testing.T) {
	t.Parallel()

	h := newHoldHandler()
	srv, _ := serve(t, Options{Handler: h, MaxConns: 100, MaxPerSource: 2})
	a, b := dial(t, srv), dial(t, srv)
	waitEntered(t, h, 2)

	c := dial(t, srv)
	if !refused(t, c) {
		t.Fatal("the third connection of the source was served, want it refused")
	}
	if got := srv.TakeStats(); got.RefusedSource != 1 || got.RefusedTotal != 0 {
		t.Errorf("TakeStats() = %+v, want one connection refused because of the source", got)
	}
	_, _ = a, b
}

func TestServer_ClosedConnection_FreesItsSlot(t *testing.T) {
	t.Parallel()

	h := newHoldHandler()
	srv, _ := serve(t, Options{Handler: h, MaxConns: 1, MaxPerSource: 1})
	first := dial(t, srv)
	waitEntered(t, h, 1)
	h.release <- struct{}{}
	// The handler is done, the server closes the connection: the client sees
	// the end of the stream, and the slot is free.
	if !refused(t, first) {
		t.Fatal("the connection stayed open after its handler returned")
	}
	second := dial(t, srv)
	waitEntered(t, h, 1)
	_ = second
}

func TestServer_Defaults_AreThe128And8AndTwoMinutes(t *testing.T) {
	t.Parallel()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := New(Options{Listener: ln, Handler: newHoldHandler(), Clock: clocktest.New()})
	if srv.maxConns != 128 || srv.maxPerSource != 8 || srv.maxSession != 2*time.Minute {
		t.Errorf("limits = %d, %d, %v; want 128, 8 and 2m0s", srv.maxConns, srv.maxPerSource, srv.maxSession)
	}
}

// The table of sources holds the sources of the open connections and no
// others, so a flood from many sources cannot grow it.
func TestServer_SourceTable_IsBoundedByTheOpenConnections(t *testing.T) {
	t.Parallel()

	srv := New(Options{Listener: stubListener{}, Handler: newHoldHandler(), Clock: clocktest.New(), MaxConns: 16, MaxPerSource: 2})
	var sources []netip.Addr
	for i := range 1000 {
		conn := fakeConn{remote: &net.TCPAddr{IP: net.IPv4(10, byte(i>>8), byte(i), 1), Port: 1000}}
		if source, ok := srv.admit(conn); ok {
			sources = append(sources, source)
		}
		if len(srv.sources) > 16 {
			t.Fatalf("the table holds %d sources with at most 16 connections", len(srv.sources))
		}
	}
	if len(sources) != 16 || srv.open != 16 {
		t.Errorf("admitted %d connections, open = %d; want 16", len(sources), srv.open)
	}
	if got := srv.TakeStats().RefusedTotal; got != 1000-16 {
		t.Errorf("refused = %d, want %d", got, 1000-16)
	}
	for _, s := range sources {
		srv.release(s)
	}
	if len(srv.sources) != 0 || srv.open != 0 {
		t.Errorf("table holds %d sources, open = %d after all connections ended, want none", len(srv.sources), srv.open)
	}
}

func TestSourceOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ip   string
		want string
		same string
		diff string
	}{
		{name: "IPv4 is its own source", ip: "203.0.113.9", want: "203.0.113.9", diff: "203.0.113.10"},
		{name: "IPv4 mapped into IPv6 is the IPv4 address", ip: "::ffff:203.0.113.9", want: "203.0.113.9"},
		{name: "IPv6 is its /64", ip: "2001:db8:1:2:aaaa:bbbb:cccc:dddd", want: "2001:db8:1:2::", same: "2001:db8:1:2:1::1", diff: "2001:db8:1:3::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := sourceOf(&net.TCPAddr{IP: net.ParseIP(tt.ip)})
			if !ok || got.String() != tt.want {
				t.Fatalf("sourceOf(%s) = %v, %v; want %s", tt.ip, got, ok, tt.want)
			}
			if tt.same != "" {
				if other, _ := sourceOf(&net.TCPAddr{IP: net.ParseIP(tt.same)}); other != got {
					t.Errorf("sourceOf(%s) = %v, want the source of %s", tt.same, other, tt.ip)
				}
			}
			if tt.diff != "" {
				if other, _ := sourceOf(&net.TCPAddr{IP: net.ParseIP(tt.diff)}); other == got {
					t.Errorf("sourceOf(%s) = %v, want another source than %s", tt.diff, other, tt.ip)
				}
			}
		})
	}

	if _, ok := sourceOf(&net.UnixAddr{Name: "x", Net: "unix"}); ok {
		t.Error("sourceOf(unix address) = ok, want refused")
	}
	withZone, _ := sourceOf(&net.TCPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0"})
	if withZone.Zone() != "" {
		t.Errorf("sourceOf(fe80::1%%eth0) = %v, want no zone", withZone)
	}
}

// A session ends after two minutes whatever the protocol does.
func TestServer_SessionLongerThanTheLimit_IsClosed(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	handlerDone := make(chan struct{})
	srv, _ := serve(t, Options{Clock: clk, Handler: handlerFunc(func(_ context.Context, conn net.Conn) {
		defer close(handlerDone)
		// A protocol that waits for the client and notices nothing else.
		_, _ = io.Copy(io.Discard, conn)
	})})
	client := dial(t, srv)

	clk.BlockUntil(1)
	clk.Advance(2*time.Minute - time.Nanosecond)
	if got := clk.Pending(); got != 1 {
		t.Fatalf("Pending() = %d just before the limit, want the session still watched", got)
	}
	clk.Advance(time.Nanosecond)

	select {
	case <-handlerDone:
	case <-time.After(deadline):
		t.Fatal("the connection stayed open after two minutes")
	}
	if !refused(t, client) {
		t.Error("the client still has a connection")
	}
}

func TestServer_EndOfTheSensor_ClosesOpenConnections(t *testing.T) {
	t.Parallel()

	// A protocol that waits for the client and notices nothing else: only the
	// closing of its connection ends it.
	entered := make(chan struct{})
	srv, stop := serve(t, Options{Handler: handlerFunc(func(_ context.Context, conn net.Conn) {
		close(entered)
		_, _ = io.Copy(io.Discard, conn)
	})})
	client := dial(t, srv)
	<-entered

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		stop()
	}()
	select {
	case <-stopped:
	case <-time.After(deadline):
		t.Fatal("the server did not stop: it left a connection open")
	}
	if !refused(t, client) {
		t.Error("the connection stayed open after the server stopped")
	}
}

func TestServer_PanickingHandler_IsCountedAndFreesItsSlot(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	srv, _ := serve(t, Options{MaxConns: 1, MaxPerSource: 1, Handler: handlerFunc(func(context.Context, net.Conn) {
		if calls.Add(1) == 1 {
			_ = 1 / zero()
		}
		panic("the protocol failed on what an attacker sent")
	})})
	for range 3 {
		c := dial(t, srv)
		if !refused(t, c) {
			t.Fatal("a connection of a failed handler stayed open")
		}
	}
	// The slot is free again after each panic, so all three were served.
	if got := calls.Load(); got != 3 {
		t.Errorf("handled = %d, want 3", got)
	}
	// The first failure of the interval is described, so that an operator can
	// find the fault, and the count starts again after it was taken.
	got := srv.TakeStats()
	if got.Panics != 3 || !strings.Contains(got.Panic, "integer divide by zero") || !strings.Contains(got.Stack, "listener_test.go") {
		t.Errorf("TakeStats() = %+v, want 3 failures and the first one described with its place", got)
	}
	if again := srv.TakeStats(); again.Panics != 0 || again.Panic != "" || again.Stack != "" {
		t.Errorf("TakeStats() = %+v after it was taken, want nothing", again)
	}
}

// The text of a panic could hold what a client sent, so only its type is kept.
func TestServer_PanicWithText_DescribesOnlyItsType(t *testing.T) {
	t.Parallel()

	srv, _ := serve(t, Options{Handler: handlerFunc(func(context.Context, net.Conn) {
		panic("typed-by-an-attacker")
	})})
	if !refused(t, dial(t, srv)) {
		t.Fatal("the connection stayed open")
	}
	got := srv.TakeStats()
	if got.Panic != "string" || strings.Contains(got.Stack, "typed-by-an-attacker") {
		t.Errorf("TakeStats() = %q, %q; want the type of the value and no text of it", got.Panic, got.Stack)
	}
}

func TestServer_Stack_IsCut(t *testing.T) {
	t.Parallel()

	var deep func(n int)
	deep = func(n int) {
		if n == 0 {
			panic("deep")
		}
		deep(n - 1)
	}
	srv, _ := serve(t, Options{Handler: handlerFunc(func(context.Context, net.Conn) { deep(200) })})
	if !refused(t, dial(t, srv)) {
		t.Fatal("the connection stayed open")
	}
	if got := len(srv.TakeStats().Stack); got != 2048 {
		t.Errorf("len(Stack) = %d, want it cut at 2048", got)
	}
}

// A failing accept makes the server wait, longer each time, not spin.
func TestServer_FailingAccept_WaitsWithGrowingPauses(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	ln := &failingListener{errs: make(chan error), closed: make(chan struct{})}
	srv := New(Options{Listener: ln, Handler: newHoldHandler(), Clock: clk})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.Serve(ctx)
	}()

	// 5ms, doubled each time, and never more than a second.
	pauses := []time.Duration{
		5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond, 80 * time.Millisecond,
		160 * time.Millisecond, 320 * time.Millisecond, 640 * time.Millisecond, time.Second, time.Second,
	}
	for i, p := range pauses {
		ln.errs <- errors.New("too many open files")
		clk.BlockUntil(1)
		clk.Advance(p - time.Nanosecond)
		if clk.Pending() != 1 {
			t.Fatalf("pause %d ended before %v", i+1, p)
		}
		clk.Advance(time.Nanosecond)
		if clk.Pending() != 0 {
			t.Fatalf("pause %d lasted longer than %v", i+1, p)
		}
	}

	cancel()
	<-done
	if got := srv.TakeStats().AcceptErrors; got != 10 {
		t.Errorf("AcceptErrors = %d, want 10", got)
	}
}

type failingListener struct {
	errs   chan error
	closed chan struct{}
	once   sync.Once
}

func (l *failingListener) Accept() (net.Conn, error) {
	select {
	case err := <-l.errs:
		return nil, err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *failingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (*failingListener) Addr() net.Addr { return &net.TCPAddr{} }

type stubListener struct{}

func (stubListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (stubListener) Close() error              { return nil }
func (stubListener) Addr() net.Addr            { return &net.TCPAddr{} }

type fakeConn struct {
	net.Conn
	remote net.Addr
}

func (c fakeConn) RemoteAddr() net.Addr { return c.remote }
