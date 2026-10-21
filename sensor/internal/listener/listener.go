// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package listener accepts the connections of a honeypot within limits that
// do not depend on the protocol: how many connections there are, how many come
// from one source, and how long one lasts. The protocols run within them.
package listener

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock"
)

// Limits of a honeypot, for connections that are open at the same time.
const (
	// MaxConns is the number of open connections of a honeypot.
	MaxConns = 128
	// MaxPerSource is the number of open connections from one source.
	MaxPerSource = 8
	// MaxSession is how long a connection may last. A session is reported
	// when it ends, and a report older than five minutes is dropped, so the
	// longest session leaves most of that time for the queue and for repeated
	// requests.
	MaxSession = 2 * time.Minute
)

// Prefix length of the source of an IPv6 address: the smallest network that
// providers commonly assign to one customer.
const sourceBitsIPv6 = 64

// maxAcceptBackoff is the longest pause after a failed accept.
const maxAcceptBackoff = time.Second

// Handler serves one connection. It returns when the connection is done; the
// listener closes the connection after it.
type Handler interface {
	Handle(ctx context.Context, conn net.Conn)
}

// Options configure a Server. Zero limits mean the defaults above; tests set
// smaller ones.
type Options struct {
	Listener     net.Listener
	Handler      Handler
	Clock        clock.Clock
	MaxConns     int
	MaxPerSource int
	MaxSession   time.Duration
}

// Server accepts connections on a listener.
type Server struct {
	ln           net.Listener
	handler      Handler
	clock        clock.Clock
	maxConns     int
	maxPerSource int
	maxSession   time.Duration

	mu      sync.Mutex
	open    int
	sources map[netip.Addr]int

	refusedTotal  atomic.Int64
	refusedSource atomic.Int64
	acceptErrors  atomic.Int64

	// failures counts the handlers that panicked, and the first of them since
	// the last call of TakeStats is described.
	failMu       sync.Mutex
	failures     int
	failure      string
	failureWhere string
}

// Stats counts what the server turned away or lost since the last call of
// TakeStats.
type Stats struct {
	// RefusedTotal counts connections refused because the honeypot had its
	// most connections open.
	RefusedTotal int
	// RefusedSource counts connections refused because their source had its
	// most connections open.
	RefusedSource int
	// AcceptErrors counts failed accepts.
	AcceptErrors int
	// Panics counts handlers that panicked.
	Panics int
	// Panic and Stack describe the first of them: the kind of the failure and
	// where it happened. They hold no text that a client sent, see describe.
	Panic string
	Stack string
}

// New returns a server. It panics if a dependency is missing.
func New(o Options) *Server {
	if o.Listener == nil || o.Handler == nil || o.Clock == nil {
		panic("listener: missing listener, handler or clock")
	}
	s := &Server{
		ln:           o.Listener,
		handler:      o.Handler,
		clock:        o.Clock,
		maxConns:     o.MaxConns,
		maxPerSource: o.MaxPerSource,
		maxSession:   o.MaxSession,
		sources:      map[netip.Addr]int{},
	}
	if s.maxConns <= 0 {
		s.maxConns = MaxConns
	}
	if s.maxPerSource <= 0 {
		s.maxPerSource = MaxPerSource
	}
	if s.maxSession <= 0 {
		s.maxSession = MaxSession
	}
	return s
}

// Addr returns the address that the server listens on.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// Close closes the listener of a server that was not started.
func (s *Server) Close() error { return s.ln.Close() }

// TakeStats returns the counts since the last call and resets them.
func (s *Server) TakeStats() Stats {
	s.failMu.Lock()
	defer s.failMu.Unlock()
	st := Stats{
		RefusedTotal:  int(s.refusedTotal.Swap(0)),
		RefusedSource: int(s.refusedSource.Swap(0)),
		AcceptErrors:  int(s.acceptErrors.Swap(0)),
		Panics:        s.failures,
		Panic:         s.failure,
		Stack:         s.failureWhere,
	}
	s.failures, s.failure, s.failureWhere = 0, "", ""
	return st
}

// maxStack is the most of a stack that is kept.
const maxStack = 2048

// recordPanic counts a handler that panicked and keeps a description of the
// first one of the interval, so that the operator can find the fault.
func (s *Server) recordPanic(v any) {
	s.failMu.Lock()
	defer s.failMu.Unlock()
	s.failures++
	if s.failures == 1 {
		s.failure = describe(v)
		stack := debug.Stack()
		s.failureWhere = string(stack[:min(len(stack), maxStack)])
	}
}

// describe says what kind of failure a panic value is. The text of a runtime
// error names an index or a nil map, never a byte that a client sent; the
// text of any other value could, so only its type is kept.
func describe(v any) string {
	if err, ok := v.(runtime.Error); ok {
		return err.Error()
	}
	return fmt.Sprintf("%T", v)
}

// Serve accepts connections until ctx is done or the listener is closed, then
// closes the connections that are still open and waits for their handlers.
func (s *Server) Serve(ctx context.Context) {
	var wg sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { _ = s.ln.Close() })
	defer stop()
	defer wg.Wait()

	var backoff time.Duration
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// A full table of descriptors, for example: wait instead of
			// spinning.
			s.acceptErrors.Add(1)
			backoff = min(max(2*backoff, 5*time.Millisecond), maxAcceptBackoff)
			if s.clock.Wait(ctx, backoff) != nil {
				return
			}
			continue
		}
		backoff = 0
		source, ok := s.admit(conn)
		if !ok {
			_ = conn.Close()
			continue
		}
		wg.Go(func() { s.serve(ctx, conn, source) })
	}
}

// admit counts the connection if the limits allow it.
func (s *Server) admit(conn net.Conn) (netip.Addr, bool) {
	source, ok := sourceOf(conn.RemoteAddr())
	if !ok {
		return netip.Addr{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.open >= s.maxConns:
		s.refusedTotal.Add(1)
		return netip.Addr{}, false
	case s.sources[source] >= s.maxPerSource:
		s.refusedSource.Add(1)
		return netip.Addr{}, false
	}
	s.open++
	s.sources[source]++
	return source, true
}

// release uncounts a connection. A source without connections leaves the
// table, so that the table never holds more entries than there are open
// connections, however many sources have come by.
func (s *Server) release(source netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.open--
	if s.sources[source]--; s.sources[source] <= 0 {
		delete(s.sources, source)
	}
}

func (s *Server) serve(ctx context.Context, conn net.Conn, source netip.Addr) {
	// The connection is closed last: a client that sees it closed finds the
	// slot free and the count of a failed handler made.
	defer conn.Close() //nolint:errcheck // nothing to do about a failed close of a connection that is done.
	defer s.release(source)
	defer func() {
		// A protocol that panics on what an attacker sent must not end the
		// sensor, which would blind every other honeypot on it.
		if v := recover(); v != nil {
			s.recordPanic(v)
		}
	}()

	// The connection ends with the sensor.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	// The longest a session lasts, whatever the protocol does: the handler of
	// a protocol that is slow to give up cannot keep a slot for longer.
	connCtx, cancel := context.WithCancel(ctx)
	var watchdog sync.WaitGroup
	watchdog.Go(func() {
		if s.clock.Wait(connCtx, s.maxSession) == nil {
			_ = conn.Close()
		}
	})
	defer watchdog.Wait()
	defer cancel()

	s.handler.Handle(connCtx, conn)
}

// sourceOf returns the source network of an address: the address of an IPv4
// client, the /64 of an IPv6 client.
func sourceOf(a net.Addr) (netip.Addr, bool) {
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return netip.Addr{}, false
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return addr, true
	}
	return netip.PrefixFrom(addr, sourceBitsIPv6).Masked().Addr(), true
}
