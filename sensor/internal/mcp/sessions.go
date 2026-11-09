// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"net/netip"
	"sync"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock"
	"nyktus.org/nyktus/sensor/internal/listener"
	"nyktus.org/nyktus/sensor/internal/session"
)

// Limits of a session of a source.
const (
	// quietPeriod is how long a source may be silent before its session ends. It
	// is longer than the idle time of a connection because an AI agent thinks
	// between two calls, and many clients close their connection meanwhile.
	quietPeriod = time.Minute
	// sweepInterval is how often sessions are checked for their end.
	sweepInterval = 5 * time.Second
	// maxSession is the longest a session lasts, so that it ends within the two
	// minutes of a connection although it is only checked every sweepInterval.
	maxSession = listener.MaxSession - sweepInterval
	// maxSessions is the number of sessions of a honeypot that are open at the
	// same time, as many as it has connections.
	maxSessions = listener.MaxConns
)

// sessions holds the open sessions of a honeypot, one per source. HTTP has no
// lasting connection and the protocol no identifier of a session, so the requests
// of a source within a short time are one session: otherwise the listing of the
// tools would raise the event and the alert, and the call would come after them.
type sessions struct {
	clock   clock.Clock
	start   func(remote, local netip.AddrPort) (*session.Session, error)
	submit  func(*session.Session)
	mu      sync.Mutex
	open    map[netip.Addr]*entry
	dropped int
}

type entry struct {
	session *session.Session
	began   time.Duration
	last    time.Duration
	// named reports whether the client has said who it is.
	named bool
	// active reports whether the source has sent a request of the protocol, and
	// not only connected.
	active bool
}

func (e *entry) over(now time.Duration) bool {
	return now-e.last >= quietPeriod || now-e.began >= maxSession
}

// with counts a request of the source and passes its session to fill, which may
// be nil. A source that finds the table full takes the place of the oldest
// source that has only connected, so that connections alone cannot keep a client
// from being recorded; if every place holds a client, it is served but not
// recorded, and counted.
func (t *sessions) with(remote, local netip.AddrPort, fill func(*entry)) {
	key := listener.Source(remote.Addr())
	now := t.clock.Elapsed()
	var ended []*session.Session
	defer func() {
		// Outside the lock, as the queue of reports has one of its own.
		for _, s := range ended {
			t.submit(s)
		}
	}()
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.open[key]
	if e != nil && e.over(now) {
		e.session.EndAt(e.last)
		ended = append(ended, e.session)
		delete(t.open, key)
		e = nil
	}
	if e == nil {
		if len(t.open) >= maxSessions {
			victim, ok := t.oldestIdle()
			if !ok {
				t.dropped++
				return
			}
			t.open[victim].session.EndAt(t.open[victim].last)
			ended = append(ended, t.open[victim].session)
			delete(t.open, victim)
		}
		s, err := t.start(remote, local)
		if err != nil {
			t.dropped++
			return
		}
		e = &entry{session: s, began: now}
		t.open[key] = e
	}
	e.last = now
	if fill != nil {
		e.active = true
		fill(e)
	}
}

// oldestIdle returns the source that has only connected and has been silent
// the longest. The caller holds the lock.
func (t *sessions) oldestIdle() (netip.Addr, bool) {
	var (
		oldest netip.Addr
		found  bool
		last   time.Duration
	)
	for key, e := range t.open {
		if !e.active && (!found || e.last < last) {
			oldest, found, last = key, true, e.last
		}
	}
	return oldest, found
}

// expire ends the sessions that are over and reports them.
func (t *sessions) expire() {
	t.finish(func(e *entry, now time.Duration) bool { return e.over(now) })
}

// flush ends every session and reports it. Nothing reaches the table after the
// connections have ended, which is when the caller flushes it.
func (t *sessions) flush() {
	t.finish(func(*entry, time.Duration) bool { return true })
}

func (t *sessions) finish(done func(*entry, time.Duration) bool) {
	now := t.clock.Elapsed()
	var ended []*session.Session
	t.mu.Lock()
	for key, e := range t.open {
		if done(e, now) {
			e.session.EndAt(e.last)
			ended = append(ended, e.session)
			delete(t.open, key)
		}
	}
	t.mu.Unlock()
	for _, s := range ended {
		t.submit(s)
	}
}

// takeDropped returns how many requests were not recorded since the last call.
func (t *sessions) takeDropped() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.dropped
	t.dropped = 0
	return n
}
