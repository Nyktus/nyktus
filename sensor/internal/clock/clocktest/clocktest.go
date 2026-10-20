// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package clocktest provides a clock that tests move by hand. It is for tests
// only; the linter rejects it in other code.
package clocktest

import (
	"context"
	"sync"
	"time"
)

// Fake is a clock that moves only when a test says so. Its wall time and its
// monotonic time are independent, as they are on a host whose clock is set.
type Fake struct {
	mu      sync.Mutex
	changed *sync.Cond
	elapsed time.Duration
	wall    time.Time
	waiters map[*waiter]struct{}
}

type waiter struct {
	at   time.Duration
	done chan struct{}
}

// New returns a clock at its origin. Its wall time starts at the current time,
// so that a test that gives the deadlines of the clock to a real connection
// does not give it one in the past.
func New() *Fake {
	f := &Fake{wall: time.Now(), waiters: map[*waiter]struct{}{}}
	f.changed = sync.NewCond(&f.mu)
	return f
}

// Elapsed implements clock.Clock.
func (f *Fake) Elapsed() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.elapsed
}

// Deadline implements clock.Clock. It follows the wall time, so that a test
// can tell the value apart from the monotonic time.
func (f *Fake) Deadline(d time.Duration) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wall.Add(d)
}

// Wait implements clock.Clock.
func (f *Fake) Wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	if d <= 0 {
		f.mu.Unlock()
		return nil
	}
	w := &waiter{at: f.elapsed + d, done: make(chan struct{})}
	f.waiters[w] = struct{}{}
	f.changed.Broadcast()
	f.mu.Unlock()

	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		f.mu.Lock()
		delete(f.waiters, w)
		f.changed.Broadcast()
		f.mu.Unlock()
		return ctx.Err()
	}
}

// Advance moves both clocks forward by d and wakes every wait that is due.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.elapsed += d
	f.wall = f.wall.Add(d)
	for w := range f.waiters {
		if w.at <= f.elapsed {
			close(w.done)
			delete(f.waiters, w)
		}
	}
	f.changed.Broadcast()
}

// SetWall moves the wall time by d without moving the monotonic time, as an
// operator or a time service does.
func (f *Fake) SetWall(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wall = f.wall.Add(d)
}

// BlockUntil returns once n waits are pending. Tests use it to know that the
// code under test has reached its wait, instead of sleeping.
func (f *Fake) BlockUntil(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for len(f.waiters) < n {
		f.changed.Wait()
	}
}

// Pending returns the number of waits that have not ended.
func (f *Fake) Pending() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.waiters)
}
