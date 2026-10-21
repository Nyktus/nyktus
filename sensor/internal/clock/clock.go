// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package clock is the source of time of the sensor. The sensor never reads a
// wall clock: it measures how long ago a session began with a monotonic clock,
// so that a clock that is set while a session runs, or that differs from the
// one of the server, cannot change the age of a report.
package clock

import (
	"context"
	"time"
)

// Clock is the time source of the sensor. Code that depends on time receives
// one, so that tests move time instead of waiting for it.
type Clock interface {
	// Elapsed returns the time since an arbitrary origin, read from the
	// monotonic clock. It never goes back, whatever happens to the wall clock.
	Elapsed() time.Duration
	// Deadline returns the instant that lies d from now, for the deadlines of
	// connections.
	Deadline(d time.Duration) time.Time
	// Wait blocks for d or until ctx is done, and returns the error of ctx in
	// that case.
	Wait(ctx context.Context, d time.Duration) error
}

// System is the clock of the operating system.
type System struct {
	// origin carries a monotonic reading, which Since uses.
	origin time.Time
}

// NewSystem returns the clock of the operating system, whose origin is now.
func NewSystem() *System {
	return &System{origin: time.Now()}
}

// Elapsed implements Clock.
func (s *System) Elapsed() time.Duration {
	return time.Since(s.origin)
}

// Deadline implements Clock.
func (*System) Deadline(d time.Duration) time.Time {
	return time.Now().Add(d)
}

// Wait implements Clock.
func (*System) Wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
