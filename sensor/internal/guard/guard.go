// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package guard sets the limits of a connection that do not depend on the
// protocol: how long it may be silent, how long a write may block and how much
// the client may send in all. Every honeypot reads and writes through it, so
// that no protocol can forget one of them. The listener bounds the whole
// session in addition.
package guard

import (
	"errors"
	"net"
	"sync"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock"
)

// Limits of a connection.
const (
	// IdleTimeout is how long a connection may be silent.
	IdleTimeout = 30 * time.Second
	// WriteTimeout is how long a write may block on a client that does not
	// read.
	WriteTimeout = 10 * time.Second
	// MaxReadBytes is the most that a connection may send in all. A real login
	// takes a few KiB, and a flood of negotiations or of messages ends the
	// session at it.
	MaxReadBytes = 16 << 10
)

// ErrTooMuch ends a connection that has sent more than it may.
var ErrTooMuch = errors.New("guard: the client sent too much")

// Conn is a connection within the limits. A library may read and write from
// several goroutines, so the count of bytes is protected.
type Conn struct {
	net.Conn
	clock clock.Clock

	mu   sync.Mutex
	left int
}

// New returns conn within the limits. It panics if clk is nil.
func New(conn net.Conn, clk clock.Clock) *Conn {
	if clk == nil {
		panic("guard: missing clock")
	}
	return &Conn{Conn: conn, clock: clk, left: MaxReadBytes}
}

// Read gives the client the idle time again, and reads no more than what is
// left of the bytes that it may send.
func (c *Conn) Read(p []byte) (int, error) {
	c.mu.Lock()
	left := c.left
	c.mu.Unlock()
	if left <= 0 {
		return 0, ErrTooMuch
	}
	if err := c.SetReadDeadline(c.clock.Deadline(IdleTimeout)); err != nil {
		return 0, err
	}
	if len(p) > left {
		p = p[:left]
	}
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.left -= n
	c.mu.Unlock()
	return n, err
}

// Write writes with a deadline.
func (c *Conn) Write(p []byte) (int, error) {
	if err := c.SetWriteDeadline(c.clock.Deadline(WriteTimeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}
