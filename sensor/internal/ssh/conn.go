// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ssh

import (
	"bytes"
	"net"
	"sync"

	"nyktus.org/nyktus/sensor/internal/clock"
	"nyktus.org/nyktus/sensor/internal/guard"
)

// The library reads the version of the client byte by byte, and gives up at a
// line of 255 bytes before its end, so the longest version it accepts has 254,
// and after 1024 lines that are not one (RFC 4253, section 4.2). The honeypot
// reads the same, so that the two agree.
const (
	maxVersionLine = 255
	maxLinesBefore = 1024
)

// guardedConn is the connection that the library reads and writes. The library
// reads on its own, so the limits of the honeypot are set on the connection it
// is given. It also reads the version that the client announces, which the
// library shows only after the key exchange.
type guardedConn struct {
	*guard.Conn

	// The library reads and writes from different goroutines, and the version
	// is read when they are done.
	mu      sync.Mutex
	line    []byte
	lines   int
	version string
	found   bool
}

func newGuardedConn(conn net.Conn, clk clock.Clock) *guardedConn {
	return &guardedConn{Conn: guard.New(conn, clk)}
}

func (c *guardedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.scan(p[:n])
	c.mu.Unlock()
	return n, err
}

// scan looks for the version of the client in what it sent: the first line that
// starts with "SSH-". Lines before it are skipped, as the library skips them,
// and it gives up where the library does, at a line that is too long or after
// too many lines. The caller holds the lock.
func (c *guardedConn) scan(b []byte) {
	for _, ch := range b {
		if c.found {
			return
		}
		if ch != '\n' {
			c.line = append(c.line, ch)
			if len(c.line) >= maxVersionLine {
				c.found = true
			}
			continue
		}
		if bytes.HasPrefix(c.line, []byte("SSH-")) {
			c.version = string(bytes.TrimSuffix(c.line, []byte("\r")))
			c.found = true
			return
		}
		c.line = c.line[:0]
		if c.lines++; c.lines >= maxLinesBefore {
			c.found = true
		}
	}
}

// clientVersion returns the version that the client announced, or an empty text
// if it has not announced one.
func (c *guardedConn) clientVersion() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}
