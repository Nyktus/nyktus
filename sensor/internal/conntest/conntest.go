// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package conntest provides a connection for the tests of the honeypots: its
// client has sent everything in advance, so that a service reads the script and
// then finds the end of the stream. It is for tests only; the linter rejects it
// in other code.
package conntest

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"time"
)

// Conn serves a script to the server and records what the server writes and the
// deadlines it sets.
type Conn struct {
	mu             sync.Mutex
	input          *bytes.Reader
	read           int
	output         bytes.Buffer
	readDeadlines  []time.Time
	writeDeadlines []time.Time
	// okWrites is the number of writes that succeed before the rest fail, or
	// negative if none fails.
	okWrites int
}

// New returns a connection whose client sends script.
func New(script []byte) *Conn {
	return &Conn{input: bytes.NewReader(script), okWrites: -1}
}

// FailAfter makes every write fail after n writes have succeeded.
func (c *Conn) FailAfter(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.okWrites = n
}

// Read implements net.Conn.
func (c *Conn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.input.Read(p)
	c.read += n
	return n, err
}

// Write implements net.Conn.
func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.okWrites == 0 {
		return 0, errors.New("write failed")
	}
	if c.okWrites > 0 {
		c.okWrites--
	}
	return c.output.Write(p)
}

// SetReadDeadline implements net.Conn and records the deadline.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadlines = append(c.readDeadlines, t)
	return nil
}

// SetWriteDeadline implements net.Conn and records the deadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadlines = append(c.writeDeadlines, t)
	return nil
}

// SetDeadline implements net.Conn.
func (c *Conn) SetDeadline(time.Time) error { return nil }

// Close implements net.Conn.
func (c *Conn) Close() error { return nil }

// LocalAddr implements net.Conn.
func (c *Conn) LocalAddr() net.Addr { return &net.TCPAddr{} }

// RemoteAddr implements net.Conn.
func (c *Conn) RemoteAddr() net.Addr { return &net.TCPAddr{} }

// Written returns what the server has written.
func (c *Conn) Written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.output.Bytes()...)
}

// BytesRead returns how many bytes the server has read.
func (c *Conn) BytesRead() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.read
}

// ReadDeadlines returns the deadlines that the server set for reading.
func (c *Conn) ReadDeadlines() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.readDeadlines...)
}

// WriteDeadlines returns the deadlines that the server set for writing.
func (c *Conn) WriteDeadlines() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.writeDeadlines...)
}
