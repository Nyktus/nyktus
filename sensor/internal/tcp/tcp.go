// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tcp emulates a port that speaks no protocol of its own: it accepts a
// connection, says a fixed banner if the operator chose one, and reads and
// drops what the client sends until the client leaves or the limits of the
// connection end it.
//
// It never answers. What the client sent is not looked at and not kept, because
// the first bytes of a connection are where credentials stand, such as the
// header of a Basic login or the cookie of an RDP client. The session is a
// connection and nothing else.
package tcp

import (
	"context"
	"io"
	"net"

	"nyktus.org/nyktus/sensor/internal/clock"
	"nyktus.org/nyktus/sensor/internal/guard"
	"nyktus.org/nyktus/sensor/internal/session"
)

// Config holds the text of a honeypot.
type Config struct {
	// Banner is sent when the connection opens. Empty means the port says
	// nothing before the client does. There is no default: a text that every
	// installation shares is one that a scanner can look for.
	Banner string
}

// Service is the honeypot of a port without a protocol.
type Service struct {
	cfg   Config
	clock clock.Clock
}

// New returns a honeypot. It panics if clk is nil.
func New(cfg Config, clk clock.Clock) *Service {
	if clk == nil {
		panic("tcp: missing clock")
	}
	return &Service{cfg: cfg, clock: clk}
}

// Serve sends the banner and then reads and drops what the client sends. It
// returns when the client has gone, was silent for too long or has sent more
// than the guard allows, and leaves closing the connection to its caller. The
// session records nothing but that it happened.
func (s *Service) Serve(_ context.Context, conn net.Conn, _ *session.Session) {
	g := guard.New(conn, s.clock)
	if s.cfg.Banner != "" {
		if _, err := g.Write([]byte(s.cfg.Banner)); err != nil {
			return
		}
	}
	// The listener ends the connection when the context ends or the session has
	// lasted its longest time, which unblocks the read.
	_, _ = io.Copy(io.Discard, g)
}
