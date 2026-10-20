// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package telnet emulates the login of a Telnet server, as on network devices
// and old servers: it offers the options of a real server, shows a banner and
// asks for a user name and a password, and refuses every login.
//
// It offers nothing behind the login. What the client types is read, counted
// and recorded in the session, never run, never answered with anything but the
// prompts, and never passed on. A password is not kept: only its length.
package telnet

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/session"
)

// Defaults of the texts of a honeypot. Operators change them, because a
// banner that every installation shares is one a scanner can look for.
const (
	DefaultBanner      = "\r\nUbuntu 22.04.4 LTS\r\n"
	DefaultLoginPrompt = "login: "
)

const passwordPrompt = "Password: "

// Limits of a connection. The listener bounds the whole session in addition.
const (
	// idleTimeout is how long a connection may be silent.
	idleTimeout = 30 * time.Second
	// writeTimeout is how long a write may block on a client that does not
	// read.
	writeTimeout = 10 * time.Second
	// maxReadBytes is the most that a connection may send, commands included,
	// so that a flood of negotiations ends the session as well.
	maxReadBytes = 16 << 10
	// maxRounds is the number of times that the login is offered, as many as
	// a session keeps logins.
	maxRounds = session.MaxAttempts
)

// Config holds the texts of a honeypot.
type Config struct {
	// Banner is sent before the first prompt.
	Banner string
	// LoginPrompt asks for the user name.
	LoginPrompt string
}

// Service is the Telnet honeypot.
type Service struct {
	cfg   Config
	clock clock.Clock
}

// New returns a Telnet honeypot. It panics if clk is nil.
func New(cfg Config, clk clock.Clock) *Service {
	if clk == nil {
		panic("telnet: missing clock")
	}
	return &Service{cfg: cfg, clock: clk}
}

// Serve plays the login on conn and records the logins in sess. It returns
// when the client has gone, was silent for too long, sent too much or has used
// up its logins, and leaves closing the connection to its caller.
func (s *Service) Serve(ctx context.Context, conn net.Conn, sess *session.Session) {
	w := &writer{conn: conn, clock: s.clock}
	r := &lineReader{r: bufio.NewReader(&budgetReader{
		r:    &idleReader{conn: conn, clock: s.clock},
		left: maxReadBytes,
	})}

	// The options that a Telnet server offers first: it echoes what the
	// client types, and it sends no go-ahead.
	opening := []byte{iac, will, optEcho, iac, will, optSGA}
	if w.write(append(opening, s.cfg.Banner...)) != nil {
		return
	}
	for range maxRounds {
		if ctx.Err() != nil || w.write([]byte(s.cfg.LoginPrompt)) != nil {
			return
		}
		user, err := r.read(report.MaxUsername, w.echo)
		if err != nil {
			// A name that was not entered, because the client left, was silent
			// for too long or sent too much, is no login.
			return
		}
		if w.write([]byte("\r\n")) != nil {
			return
		}
		if user.n == 0 {
			// Like login(1), an empty name asks again.
			continue
		}

		attempt := report.Attempt{Username: string(user.text)}
		if w.write([]byte(passwordPrompt)) != nil {
			return
		}
		pass, err := r.read(0, nil)
		if pass.n > 0 || pass.complete {
			n := pass.n
			attempt.PasswordLength = &n
		}
		sess.AddAttempt(attempt)
		if err != nil || !pass.complete {
			return
		}
		if w.write([]byte("\r\nLogin incorrect\r\n")) != nil {
			return
		}
	}
}

// writer writes to the client with a deadline.
type writer struct {
	conn  net.Conn
	clock clock.Clock
}

func (w *writer) write(b []byte) error {
	if err := w.conn.SetWriteDeadline(w.clock.Deadline(writeTimeout)); err != nil {
		return err
	}
	_, err := w.conn.Write(b)
	return err
}

// echo shows a typed character to the client, as a Telnet server that offers
// to echo does.
func (w *writer) echo(b byte) error {
	return w.write([]byte{b})
}

// idleReader reads from the client and gives it the idle time again with
// every read.
type idleReader struct {
	conn  net.Conn
	clock clock.Clock
}

func (r *idleReader) Read(p []byte) (int, error) {
	if err := r.conn.SetReadDeadline(r.clock.Deadline(idleTimeout)); err != nil {
		return 0, err
	}
	return r.conn.Read(p)
}

// errTooMuch ends a connection that has sent more than it may.
var errTooMuch = errors.New("telnet: the client sent too much")

// budgetReader reads at most left bytes in all.
type budgetReader struct {
	r    io.Reader
	left int
}

func (b *budgetReader) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, errTooMuch
	}
	if len(p) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= n
	return n, err
}
