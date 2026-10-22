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
	"net"

	"nyktus.org/nyktus/sensor/internal/clock"
	"nyktus.org/nyktus/sensor/internal/guard"
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

// maxRounds is the number of times that the login is offered, as many as a
// session keeps logins. The limits of the connection are those of the guard.
const maxRounds = session.MaxAttempts

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
	g := guard.New(conn, s.clock)
	r := &lineReader{r: bufio.NewReader(g)}
	write := func(b []byte) error {
		_, err := g.Write(b)
		return err
	}

	// A login whose name has been entered is recorded wherever the dialog
	// ends after that: when the prompt for the password cannot be written, the
	// client leaves or the password stays unfinished.
	var open *report.Attempt
	defer func() {
		if open != nil {
			sess.AddAttempt(*open)
		}
	}()

	// The options that a Telnet server offers first: it echoes what the
	// client types, and it sends no go-ahead.
	opening := []byte{iac, will, optEcho, iac, will, optSGA}
	if write(append(opening, s.cfg.Banner...)) != nil {
		return
	}
	for range maxRounds {
		if ctx.Err() != nil || write([]byte(s.cfg.LoginPrompt)) != nil {
			return
		}
		user, err := r.read(report.MaxUsername, write)
		if err != nil {
			// A name that was not entered, because the client left, was silent
			// for too long or sent too much, is no login.
			return
		}
		if write([]byte("\r\n")) != nil {
			return
		}
		if user.n == 0 {
			// Like login(1), an empty name asks again.
			continue
		}

		open = &report.Attempt{Username: string(user.text)}
		if write([]byte(passwordPrompt)) != nil {
			return
		}
		pass, err := r.read(0, nil)
		if pass.n > 0 || pass.complete {
			n := pass.n
			open.PasswordLength = &n
		}
		if err != nil || !pass.complete {
			return
		}
		sess.AddAttempt(*open)
		open = nil
		if write([]byte("\r\nLogin incorrect\r\n")) != nil {
			return
		}
	}
}
