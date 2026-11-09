// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package session records what one attacker did in one connection and turns it
// into a report. The protocols fill a session; the reporter sends it.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/secret"
)

// MaxAge is the oldest a session may be when it is sent. The server takes the
// age within the same bound, so an older report would be stored with a wrong
// time; the sensor drops it.
const MaxAge = 5 * time.Minute

// MaxAttempts is the number of logins that a session keeps.
const MaxAttempts = report.MaxAttempts

// Honeypot names the honeypot that a session belongs to and holds the secret
// that its reports are sent with.
type Honeypot struct {
	ID      string
	Service string
	Secret  secret.Secret
}

// Attr is the attribute that names the honeypot in a log record: its
// identifier and service, never the secret. The attributes are inlined, so
// that a record has the fields honeypot_id and service.
func (h *Honeypot) Attr() slog.Attr {
	return slog.Group("", slog.String("honeypot_id", h.ID), slog.String("service", h.Service))
}

// LogValue implements slog.LogValuer, so that a honeypot that is logged as a
// value, not through Attr, shows the same and no secret.
func (h *Honeypot) LogValue() slog.Value {
	return slog.GroupValue(slog.String("honeypot_id", h.ID), slog.String("service", h.Service))
}

// Session is one connection of an attacker. It is not safe for concurrent use:
// one goroutine fills it, or, where a session spans connections, the holder of
// its lock does. It is not changed after End.
type Session struct {
	honeypot *Honeypot
	clock    clock.Clock
	id       string
	started  time.Duration
	ended    time.Duration
	finished bool
	clientIP netip.Addr
	port     int

	attempts        []report.Attempt
	clientVersion   string
	database        string
	applicationName string
	query           *report.Query
	toolCalls       []report.ToolCall
}

// Start begins a session of the honeypot for a connection from remote to the
// local address local.
func Start(clk clock.Clock, hp *Honeypot, remote, local netip.AddrPort) (*Session, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("create session id: %w", err)
	}
	return &Session{
		honeypot: hp,
		clock:    clk,
		id:       hex.EncodeToString(b[:]),
		started:  clk.Elapsed(),
		// The server refuses an address with a zone and reads a mapped IPv4
		// address as the IPv4 address.
		clientIP: remote.Addr().Unmap().WithZone(""),
		port:     int(local.Port()),
	}, nil
}

// Honeypot returns the honeypot of the session.
func (s *Session) Honeypot() *Honeypot { return s.honeypot }

// ID returns the identifier of the session.
func (s *Session) ID() string { return s.id }

// AddAttempt records a login. It reports false and records nothing once the
// session holds the most that it keeps.
func (s *Session) AddAttempt(a report.Attempt) bool {
	if len(s.attempts) >= MaxAttempts {
		return false
	}
	s.attempts = append(s.attempts, a)
	return true
}

// SetClientVersion records the version string that the client announced. The
// caller keeps it within report.MaxClientVersion.
func (s *Session) SetClientVersion(v string) { s.clientVersion = v }

// SetStartup records what a PostgreSQL client asked for in its startup message:
// the database and the name it calls itself. The caller keeps each within its
// limit in report.
func (s *Session) SetStartup(database, applicationName string) {
	s.database = database
	s.applicationName = applicationName
}

// SetQuery records the search of a directory client. Only the first search of a
// session is kept; it reports false for a later one.
func (s *Session) SetQuery(q report.Query) bool {
	if s.query != nil {
		return false
	}
	s.query = &q
	return true
}

// AddToolCall records a call of a tool. It reports false and records nothing once
// the session holds the most that it keeps.
func (s *Session) AddToolCall(c report.ToolCall) bool {
	if len(s.toolCalls) >= report.MaxToolCalls {
		return false
	}
	s.toolCalls = append(s.toolCalls, c)
	return true
}

// Attempts returns the number of logins recorded.
func (s *Session) Attempts() int { return len(s.attempts) }

// End closes the session now. A second call changes nothing.
func (s *Session) End() { s.EndAt(s.clock.Elapsed()) }

// EndAt closes the session as of at, a time of the clock of the session. A
// service whose session is over only after a time of silence ends it at its
// last traffic, so that the duration does not hold the silence. A second call
// changes nothing.
func (s *Session) EndAt(at time.Duration) {
	if s.finished {
		return
	}
	s.finished = true
	s.ended = at
}

// EventType names the stage that the session reached, for the log. The server
// decides the kind of event from the report; this is what it will find in a
// session of a service that logs in, searches a directory or offers tools.
func (s *Session) EventType() string {
	if len(s.toolCalls) > 0 {
		return "tool_call"
	}
	if s.query != nil {
		return "directory_query"
	}
	if len(s.attempts) > 0 {
		return "login_attempt"
	}
	return "connection"
}

// Attr is the attribute that describes the session in a log record: the
// honeypot, the kind of event and the number of logins, and nothing that the
// attacker typed.
func (s *Session) Attr() slog.Attr {
	return slog.Group("",
		slog.String("honeypot_id", s.honeypot.ID),
		slog.String("service", s.honeypot.Service),
		slog.String("event_type", s.EventType()),
		slog.Int("attempts", len(s.attempts)),
	)
}

// LogValue implements slog.LogValuer, so that a session that is logged as a
// value shows the same.
func (s *Session) LogValue() slog.Value { return s.Attr().Value }

// Report returns the report of the session as it is sent at the time now, and
// false if the session began more than MaxAge before. The age is computed from
// the monotonic clock at every call, so a repeated report is as much older as
// the pause before it.
func (s *Session) Report(now time.Duration) (report.Session, bool) {
	age := now - s.started
	if age > MaxAge {
		return report.Session{}, false
	}
	end := s.ended
	if !s.finished {
		end = now
	}
	attempts := make([]report.Attempt, len(s.attempts))
	copy(attempts, s.attempts)
	var query *report.Query
	if s.query != nil {
		q := *s.query
		query = &q
	}
	var toolCalls []report.ToolCall
	if len(s.toolCalls) > 0 {
		toolCalls = make([]report.ToolCall, len(s.toolCalls))
		copy(toolCalls, s.toolCalls)
	}
	return report.Session{
		Version:    report.Version,
		Type:       report.TypeSession,
		SessionID:  s.id,
		AgeMS:      age.Milliseconds(),
		DurationMS: (end - s.started).Milliseconds(),
		ClientIP:   s.clientIP.String(),
		Port:       s.port,

		ClientVersion:   s.clientVersion,
		Database:        s.database,
		ApplicationName: s.applicationName,
		Attempts:        attempts,
		Query:           query,
		ToolCalls:       toolCalls,
	}, true
}
