// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package postgres emulates the login of a PostgreSQL server: it reads the
// startup message of a client, asks for the password in clear text, as a server
// does whose pg_hba.conf says "password", and refuses it.
//
// It offers nothing behind the login. There is no session, no query and no SQL:
// the connection ends with the refusal. What the client sent is read, counted
// and recorded in the session, the password included. A server that asks for
// SCRAM never sees a password, so this one asks in clear text.
package postgres

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"

	"nyktus.org/nyktus/sensor/internal/clock"
	"nyktus.org/nyktus/sensor/internal/guard"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/session"
)

// Limits of the dialog, within those of the connection.
const (
	// maxStartup is the longest startup message that a real server reads
	// (MAX_STARTUP_PACKET_LENGTH). It is the one allocation that the length of a
	// client decides.
	maxStartup = 10000
	// maxPackets is how many packets a client may send before its startup
	// message: a request for TLS and one for GSSAPI encryption, as libpq sends
	// one after the other.
	maxPackets = 3
	// maxPasswordMessage is the longest message with a password that is read.
	// A longer one ends the session, and the login is recorded without it.
	maxPasswordMessage = 2048
)

// authenticationCleartextPassword is the code of the request for a password in
// clear text.
const authenticationCleartextPassword = 3

// Codes of the first packet of a client. A code below 0x10000 does not exist;
// the high half of the others is the major version of the protocol.
const (
	sslRequest   = 80877103
	gssRequest   = 80877104
	majorVersion = 3
)

var errMalformed = errors.New("postgres: malformed message")

// Config holds the settings of a honeypot.
type Config struct {
	// Certificate, if set, lets a client ask for TLS. It comes from the
	// operator: a certificate that the sensor made itself would identify it.
	Certificate *Certificate
}

// Certificate is a certificate with its private key. It writes nothing but a
// placeholder, whatever formats or logs a value that holds it ends up in.
type Certificate struct {
	tls.Certificate
}

const redacted = "[redacted]"

// String implements fmt.Stringer.
func (Certificate) String() string { return redacted }

// GoString implements fmt.GoStringer, which %#v and %+v of a struct use.
func (Certificate) GoString() string { return redacted }

// LogValue implements slog.LogValuer.
func (Certificate) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText implements encoding.TextMarshaler, which JSON and YAML encoders
// use.
func (Certificate) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Service is the PostgreSQL honeypot.
type Service struct {
	clock clock.Clock
	tls   *tls.Config
}

// New returns a PostgreSQL honeypot. It panics if clk is nil.
func New(cfg Config, clk clock.Clock) *Service {
	if clk == nil {
		panic("postgres: missing clock")
	}
	s := &Service{clock: clk}
	if cfg.Certificate != nil {
		s.tls = &tls.Config{Certificates: []tls.Certificate{cfg.Certificate.Certificate}, MinVersion: tls.VersionTLS12}
	}
	return s
}

// stream is what the dialog reads and writes: the connection, or TLS on it.
type stream struct {
	io.Writer
	r         *bufio.Reader
	encrypted bool
}

// Serve plays the login on conn and records it in sess. It returns when the
// refusal is sent, when the client has gone, was silent for too long or sent
// too much, and leaves closing the connection to its caller.
func (s *Service) Serve(ctx context.Context, conn net.Conn, sess *session.Session) {
	if ctx.Err() != nil {
		return
	}
	st, c, ok := s.negotiate(ctx, guard.New(conn, s.clock))
	if !ok {
		return
	}
	sess.SetStartup(report.Clean(st.database, report.MaxDatabase), report.Clean(st.application, report.MaxApplicationName))
	if st.user == "" {
		return
	}

	// The user is entered once the startup message is complete, so the login
	// is recorded wherever the dialog ends after that.
	attempt := report.Attempt{Username: report.Clean(st.user, report.MaxUsername)}
	defer func() { sess.AddAttempt(attempt) }()

	s.exchange(c, &attempt)
}

// exchange asks for the password and refuses it, as a server does that has no
// such user. The login is recorded once the user is known, so a password that
// does not arrive in full leaves a login without one.
func (s *Service) exchange(c *stream, attempt *report.Attempt) {
	if write(c, message('R', binary.BigEndian.AppendUint32(nil, authenticationCleartextPassword))) != nil {
		return
	}
	password, ok := readPassword(c.r)
	if !ok {
		return
	}
	attempt.Password = &password
	_ = write(c, errorResponse(attempt.Username))
}

// negotiate answers the requests for encryption and reads the startup message.
// It returns the stream that the dialog goes on with, and reports false if the
// client did not send a startup message that this server speaks.
func (s *Service) negotiate(ctx context.Context, conn net.Conn) (startup, *stream, bool) {
	c := &stream{Writer: conn, r: bufio.NewReader(conn)}
	for range maxPackets {
		code, body, err := readPacket(c.r)
		if err != nil {
			return startup{}, nil, false
		}
		switch {
		case code == sslRequest && s.tls != nil && !c.encrypted:
			if write(c, []byte{'S'}) != nil {
				return startup{}, nil, false
			}
			// TLS reads the connection, not the buffer: what arrived in clear text
			// before the answer is never taken for part of the encrypted dialog.
			tc := tls.Server(conn, s.tls)
			if tc.HandshakeContext(ctx) != nil {
				return startup{}, nil, false
			}
			c = &stream{Writer: tc, r: bufio.NewReader(tc), encrypted: true}
		case code == sslRequest || code == gssRequest:
			// No encryption is offered, and the client goes on as it is.
			if write(c, []byte{'N'}) != nil {
				return startup{}, nil, false
			}
		case code>>16 == majorVersion:
			st, err := parseStartup(body)
			return st, c, err == nil
		default:
			// A cancel request, or a protocol that does not exist.
			return startup{}, nil, false
		}
	}
	return startup{}, nil, false
}

// readPacket reads one packet of the startup phase: its length, which counts
// itself, its code and the rest. The length is checked before anything is
// allocated.
func readPacket(r io.Reader) (code uint32, body []byte, err error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n < 8 || n > maxStartup {
		return 0, nil, errMalformed
	}
	buf := make([]byte, n-4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return binary.BigEndian.Uint32(buf), buf[4:], nil
}

// startup holds what a client says about itself in its startup message.
type startup struct {
	user, database, application string
}

// parseStartup reads the parameters of a startup message: pairs of names and
// values, each ended by a zero byte, and one more zero byte after the last.
// Parameters other than the three that are recorded are skipped.
func parseStartup(b []byte) (startup, error) {
	var st startup
	for {
		key, rest, ok := cutString(b)
		if !ok {
			return startup{}, errMalformed
		}
		if key == "" {
			return st, nil
		}
		// A value without its end leaves nothing, and the next name is refused.
		value, rest, _ := cutString(rest)
		switch key {
		case "user":
			st.user = value
		case "database":
			st.database = value
		case "application_name":
			st.application = value
		}
		b = rest
	}
}

// cutString splits a string that ends with a zero byte from what follows.
func cutString(b []byte) (s string, rest []byte, ok bool) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], true
		}
	}
	return "", nil, false
}

// readPassword reads the message with the password: its type, its length, which
// is checked before anything is allocated, and the password with its end. The
// password is cut to the limit of the report; a message without the end of the
// string is no password.
func readPassword(r *bufio.Reader) (string, bool) {
	typ, err := r.ReadByte()
	if err != nil || typ != 'p' {
		return "", false
	}
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return "", false
	}
	n := binary.BigEndian.Uint32(head[:])
	if n < 5 || n-4 > maxPasswordMessage {
		return "", false
	}
	buf := make([]byte, n-4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", false
	}
	password, _, ok := cutString(buf)
	if !ok {
		return "", false
	}
	return report.Clean(password, report.MaxPassword), true
}

// errorResponse is the refusal of a server for a wrong password. The message
// names the user as the client gave it, in printable ASCII: it is the one part
// of what the client typed that is sent back.
func errorResponse(user string) []byte {
	name := make([]byte, 0, len(user))
	for i := range len(user) {
		if c := user[i]; c >= 0x20 && c <= 0x7e {
			name = append(name, c)
		}
	}
	var body []byte
	for _, f := range []struct{ code, text string }{
		{"S", "FATAL"},
		{"V", "FATAL"},
		{"C", "28P01"},
		{"M", `password authentication failed for user "` + string(name) + `"`},
		{"F", "auth.c"},
		{"L", "331"},
		{"R", "auth_failed"},
	} {
		body = append(body, f.code...)
		body = append(body, f.text...)
		body = append(body, 0)
	}
	return message('E', append(body, 0))
}

func message(kind byte, body []byte) []byte {
	msg := make([]byte, 5, 5+len(body))
	msg[0] = kind
	binary.BigEndian.PutUint32(msg[1:], uint32(4+len(body))) //nolint:gosec // G115: the messages are a few hundred bytes
	return append(msg, body...)
}

func write(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}
