// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package postgres emulates the login of a PostgreSQL server: it reads the
// startup message of a client, asks for a password in clear text and refuses
// it, as a server does that has no such user.
//
// It offers nothing behind the login. There is no session, no query and no SQL:
// the connection ends with the refusal. What the client sent is read, counted
// and recorded in the session. A password is not kept: only its length.
package postgres

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
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
)

// Codes of the first packet of a client. A code below 0x10000 does not exist;
// the high half of the others is the major version of the protocol.
const (
	sslRequest   = 80877103
	gssRequest   = 80877104
	majorVersion = 3
)

var errMalformed = errors.New("postgres: malformed message")

// Service is the PostgreSQL honeypot.
type Service struct {
	clock clock.Clock
}

// New returns a PostgreSQL honeypot. It panics if clk is nil.
func New(clk clock.Clock) *Service {
	if clk == nil {
		panic("postgres: missing clock")
	}
	return &Service{clock: clk}
}

// Serve plays the login on conn and records it in sess. It returns when the
// refusal is sent, when the client has gone, was silent for too long or sent
// too much, and leaves closing the connection to its caller.
func (s *Service) Serve(ctx context.Context, conn net.Conn, sess *session.Session) {
	if ctx.Err() != nil {
		return
	}
	g := guard.New(conn, s.clock)
	r := bufio.NewReader(g)

	st, ok := s.negotiate(g, r)
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

	if write(g, authenticationCleartextPassword) != nil {
		return
	}
	n, ok := readPassword(r)
	if !ok {
		return
	}
	attempt.PasswordLength = &n
	_ = write(g, errorResponse(attempt.Username))
}

// negotiate answers the requests for encryption and reads the startup message. It
// reports false if the client did not send one that this server speaks.
func (s *Service) negotiate(w io.Writer, r *bufio.Reader) (startup, bool) {
	for range maxPackets {
		code, body, err := readPacket(r)
		if err != nil {
			return startup{}, false
		}
		switch {
		case code == sslRequest || code == gssRequest:
			// No encryption is offered, and the client goes on in clear text.
			if write(w, []byte{'N'}) != nil {
				return startup{}, false
			}
		case code>>16 == majorVersion:
			st, err := parseStartup(body)
			return st, err == nil
		default:
			// A cancel request, or a protocol that does not exist.
			return startup{}, false
		}
	}
	return startup{}, false
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

// readPassword reads the message with the password and returns its length, not
// the password. It reports false if the next message is anything else, or if
// the client does not finish it within what the connection allows: the length in
// its header is not believed. The password is counted as it is read and dropped.
func readPassword(r *bufio.Reader) (int, bool) {
	typ, err := r.ReadByte()
	if err != nil || typ != 'p' {
		return 0, false
	}
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, false
	}
	// The length counts itself, the password and its zero byte.
	n := binary.BigEndian.Uint32(head[:])
	if n < 5 {
		return 0, false
	}
	if _, err := io.CopyN(io.Discard, r, int64(n)-4); err != nil {
		return 0, false
	}
	return int(n) - 5, true
}

// authenticationCleartextPassword asks the client for its password in clear
// text, the one request that tells the length of the password.
var authenticationCleartextPassword = []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}

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
	} {
		body = append(body, f.code...)
		body = append(body, f.text...)
		body = append(body, 0)
	}
	body = append(body, 0)
	msg := make([]byte, 5, 5+len(body))
	msg[0] = 'E'
	binary.BigEndian.PutUint32(msg[1:], uint32(4+len(body))) //nolint:gosec // G115: the message is a few hundred bytes
	return append(msg, body...)
}

func write(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}
