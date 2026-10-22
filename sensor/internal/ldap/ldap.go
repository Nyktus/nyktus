// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ldap emulates a directory server that refuses every login but one: it
// reads the binds and the first search of a client, as a scanner or a tool that
// maps a domain sends them, and answers every search with an empty result.
//
// It offers nothing behind the bind. No entry is ever returned and nothing is
// changed. What the client sent is read, counted and recorded in the session. A
// password is not kept: only its length.
package ldap

import (
	"bufio"
	"context"
	"errors"
	"net"

	"nyktus.org/nyktus/sensor/internal/clock"
	"nyktus.org/nyktus/sensor/internal/guard"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/session"
)

// Identifier octets of LDAP (RFC 4511) in BER: the class and form are part of
// them.
const (
	tagSequence      = 0x30
	tagInteger       = 0x02
	tagOctetString   = 0x04
	tagEnumerated    = 0x0a
	tagBoolean       = 0x01
	tagBindRequest   = 0x60 // [APPLICATION 0]
	tagBindResponse  = 0x61 // [APPLICATION 1]
	tagUnbindRequest = 0x42 // [APPLICATION 2]
	tagSearchRequest = 0x63 // [APPLICATION 3]
	tagSearchDone    = 0x65 // [APPLICATION 5]
	tagSimple        = 0x80 // [0] of the credentials of a bind
	tagSASL          = 0xa3 // [3] of the credentials of a bind
)

// Result codes (RFC 4511, section 4.1.9).
const (
	resultSuccess                = 0
	resultAuthMethodNotSupported = 7
	resultInvalidCredentials     = 49
)

// Service is the LDAP honeypot.
type Service struct {
	clock clock.Clock
}

// New returns an LDAP honeypot. It panics if clk is nil.
func New(clk clock.Clock) *Service {
	if clk == nil {
		panic("ldap: missing clock")
	}
	return &Service{clock: clk}
}

// Serve answers the messages of the client and records them in sess. It returns
// when the client unbinds, sends anything but a bind or a search, sends a message
// that it cannot read, has gone, was silent for too long or sent too much, and
// leaves closing the connection to its caller.
func (s *Service) Serve(ctx context.Context, conn net.Conn, sess *session.Session) {
	g := guard.New(conn, s.clock)
	r := bufio.NewReader(g)
	for ctx.Err() == nil {
		msg, err := readMessage(r)
		if err != nil {
			return
		}
		id, op, err := envelope(msg)
		if err != nil {
			return
		}
		var reply []byte
		switch op.tag {
		case tagBindRequest:
			code, err := bind(op.content, sess)
			if err != nil {
				return
			}
			reply = response(id, tagBindResponse, code)
		case tagSearchRequest:
			if err := search(op.content, sess); err != nil {
				return
			}
			reply = response(id, tagSearchDone, resultSuccess)
		default:
			// An unbind ends the session; any other operation is not offered.
			return
		}
		if _, err := g.Write(reply); err != nil {
			return
		}
	}
}

// envelope splits an LDAPMessage into its identifier, which is sent back as it
// came, and its operation. Controls after the operation are ignored.
func envelope(msg []byte) (id []byte, op element, err error) {
	id, rest, err := expect(msg, tagInteger)
	if err != nil || len(id) == 0 || len(id) > 4 {
		return nil, element{}, errMalformed
	}
	op, _, err = next(rest)
	if err != nil {
		return nil, element{}, err
	}
	return id, op, nil
}

// bind records a bind request and returns the code of the answer. An anonymous
// bind, with neither a name nor a password, succeeds, so that a client that
// begins with one goes on to its search; it carries no credentials and is no
// login. Every other simple bind is a login and fails.
func bind(op []byte, sess *session.Session) (code byte, err error) {
	_, rest, err := expect(op, tagInteger) // the version
	if err != nil {
		return 0, err
	}
	name, rest, err := expect(rest, tagOctetString)
	if err != nil {
		return 0, err
	}
	auth, _, err := next(rest)
	if err != nil {
		return 0, err
	}
	switch auth.tag {
	case tagSimple:
		if len(name) == 0 && len(auth.content) == 0 {
			return resultSuccess, nil
		}
		n := len(auth.content)
		sess.AddAttempt(report.Attempt{Username: report.Clean(string(name), report.MaxUsername), PasswordLength: &n})
		return resultInvalidCredentials, nil
	case tagSASL:
		return resultAuthMethodNotSupported, nil
	default:
		return 0, errMalformed
	}
}

// search records the first search of the session. Its answer is always empty.
func search(op []byte, sess *session.Session) error {
	base, rest, err := expect(op, tagOctetString)
	if err != nil {
		return err
	}
	// scope, derefAliases, sizeLimit, timeLimit and typesOnly are read past.
	for _, tag := range []byte{tagEnumerated, tagEnumerated, tagInteger, tagInteger, tagBoolean} {
		if _, rest, err = expect(rest, tag); err != nil {
			return err
		}
	}
	f, _, err := next(rest)
	if err != nil {
		return err
	}
	filter, err := filterText(f)
	switch {
	case errors.Is(err, errTooDeep):
		// A filter that only nests too deep is no reason to lose the search: its
		// base is recorded, and the session ends as for a message that cannot be
		// read.
		sess.SetQuery(report.Query{BaseDN: report.Clean(string(base), report.MaxBaseDN), Filter: unreadable})
		return err
	case err != nil:
		return err
	}
	sess.SetQuery(report.Query{BaseDN: report.Clean(string(base), report.MaxBaseDN), Filter: filter})
	return nil
}

// response encodes an LDAPMessage that answers the message with the given
// identifier by an LDAPResult: the code, and an empty matched name and
// diagnostic message. Everything in it is shorter than 128 octets, so every
// length is one octet.
func response(id []byte, op byte, code byte) []byte {
	result := []byte{tagEnumerated, 1, code, tagOctetString, 0, tagOctetString, 0}
	body := append([]byte{tagInteger, short(len(id))}, id...)
	body = append(body, op, short(len(result)))
	body = append(body, result...)
	return append([]byte{tagSequence, short(len(body))}, body...)
}

// short returns a length of one octet.
func short(n int) byte {
	if n < 0 || n > 0x7f {
		panic("ldap: length of a reply out of range")
	}
	return byte(n)
}
