// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ldap

import (
	"bufio"
	"errors"
	"io"
)

// maxMessage is the longest LDAP message that is read. A real bind or search is
// a few hundred bytes. The limit is checked against the length in the header
// before anything is allocated.
const maxMessage = 8 << 10

var errMalformed = errors.New("ldap: malformed message")

// element is one element of BER (ITU-T X.690): its identifier octet and its
// content.
//
// Only what LDAP uses is read: identifiers of one octet and definite lengths,
// in the short form or in the long form with up to four octets, as encoders that
// pad every length write them. An indefinite length, a longer form and a length
// beyond maxMessage are refused, and the message ends the session, never guessed
// at. The caller compares the identifier with the ones it expects, and none of
// them has a tag number of 31 or more, which is how an identifier of several
// octets would begin, so such an element is never taken for another.
//
// The reader is a cursor over a message that is already in memory and bounded:
// it holds no state, does not recurse and copies nothing, so how deep a message
// nests is decided by the code that walks it.
type element struct {
	tag     byte
	content []byte
}

// next returns the element at the start of b and what follows it.
func next(b []byte) (e element, rest []byte, err error) {
	if len(b) < 2 {
		return element{}, nil, errMalformed
	}
	tag, b := b[0], b[1:]
	n, b, err := length(b)
	if err != nil || n > len(b) {
		return element{}, nil, errMalformed
	}
	return element{tag: tag, content: b[:n]}, b[n:], nil
}

// lengthOctets returns how many octets follow the first octet of a definite
// length. It reports false for an indefinite length and for a form that is
// longer than the reader takes.
func lengthOctets(first byte) (int, bool) {
	switch {
	case first < 0x80:
		return 0, true
	case first > 0x80 && first <= 0x84:
		return int(first & 0x7f), true
	default:
		return 0, false
	}
}

// length reads a definite length and returns it with what follows. It is the one
// place that knows the forms, and it refuses a length beyond maxMessage, which
// no element of a message can have. b is not empty.
func length(b []byte) (n int, rest []byte, err error) {
	extra, ok := lengthOctets(b[0])
	if !ok || len(b) < 1+extra {
		return 0, nil, errMalformed
	}
	if extra == 0 {
		return int(b[0]), b[1:], nil
	}
	var v uint32
	for _, o := range b[1 : 1+extra] {
		v = v<<8 | uint32(o)
	}
	if v > maxMessage {
		return 0, nil, errMalformed
	}
	return int(v), b[1+extra:], nil
}

// expect returns the element at the start of b if it has the given identifier.
func expect(b []byte, tag byte) (content, rest []byte, err error) {
	e, rest, err := next(b)
	if err != nil || e.tag != tag {
		return nil, nil, errMalformed
	}
	return e.content, rest, nil
}

// readMessage reads one LDAPMessage from the client and returns what is inside
// its outer SEQUENCE.
func readMessage(r *bufio.Reader) ([]byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	first, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if tag != tagSequence {
		return nil, errMalformed
	}
	extra, ok := lengthOctets(first)
	if !ok {
		return nil, errMalformed
	}
	// The octets of the length are read, and length() decides what they mean.
	header := [5]byte{first}
	if _, err := io.ReadFull(r, header[1:1+extra]); err != nil {
		return nil, err
	}
	n, _, err := length(header[:1+extra])
	if err != nil {
		return nil, errMalformed
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
