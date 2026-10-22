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
// Only what LDAP uses is read: identifiers of one octet and definite lengths of
// at most two octets, which is more than maxMessage needs. An indefinite length
// or a longer one is refused and the message ends the session, never guessed
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

// length reads a definite length and returns it with what follows.
func length(b []byte) (n int, rest []byte, err error) {
	switch first := b[0]; {
	case first < 0x80:
		return int(first), b[1:], nil
	case first == 0x81 && len(b) >= 2:
		return int(b[1]), b[2:], nil
	case first == 0x82 && len(b) >= 3:
		return int(b[1])<<8 | int(b[2]), b[3:], nil
	default:
		// Indefinite (0x80), longer than two octets, or cut short.
		return 0, nil, errMalformed
	}
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
	var n int
	switch {
	case first < 0x80:
		n = int(first)
	case first == 0x81 || first == 0x82:
		var octets [2]byte
		if _, err := io.ReadFull(r, octets[:first&0x0f]); err != nil {
			return nil, err
		}
		for _, o := range octets[:first&0x0f] {
			n = n<<8 | int(o)
		}
	default:
		return nil, errMalformed
	}
	if n > maxMessage {
		return nil, errMalformed
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
