// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package telnet

import (
	"bufio"
	"errors"
)

// Commands of the Telnet protocol (RFC 854, RFC 855). A command is IAC, a
// command byte and, for the four negotiations, an option byte.
const (
	iac  = 255
	dont = 254
	do   = 253
	wont = 252
	will = 251
	sb   = 250
	se   = 240
)

// Options that the server offers (RFC 857, RFC 858).
const (
	optEcho = 1
	optSGA  = 3
)

// maxSubnegotiation is the longest subnegotiation that the parser skips. The
// real ones, such as the terminal type and the window size, are a few bytes.
const maxSubnegotiation = 128

var errSubnegotiationTooLong = errors.New("subnegotiation too long")

type parserState int

const (
	stateData parserState = iota
	stateIAC
	stateOption
	stateSubnegotiation
	stateSubnegotiationIAC
)

// parser separates the data of a client from its commands. The sensor reads
// the commands without acting on them: it answers none, so that a client
// cannot make it write more than it reads, and it never passes them on.
type parser struct {
	state parserState
	// subLen counts the bytes of the current subnegotiation.
	subLen int
}

// feed processes one byte of the stream. It returns the byte and true if it is
// data, and an error if the client sends a subnegotiation that is longer than
// any real one.
func (p *parser) feed(b byte) (byte, bool, error) {
	switch p.state {
	case stateData:
		if b == iac {
			p.state = stateIAC
			return 0, false, nil
		}
		return b, true, nil
	case stateIAC:
		switch b {
		case iac:
			// An escaped 0xFF is a data byte.
			p.state = stateData
			return iac, true, nil
		case will, wont, do, dont:
			p.state = stateOption
		case sb:
			p.state = stateSubnegotiation
			p.subLen = 0
		default:
			p.state = stateData
		}
		return 0, false, nil
	case stateOption:
		p.state = stateData
		return 0, false, nil
	case stateSubnegotiation:
		if b == iac {
			p.state = stateSubnegotiationIAC
			return 0, false, nil
		}
		return 0, false, p.subnegotiationByte()
	case stateSubnegotiationIAC:
		if b == se {
			p.state = stateData
			return 0, false, nil
		}
		// An escaped IAC, or a command that does not belong here: both are
		// bytes of the subnegotiation, and both count.
		p.state = stateSubnegotiation
		return 0, false, p.subnegotiationByte()
	default:
		panic("telnet: unknown parser state")
	}
}

func (p *parser) subnegotiationByte() error {
	p.subLen++
	if p.subLen > maxSubnegotiation {
		return errSubnegotiationTooLong
	}
	return nil
}

// line is what a client typed up to the end of a line.
type line struct {
	// text holds the first bytes of the line, at most the limit of the read.
	text []byte
	// n is the number of data bytes of the line, however many of them text
	// keeps.
	n int
	// complete is false if the stream ended before the line did.
	complete bool
}

// lineReader reads lines of data from a stream that carries commands.
type lineReader struct {
	r      *bufio.Reader
	parser parser
	// skip is set after a carriage return, which ends a line together with the
	// line feed or NUL that follows it, so that the second byte is not part of
	// the next line.
	skip bool
}

// read reads one line. A line ends with CR LF, CR NUL or a lone LF or CR; a
// NUL anywhere else is dropped. It keeps at most keep bytes of the text but
// counts all of them. echo, if set, receives every printable byte that is kept,
// in order to show it to the client. On an error the line holds what was read
// until then.
func (l *lineReader) read(keep int, echo func(byte) error) (line, error) {
	var ln line
	for {
		b, err := l.r.ReadByte()
		if err != nil {
			return ln, err
		}
		data, isData, err := l.parser.feed(b)
		if err != nil {
			return ln, err
		}
		if !isData {
			continue
		}
		skip := l.skip
		l.skip = false
		switch data {
		case '\r':
			l.skip = true
			ln.complete = true
			return ln, nil
		case '\n':
			if skip {
				continue
			}
			ln.complete = true
			return ln, nil
		case 0:
			continue
		}
		ln.n++
		if len(ln.text) >= keep {
			continue
		}
		ln.text = append(ln.text, data)
		// What is kept is shown back, and nothing more: a client that sends
		// a long line does not make the sensor write a long answer.
		if echo != nil && data >= 0x20 && data <= 0x7e {
			if err := echo(data); err != nil {
				return ln, err
			}
		}
	}
}
