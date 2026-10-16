// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package smtp

import (
	"errors"
	"strings"
	"time"
)

// Limits of a message.
const (
	// MaxAddressLength is the longest address that SMTP transports (RFC 5321).
	MaxAddressLength = 254
	maxLocalPart     = 64
	// MaxRecipients bounds the recipients of a message.
	MaxRecipients = 10
	// maxSubjectLength keeps the subject on one line of a header.
	maxSubjectLength = 200
	maxIDLength      = 64
	// maxLineLength is the longest line that SMTP transports, without its
	// line break (RFC 5322).
	maxLineLength = 998
	maxBodyLength = 64 << 10
)

// Errors of a message.
var (
	ErrInvalidAddress = errors.New("smtp: invalid address")
	ErrInvalidMessage = errors.New("smtp: invalid message")
)

// Message is a message in plain text. Every field is checked before the
// message is sent: headers and body consist of printable ASCII, so that no
// value can end a header and start another one, and no encoding is needed.
type Message struct {
	// To are the recipients, each an address as ValidateAddress accepts it.
	To []string
	// Subject is a single line of printable ASCII.
	Subject string
	// ID identifies the message to its recipients, who can recognize a
	// message that reaches them twice by it. It consists of letters, digits
	// and hyphens, such as a UUID; the domain of the sender completes it.
	ID string
	// Body is printable ASCII in lines separated by "\n".
	Body string
}

// build returns m with its headers, ready for the DATA command, sent from the
// address from at date. Lines end in CRLF; net/smtp escapes leading dots.
func (m Message) build(from string, date time.Time) ([]byte, error) {
	if len(m.To) == 0 || len(m.To) > MaxRecipients {
		return nil, ErrInvalidMessage
	}
	for _, rcpt := range m.To {
		if ValidateAddress(rcpt) != nil {
			return nil, ErrInvalidAddress
		}
	}
	if m.Subject == "" || len(m.Subject) > maxSubjectLength || !printable(m.Subject) || !validID(m.ID) ||
		len(m.Body) > maxBodyLength {
		return nil, ErrInvalidMessage
	}
	// A final line break ends the last line instead of starting another.
	lines := strings.Split(strings.TrimSuffix(m.Body, "\n"), "\n")
	for _, line := range lines {
		if len(line) > maxLineLength || !printable(line) {
			return nil, ErrInvalidMessage
		}
	}
	domain := from[strings.LastIndexByte(from, '@')+1:]

	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	// One recipient per line, so that ten long addresses never exceed the
	// length of a line.
	b.WriteString("To: " + strings.Join(m.To, ",\r\n ") + "\r\n")
	b.WriteString("Subject: " + m.Subject + "\r\n")
	b.WriteString("Date: " + date.Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: <" + m.ID + "@" + domain + ">\r\n")
	// Mail of Nyktus is sent by a machine, so that out-of-office replies do
	// not answer it (RFC 3834).
	b.WriteString("Auto-Submitted: auto-generated\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=us-ascii\r\n")
	b.WriteString("Content-Transfer-Encoding: 7bit\r\n")
	b.WriteString("\r\n")
	for _, line := range lines {
		b.WriteString(line + "\r\n")
	}
	return []byte(b.String()), nil
}

// printable reports whether s consists of printable ASCII and spaces only.
func printable(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func validID(s string) bool {
	if s == "" || len(s) > maxIDLength {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !alphanumeric(c) && c != '-' {
			return false
		}
	}
	return true
}

func alphanumeric(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// ValidateAddress accepts an address of the form local@domain in ASCII, as SMTP
// transports it without extensions: the local part a dot-atom of RFC 5322, the
// domain a name of at least two labels, an internationalized one in its
// ASCII form. Display names, comments, quoted local parts and address literals
// are rejected, so that an address is never more than an address.
func ValidateAddress(s string) error {
	at := strings.IndexByte(s, '@')
	if len(s) > MaxAddressLength || at < 1 || at != strings.LastIndexByte(s, '@') {
		return ErrInvalidAddress
	}
	local, domain := s[:at], s[at+1:]
	if len(local) > maxLocalPart || !dotAtom(local) || !domainName(domain) {
		return ErrInvalidAddress
	}
	return nil
}

func dotAtom(s string) bool {
	for atom := range strings.SplitSeq(s, ".") {
		if atom == "" {
			return false
		}
		for i := range len(atom) {
			if c := atom[i]; !alphanumeric(c) && strings.IndexByte("!#$%&'*+-/=?^_`{|}~", c) < 0 {
				return false
			}
		}
	}
	return true
}

func domainName(s string) bool {
	labels := strings.Split(s, ".")
	if len(labels) < 2 || len(s) > 253 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			if c := label[i]; !alphanumeric(c) && c != '-' {
				return false
			}
		}
	}
	// A last label of digits would make an address out of the name.
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}
