// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ldap

import (
	"nyktus.org/nyktus/sensor/internal/report"
)

// maxFilterDepth is how deep filters may nest in each other. Real ones are two
// or three levels deep, and the filters of directory tools with a few conditions
// reach five.
const maxFilterDepth = 8

// Identifier octets of a filter (RFC 4511, section 4.5.1).
const (
	filterAnd       = 0xa0
	filterOr        = 0xa1
	filterNot       = 0xa2
	filterEquality  = 0xa3
	filterSubstring = 0xa4
	filterGreater   = 0xa5
	filterLess      = 0xa6
	filterPresent   = 0x87
	filterApprox    = 0xa8
	filterExtensive = 0xa9
	// Identifiers of the parts of a substring filter.
	subInitial = 0x80
	subAny     = 0x81
	subFinal   = 0x82
)

// unreadable stands for a filter with an extensible match. Reading one would
// take code for a rare form; the search is recorded all the same.
const unreadable = "(?)"

// filterText writes a search filter as text (RFC 4515), the form in which
// administrators know it. The text ends where the report ends: what lies beyond
// the limit is not read, so the work does not depend on the size of the filter.
// A filter that nests deeper than maxFilterDepth, or is not well formed, is an
// error.
func filterText(f element) (string, error) {
	t := &translator{}
	if err := t.filter(f, 0); err != nil {
		return "", err
	}
	return report.Clean(string(t.out), report.MaxFilter), nil
}

type translator struct {
	out []byte
}

func (t *translator) full() bool { return len(t.out) >= report.MaxFilter }

func (t *translator) filter(e element, depth int) error {
	if depth > maxFilterDepth {
		return errMalformed
	}
	switch e.tag {
	case filterAnd, filterOr:
		op := byte('&')
		if e.tag == filterOr {
			op = '|'
		}
		t.out = append(t.out, '(', op)
		for rest := e.content; len(rest) > 0 && !t.full(); {
			child, r, err := next(rest)
			if err != nil {
				return err
			}
			if err := t.filter(child, depth+1); err != nil {
				return err
			}
			rest = r
		}
		t.out = append(t.out, ')')
	case filterNot:
		child, rest, err := next(e.content)
		if err != nil || len(rest) != 0 {
			return errMalformed
		}
		t.out = append(t.out, '(', '!')
		if err := t.filter(child, depth+1); err != nil {
			return err
		}
		t.out = append(t.out, ')')
	case filterEquality:
		return t.comparison(e.content, "=")
	case filterGreater:
		return t.comparison(e.content, ">=")
	case filterLess:
		return t.comparison(e.content, "<=")
	case filterApprox:
		return t.comparison(e.content, "~=")
	case filterPresent:
		t.out = append(t.out, '(')
		t.escape(e.content)
		t.out = append(t.out, "=*)"...)
	case filterSubstring:
		return t.substring(e.content)
	case filterExtensive:
		t.out = append(t.out, unreadable...)
	default:
		return errMalformed
	}
	return nil
}

// comparison writes an attribute, an operator and a value.
func (t *translator) comparison(content []byte, op string) error {
	attr, rest, err := expect(content, tagOctetString)
	if err != nil {
		return err
	}
	value, _, err := expect(rest, tagOctetString)
	if err != nil {
		return err
	}
	t.out = append(t.out, '(')
	t.escape(attr)
	t.out = append(t.out, op...)
	t.escape(value)
	t.out = append(t.out, ')')
	return nil
}

// substring writes a filter such as (cn=a*b*c): the parts in their order, with a
// star in front of each one that is not the first and one at the end if the
// filter does not end with a part.
func (t *translator) substring(content []byte) error {
	attr, rest, err := expect(content, tagOctetString)
	if err != nil {
		return err
	}
	parts, _, err := expect(rest, tagSequence)
	if err != nil {
		return err
	}
	t.out = append(t.out, '(')
	t.escape(attr)
	t.out = append(t.out, '=')
	final := false
	for len(parts) > 0 && !t.full() {
		var part element
		if part, parts, err = next(parts); err != nil {
			return err
		}
		switch part.tag {
		case subInitial:
		case subAny:
			t.out = append(t.out, '*')
		case subFinal:
			t.out = append(t.out, '*')
			final = true
		default:
			return errMalformed
		}
		t.escape(part.content)
	}
	if !final {
		t.out = append(t.out, '*')
	}
	t.out = append(t.out, ')')
	return nil
}

// escape appends a value, with the characters that mean something in a filter,
// and those that do not show, as a backslash and two hexadecimal digits.
func (t *translator) escape(v []byte) {
	const hex = "0123456789abcdef"
	for _, c := range v {
		if c < 0x20 || c == 0x7f || c == '*' || c == '(' || c == ')' || c == '\\' {
			t.out = append(t.out, '\\', hex[c>>4], hex[c&0x0f])
		} else {
			t.out = append(t.out, c)
		}
	}
}
