// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package trigger

import (
	"encoding/base64"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const (
	// triggerValueLength is the length of a trigger value: 128 bits in lowercase
	// base32 without padding.
	triggerValueLength = 26
	// maxCandidates bounds how many different values one request can make the
	// trigger look up, so that a request that carries many strings of the form of
	// a value costs a few queries, not one per string. Strings of the form that
	// something else sent, such as identifiers, take a place as well, so the bound
	// leaves room for the value among them.
	maxCandidates = 8
	// maxBasicBytes bounds the credentials of an Authorization header of the
	// scheme Basic that are decoded.
	maxBasicBytes = 1024
)

// candidates returns the strings of a request that have the form of a trigger
// value, in a fixed order and without repeats: those of the path, then those of
// the query, then those of the headers by name. The value of a honeytoken may
// stand anywhere in a request, such as in a query parameter, an API key header,
// a cookie, the credentials of a URL or a segment of the path, so that what
// carries it looks like what it pretends to be, not like a honeytoken. The
// trigger does not know where a value stands and cannot ask the inventory, so it
// takes every string of the form, in whichever place; a value in a place that
// nothing configured is found as well as one in a place that something did.
//
// A string has the form of a value if it is a run of ASCII letters and digits,
// delimited by anything else, of the length of a value and in its alphabet,
// compared in lower case: the value is found after "Bearer ", "sk_" or "key=",
// but not inside a longer run. Of Basic credentials the decoded text counts too.
// The body of a request is not searched.
//
// At most maxCandidates strings are returned; a value beyond them is not found. The order decides which honeytoken
// a request with several values is recorded for, so it must not depend on the
// iteration order of a map.
func candidates(r *http.Request) []string {
	var c collector
	c.scan(r.URL.Path)
	// A parameter can be percent-encoded, which the separators do not hide. Each
	// one is decoded on its own, so that a malformed escape in one parameter does
	// not keep another from being decoded; one that cannot be decoded is searched
	// as it was sent.
	for part := range strings.FieldsFuncSeq(r.URL.RawQuery, func(r rune) bool { return r == '&' || r == ';' }) {
		if decoded, err := url.QueryUnescape(part); err == nil {
			part = decoded
		}
		c.scan(part)
	}
	for _, name := range slices.Sorted(maps.Keys(r.Header)) {
		for _, v := range r.Header[name] {
			c.scan(v)
			if name == "Authorization" {
				c.scan(basicCredentials(v))
			}
		}
	}
	return c.values
}

// basicCredentials returns the decoded credentials of an Authorization header
// of the scheme Basic, which carries them as base64 of "user:password" (the
// form in which a client sends a URL of the form https://user:password@host),
// or "" for any other header or credentials that are not base64 or too long.
func basicCredentials(header string) string {
	const scheme = "Basic "
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return ""
	}
	encoded := strings.TrimRight(strings.TrimSpace(header[len(scheme):]), "=")
	if base64.RawStdEncoding.DecodedLen(len(encoded)) > maxBasicBytes {
		return ""
	}
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	return string(decoded)
}

// collector gathers the candidates of a request.
type collector struct {
	values []string
}

func (c *collector) full() bool { return len(c.values) >= maxCandidates }

// scan adds every run of letters and digits in s that has the form of a value.
func (c *collector) scan(s string) {
	start := -1
	for i := 0; i <= len(s) && !c.full(); i++ {
		if i < len(s) && isAlphanumeric(s[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start == triggerValueLength {
			c.add(s[start:i])
		}
		start = -1
	}
}

// add keeps run, a string of the length of a value, in lower case, if it is one
// and not yet in the list.
func (c *collector) add(run string) {
	// Only ASCII letters are folded: strings.ToLower would also turn characters
	// of other scripts into letters of a value.
	folded := []byte(run)
	for i, b := range folded {
		if b >= 'A' && b <= 'Z' {
			folded[i] = b + ('a' - 'A')
		}
	}
	value := string(folded)
	if isTriggerValue(value) && !slices.Contains(c.values, value) {
		c.values = append(c.values, value)
	}
}

func isAlphanumeric(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func isTriggerValue(s string) bool {
	if len(s) != triggerValueLength {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}
