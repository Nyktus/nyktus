// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package text checks free text that users enter, such as names and notes.
package text

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// ValidName reports whether s is a name of 1 to maxRunes printable
// characters on one line without surrounding whitespace, valid UTF-8.
// unicode.IsPrint rejects control and format characters and every space
// except U+0020, because bidirectional overrides and invisible characters can
// make a name appear as a different one.
func ValidName(s string, maxRunes int) bool {
	n := utf8.RuneCountInString(s)
	if n < 1 || n > maxRunes || strings.TrimSpace(s) != s || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// ValidNotes reports whether s is valid UTF-8 of at most maxRunes characters
// that may span several lines. It may contain tabs and every kind of space,
// such as the non-breaking spaces of text copied from a document; other
// control characters and format characters are rejected, because
// bidirectional overrides and invisible characters can make text read
// differently from what it holds.
func ValidNotes(s string, maxRunes int) bool {
	if utf8.RuneCountInString(s) > maxRunes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsGraphic(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}
