// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package text checks free text that users enter, such as notes.
package text

import (
	"unicode"
	"unicode/utf8"
)

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
