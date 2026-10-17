// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package text

import (
	"strings"
	"testing"
)

func TestValidName(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		s    string
		want bool
	}{
		{"inner space", "a b", true},
		{"longest", strings.Repeat("\u00e4", 10), true},
		{"empty", "", false},
		{"too long", strings.Repeat("a", 11), false},
		{"leading space", " a", false},
		{"trailing space", "a ", false},
		{"line break", "a\nb", false},
		{"tab", "a\tb", false},
		{"non-breaking space", "a\u00a0b", false},
		{"bidirectional override", "a\u202eb", false},
		{"zero width joiner", "a\u200db", false},
		{"invalid UTF-8", "a\xff", false},
	} {
		if got := ValidName(tt.s, 10); got != tt.want {
			t.Errorf("%s: ValidName(%q) = %v, want %v", tt.name, tt.s, got, tt.want)
		}
	}
}

func TestValidNotes(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		notes string
		want  bool
	}{
		{"empty", "", true},
		{"lines, tabs and spaces", "a\r\n\tb\u00a0c\u3000d", true},
		{"longest", strings.Repeat("\u00e4", 10), true},
		{"too long", strings.Repeat("a", 11), false},
		{"control character", "a\x07", false},
		{"bidirectional override", "a\u202eb", false},
		{"zero width joiner", "a\u200db", false},
		{"invalid UTF-8", "a\xff", false},
	} {
		if got := ValidNotes(tt.notes, 10); got != tt.want {
			t.Errorf("%s: ValidNotes(%q) = %v, want %v", tt.name, tt.notes, got, tt.want)
		}
	}
}
