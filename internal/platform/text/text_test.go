// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package text

import (
	"strings"
	"testing"
)

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
