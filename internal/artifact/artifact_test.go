// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package artifact

import (
	"errors"
	"strings"
	"testing"
)

// The limits of the notes hold without a database, which maps its check to
// the same error.
func TestValidatePlacementNotes(t *testing.T) {
	t.Parallel()

	for _, s := range []string{"", "share \\\\fs01\\it\nowner: IT\tdesk 4", strings.Repeat("\u00e4", MaxPlacementNotesLength)} {
		if err := ValidatePlacementNotes(s); err != nil {
			t.Errorf("ValidatePlacementNotes(%q) = %v", s, err)
		}
	}
	for _, s := range []string{strings.Repeat("a", MaxPlacementNotesLength+1), "a\x00", "a\x1bb", "a\u202eb", "a\xff"} {
		if err := ValidatePlacementNotes(s); !errors.Is(err, ErrInvalidPlacementNotes) {
			t.Errorf("ValidatePlacementNotes(%q) = %v, want ErrInvalidPlacementNotes", s, err)
		}
	}
}
