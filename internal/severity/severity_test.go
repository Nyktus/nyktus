// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package severity

import (
	"slices"
	"testing"
)

func TestHigher(t *testing.T) {
	t.Parallel()

	for i, a := range Levels {
		for j, b := range Levels {
			want := a
			if j > i {
				want = b
			}
			if got := Higher(a, b); got != want {
				t.Errorf("Higher(%s, %s) = %s, want %s", a, b, got, want)
			}
		}
	}
}

// A decoy suggests every level in the order of Levels, except Info, which
// only an analyst chooses.
func TestSuggested_IsEveryLevelButInfo(t *testing.T) {
	t.Parallel()

	if want := Levels[1:]; !slices.Equal(Suggested, want) {
		t.Errorf("Suggested = %v, want %v", Suggested, want)
	}
	for _, l := range Levels {
		if l.IsSuggested() == (l == Info) {
			t.Errorf("%s.IsSuggested() = %v", l, l.IsSuggested())
		}
		if !l.Valid() {
			t.Errorf("%s.Valid() = false", l)
		}
	}
	for _, l := range []Level{"", "INFO", "severe"} {
		if l.Valid() || l.IsSuggested() {
			t.Errorf("%q is accepted", l)
		}
	}
}
