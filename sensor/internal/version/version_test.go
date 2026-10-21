// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package version_test

import (
	"regexp"
	"strings"
	"testing"

	"nyktus.org/nyktus/sensor/internal/version"
)

func TestOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		stamped string
		want    string
	}{
		{name: "a release", stamped: "v0.1.0", want: "0.1.0"},
		{name: "a release candidate", stamped: "v0.1.0-rc.1", want: "0.1.0-rc.1"},
		{name: "a release with build metadata", stamped: "v0.1.0-rc.1+build5", want: "0.1.0-rc.1+build5"},
		{name: "a version of exactly 32 characters", stamped: "v" + strings.Repeat("1", 32), want: strings.Repeat("1", 32)},
		{name: "a version of 33 characters", stamped: "v" + strings.Repeat("1", 33), want: "devel"},
		{name: "an untagged commit", stamped: "v0.0.0-20261009224706-f7ad5ccac2ac", want: "devel"},
		{name: "an untagged commit after a tag", stamped: "v0.1.1-0.20261009224706-f7ad5ccac2ac", want: "devel"},
		{name: "a modified tree", stamped: "v0.1.0+dirty", want: "devel"},
		{name: "a build without version control", stamped: "(devel)", want: "devel"},
		{name: "no version", stamped: "", want: "devel"},
		{name: "characters that the server refuses", stamped: "v0.1.0 beta", want: "devel"},
		{name: "a line break", stamped: "v0.1.0\n", want: "devel"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := version.Of(tt.stamped); got != tt.want {
				t.Errorf("Of(%q) = %q, want %q", tt.stamped, got, tt.want)
			}
		})
	}
}

// Whatever the toolchain stamps, the server accepts the version: its pattern
// is the one of the column.
func TestCurrent_IsAVersionTheServerAccepts(t *testing.T) {
	t.Parallel()

	if got := version.Current(); !regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$`).MatchString(got) {
		t.Errorf("Current() = %q, want a version of the form the server accepts", got)
	}
}
