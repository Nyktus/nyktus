// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package version names the version of the running sensor.
package version

import (
	"regexp"
	"runtime/debug"
	"strings"
)

// Development is what a build without a release version reports.
const Development = "devel"

// reportable is the form that the server accepts as the version of a
// sensor.
var reportable = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$`)

// Current returns the version of the running binary.
func Current() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Development
	}
	return Of(info.Main.Version)
}

// Of returns the version to report for the version that the toolchain stamped
// into a binary: the release without its leading "v", and "devel" for a build
// from an untagged commit, from a modified tree or without version control
// information, and for a version that the server would not accept. The version
// of an untagged commit is a pseudo-version of at least 33 characters, and
// "(devel)" holds characters that a version may not, so both fall under the
// last rule.
func Of(stamped string) string {
	v := strings.TrimPrefix(stamped, "v")
	switch {
	case strings.Contains(v, "+dirty"), !reportable.MatchString(v):
		return Development
	default:
		return v
	}
}
