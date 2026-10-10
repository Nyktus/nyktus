// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package buildinfo reports the version of the running binary.
package buildinfo

import "runtime/debug"

// Version returns the module version that the Go toolchain stamps into the binary:
// the tag for a build from a tagged commit, a pseudo-version with the commit and a
// "+dirty" suffix for uncommitted changes otherwise. Builds without version control
// information, such as "go run" and "go test", report "devel".
func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "devel"
	}
	return version(info)
}

func version(info *debug.BuildInfo) string {
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	return "devel"
}
