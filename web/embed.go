// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package web embeds the build of the web console into the server binary.
//
// The build output is not committed. dist holds a single placeholder, so that
// go build and go test work without Node.js; `make web-build` fills it, and the
// release build runs that first. A binary built without it serves no pages.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the files of the build, with index.html at its root.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		// The directory is part of the embed pattern, so this cannot happen.
		panic("web: " + err.Error())
	}
	return sub
}
