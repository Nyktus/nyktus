// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package catalog embeds the catalog: the deceptions under deceptions/ and the
// artifacts under artifacts/, one directory each, so that the server never
// loads them at runtime. The package internal/catalog reads and validates
// them.
package catalog

import (
	"embed"
	"io/fs"
)

//go:embed deceptions artifacts
var files embed.FS

// FS returns the embedded catalog, with the directories deceptions and
// artifacts at its root.
func FS() fs.FS {
	return files
}
