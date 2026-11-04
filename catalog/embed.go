// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package catalog embeds the catalog: the deceptions under deceptions/, one
// directory each, so that the server never loads them at runtime. The package
// internal/catalog reads and validates them.
package catalog

import (
	"embed"
	"io/fs"
)

//go:embed deceptions
var files embed.FS

// FS returns the embedded catalog, with the directory deceptions at its root.
func FS() fs.FS {
	return files
}
