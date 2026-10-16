// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package catalog embeds the deceptions of the catalog, one directory each
// under deceptions/, so that the server never loads them at runtime. The
// package internal/catalog reads and validates them.
package catalog

import (
	"embed"
	"io/fs"
)

//go:embed deceptions
var files embed.FS

// Deceptions returns the directories of the deceptions.
func Deceptions() fs.FS {
	sub, err := fs.Sub(files, "deceptions")
	if err != nil {
		// fs.Sub fails only for an invalid path, which this is not.
		panic(err)
	}
	return sub
}
