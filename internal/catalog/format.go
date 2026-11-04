// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package catalog holds the deception catalog: stories that tell an
// administrator what to place where, with the honeytokens and honeypots they
// need and example files.
//
// The catalog is data, never code. A deception holds its guide and its files
// as static text: the server inserts nothing into them and creates no files.
package catalog

import "slices"

// Format is the kind of an example file. It decides the media type of the
// download and which characters the file may hold.
type Format string

// Formats of files.
const (
	// FormatText is plain text that a person reads, such as a note.
	FormatText Format = "text"
	// FormatMarkdown is Markdown that a person reads.
	FormatMarkdown Format = "markdown"
	// FormatHTML is an HTML page or a file of bookmarks, opened in a browser.
	FormatHTML Format = "html"
	// FormatConfig is a file that a tool reads and acts on, such as an SSH
	// configuration, an INI file, a .netrc, an RDP connection or a Windows
	// shortcut.
	FormatConfig Format = "config"
)

// Formats lists every format.
var Formats = []Format{FormatText, FormatMarkdown, FormatHTML, FormatConfig}

// Valid reports whether f is a known format.
func (f Format) Valid() bool {
	return slices.Contains(Formats, f)
}

// mediaTypes are the media types of the downloads. A file that a tool
// interprets is an opaque download: a browser saves it and never renders it.
var mediaTypes = map[Format]string{
	FormatText:     "text/plain; charset=utf-8",
	FormatMarkdown: "text/markdown; charset=utf-8",
	FormatHTML:     "text/html; charset=utf-8",
	FormatConfig:   "application/octet-stream",
}

// MediaType returns the media type with which a file of format f is served.
func MediaType(f Format) string {
	if t, ok := mediaTypes[f]; ok {
		return t
	}
	return "application/octet-stream"
}
