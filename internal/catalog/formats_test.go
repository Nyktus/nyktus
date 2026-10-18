// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"testing"

	embedded "nyktus.org/nyktus/catalog"
)

// Files that a tool interprets receive only values that the server generates,
// such as URLs, host names of honeytokens and secrets, or values of the
// persona that match the pattern of their kind; free text appears only in
// files that a person reads.
func TestEmbeddedCatalog_ExecutableFormatsTakeOnlyAllowedValues(t *testing.T) {
	t.Parallel()

	c, err := Load(embedded.Deceptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range c.Deceptions() {
		for _, a := range d.Artifacts {
			if a.Format.inert() {
				continue
			}
			for path, kind := range a.Template.fields {
				if kind != KindHost && kind != KindURL && kind != KindName && kind != KindSecret {
					t.Errorf("%s/%s: .%s of kind %s in a file that a tool interprets", d.ID, a.Key, path, kind)
				}
			}
		}
	}
}
