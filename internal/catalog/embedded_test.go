// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog_test

import (
	"testing"

	embedded "nyktus.org/nyktus/catalog"
	"nyktus.org/nyktus/internal/catalog"
)

// The server refuses to start with an invalid catalog, so every deception
// that ships must load.
func TestEmbeddedCatalog_IsValid(t *testing.T) {
	t.Parallel()

	c, err := catalog.Load(embedded.Deceptions())
	if err != nil {
		t.Fatalf("Load(embedded catalog) error = %v", err)
	}
	if len(c.Deceptions()) == 0 {
		t.Fatal("the embedded catalog has no deceptions")
	}
}
