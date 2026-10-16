// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
)

// Catalog is a validated set of deceptions.
type Catalog struct {
	deceptions []Deception
}

// Load reads every deception of fsys, one directory each, and validates and
// compiles them. It fails if any deception is invalid, so that a server never
// starts with a catalog that it cannot apply in full.
func Load(fsys fs.FS) (*Catalog, error) {
	// fs.ReadDir orders the entries by name, so the deceptions are ordered by
	// identifier, which Lookup relies on.
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	c := &Catalog{}
	for _, e := range entries {
		if !e.IsDir() {
			return nil, fmt.Errorf("%w: %s is not the directory of a deception", ErrInvalidDeception, e.Name())
		}
		d, err := loadDeception(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		c.deceptions = append(c.deceptions, d)
	}
	if len(c.deceptions) == 0 {
		return nil, errors.New("load catalog: no deceptions")
	}
	return c, nil
}

// Deceptions returns every deception, ordered by identifier. The deceptions
// share their texts, lists and templates with the catalog, which callers do
// not change.
func (c *Catalog) Deceptions() []Deception {
	return slices.Clone(c.deceptions)
}

// Lookup returns the deception id, which shares its data with the catalog as
// Deceptions describes.
func (c *Catalog) Lookup(id string) (Deception, bool) {
	i, ok := slices.BinarySearchFunc(c.deceptions, id, func(d Deception, id string) int { return strings.Compare(d.ID, id) })
	if !ok {
		return Deception{}, false
	}
	return c.deceptions[i], true
}
