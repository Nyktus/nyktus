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

// deceptionsDir is the directory of the deceptions in the catalog.
const deceptionsDir = "deceptions"

// Catalog is a validated set of deceptions.
type Catalog struct {
	deceptions []Deception
}

// Load reads every deception of the directory deceptions of fsys, one
// directory each, and validates it. It fails if any entry is invalid, so that
// a server never starts with a catalog that it cannot serve in full.
func Load(fsys fs.FS) (*Catalog, error) {
	// fs.ReadDir orders the entries by name, so the deceptions are ordered by
	// identifier, which the lookup relies on.
	entries, err := fs.ReadDir(fsys, deceptionsDir)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	c := &Catalog{}
	sub := mustSub(fsys, deceptionsDir)
	for _, e := range entries {
		if !e.IsDir() {
			return nil, fmt.Errorf("%w: %s/%s is not a directory", ErrInvalidDeception, deceptionsDir, e.Name())
		}
		d, err := loadDeception(sub, e.Name())
		if err != nil {
			return nil, err
		}
		c.deceptions = append(c.deceptions, d)
	}
	if len(c.deceptions) == 0 {
		return nil, errors.New("load catalog: no deceptions in " + deceptionsDir)
	}
	return c, nil
}

// mustSub returns the directory dir of fsys. dir is a name that fs.Sub
// accepts: a constant of this package or an identifier that was validated.
func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

// Deceptions returns every deception, ordered by identifier. The deceptions
// share their texts and lists with the catalog, which callers do not change.
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
