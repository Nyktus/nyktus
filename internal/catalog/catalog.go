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

// Directories of the catalog.
const (
	deceptionsDir = "deceptions"
	artifactsDir  = "artifacts"
)

// Catalog is a validated set of deceptions and artifacts. A deception
// recommends artifacts of the set; an artifact may be recommended by none.
type Catalog struct {
	deceptions []Deception
	artifacts  []Artifact
}

// Load reads every artifact of the directory artifacts and every deception of
// the directory deceptions of fsys, one directory each, and validates and
// compiles them. It fails if any entry is invalid, so that a server never
// starts with a catalog that it cannot apply in full.
func Load(fsys fs.FS) (*Catalog, error) {
	c := &Catalog{}
	var err error
	if c.artifacts, err = loadAll(fsys, artifactsDir, ErrInvalidArtifact, loadArtifact); err != nil {
		return nil, err
	}
	byID := make(map[string]Artifact, len(c.artifacts))
	for _, a := range c.artifacts {
		byID[a.ID] = a
	}
	if c.deceptions, err = loadAll(fsys, deceptionsDir, ErrInvalidDeception, func(fsys fs.FS, dir string) (Deception, error) {
		return loadDeception(fsys, dir, byID)
	}); err != nil {
		return nil, err
	}
	// An artifact that no deception recommends is valid: it is offered on its
	// own.
	return c, nil
}

// loadAll loads the entry in each directory of dir, which holds nothing else.
func loadAll[T any](fsys fs.FS, dir string, invalid error, load func(fs.FS, string) (T, error)) ([]T, error) {
	// fs.ReadDir orders the entries by name, so the entries are ordered by
	// identifier, which the lookups rely on.
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	var all []T
	for _, e := range entries {
		if !e.IsDir() {
			return nil, fmt.Errorf("%w: %s/%s is not a directory", invalid, dir, e.Name())
		}
		v, err := load(mustSub(fsys, dir), e.Name())
		if err != nil {
			return nil, err
		}
		all = append(all, v)
	}
	if len(all) == 0 {
		return nil, errors.New("load catalog: no entries in " + dir)
	}
	return all, nil
}

// mustSub returns the directory dir of fsys. dir is one of the constants of
// this package, which fs.Sub accepts.
func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err)
	}
	return sub
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

// Artifacts returns every artifact, ordered by identifier, which share their
// data with the catalog as Deceptions describes.
func (c *Catalog) Artifacts() []Artifact {
	return slices.Clone(c.artifacts)
}

// LookupArtifact returns the artifact id, which shares its data with the
// catalog.
func (c *Catalog) LookupArtifact(id string) (Artifact, bool) {
	i, ok := slices.BinarySearchFunc(c.artifacts, id, func(a Artifact, id string) int { return strings.Compare(a.ID, id) })
	if !ok {
		return Artifact{}, false
	}
	return c.artifacts[i], true
}
