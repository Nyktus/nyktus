// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	embedded "nyktus.org/nyktus/catalog"
	"nyktus.org/nyktus/internal/catalog"
)

var update = flag.Bool("update", false, "rewrite the golden files of the embedded catalog")

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

// goldenValues returns fixed values for every field of d: the examples of
// the persona, and values for honeytokens and secrets that look like those
// that Nyktus generates.
func goldenValues(d catalog.Deception) map[string]string {
	values := map[string]string{}
	for _, h := range d.Honeytokens {
		value := strings.ToLower(h.Key) + "q3xwz7a2kfm4ub6tyc5nre"
		values["Honeytokens."+h.Key+".Host"] = value + ".d.example.net"
		values["Honeytokens."+h.Key+".URL"] = "https://t.example.net/" + value
	}
	for _, p := range d.Persona {
		values["Persona."+p.Key] = p.Example
	}
	for _, s := range d.Secrets {
		values["Secrets."+s.Key] = strings.Repeat("Xy7", s.Length)[:s.Length]
	}
	return values
}

// Every artifact and guide of the embedded catalog is compared with its
// golden file, so that a change of a template shows as a diff of what
// operators receive. Regenerate them with go test ./internal/catalog/... -update.
func TestEmbeddedCatalog_RendersTheGoldenFiles(t *testing.T) {
	t.Parallel()

	c, err := catalog.Load(embedded.Deceptions())
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, d := range c.Deceptions() {
		values := goldenValues(d)
		files := map[string][]byte{}
		for _, a := range d.Artifacts {
			out, err := a.Render(values)
			if err != nil {
				t.Fatalf("%s/%s: Render() error = %v", d.ID, a.Key, err)
			}
			files[a.FileName] = out

			// A rendered artifact names neither the product nor what it is,
			// also not as metadata or in a comment, so that whoever finds it
			// cannot tell it from a real file.
			if m := d.Reveals(out); m != "" {
				t.Errorf("%s/%s: the artifact contains %q", d.ID, a.Key, m)
			}
			if a.LineEndings == catalog.CRLF && bytes.Count(out, []byte("\n")) != bytes.Count(out, []byte("\r\n")) {
				t.Errorf("%s/%s: not every line ends in CRLF", d.ID, a.Key)
			}
		}
		// Applying renders the artifacts and the guide of one language, and
		// checks the artifacts for markers again.
		for _, lang := range catalog.Languages {
			r, err := d.Render(values, lang)
			if err != nil {
				t.Fatalf("%s/%s: Render() error = %v", d.ID, lang, err)
			}
			for _, a := range r.Artifacts {
				if !bytes.Equal(a.Content, files[a.FileName]) {
					t.Errorf("%s/%s: applying in %s renders another %s", d.ID, a.Key, lang, a.FileName)
				}
			}
			files["guide."+lang+".md"] = r.Guide
		}

		for name, got := range files {
			path := filepath.Join("testdata", "golden", d.ID, name)
			want = append(want, path)
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			golden, err := os.ReadFile(path) //nolint:gosec // A golden file of this test.
			if err != nil {
				t.Errorf("%s: %v; run go test ./internal/catalog/... -update", path, err)
				continue
			}
			if !bytes.Equal(got, golden) {
				t.Errorf("%s differs from the rendered file; run go test ./internal/catalog/... -update and review the diff\ngot:\n%s", path, got)
			}
		}
	}

	// A golden file without a template would hide that a file was removed.
	var have []string
	if err := filepath.WalkDir(filepath.Join("testdata", "golden"), func(path string, e os.DirEntry, err error) error {
		if err == nil && !e.IsDir() {
			have = append(have, path)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	slices.Sort(want)
	slices.Sort(have)
	if !slices.Equal(want, have) {
		t.Errorf("golden files %v, want %v; remove the files of removed templates", have, want)
	}
}
