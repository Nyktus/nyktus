// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog_test

import (
	"bytes"
	"errors"
	"flag"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	embedded "nyktus.org/nyktus/catalog"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/engage"
)

var update = flag.Bool("update", false, "rewrite the golden files of the embedded catalog")

// The server refuses to start with an invalid catalog, so every deception and
// artifact that ships must load.
func TestEmbeddedCatalog_IsValid(t *testing.T) {
	t.Parallel()

	c, err := catalog.Load(embedded.FS())
	if err != nil {
		t.Fatalf("Load(embedded catalog) error = %v", err)
	}
	if len(c.Deceptions()) == 0 || len(c.Artifacts()) == 0 {
		t.Fatal("the embedded catalog has no deceptions or no artifacts")
	}
}

// placedAs returns the host name and the URL under which a honeytoken with the
// key is placed, that look like those that Nyktus generates.
func placedAs(key string) catalog.Placed {
	value := strings.ToLower(key) + "q3xwz7a2kfm4ub6tyc5nre"
	return catalog.Placed{Host: value + ".d.example.net", URL: "https://t.example.net/" + value}
}

// goldenSecrets returns fixed secrets that look like those that Nyktus
// generates.
func goldenSecrets(secrets []catalog.Secret) map[string]string {
	values := map[string]string{}
	for _, s := range secrets {
		values[s.Key] = strings.Repeat("Xy7", s.Length)[:s.Length]
	}
	return values
}

// examples returns the examples of the persona, which fit every kind.
func examples(persona []catalog.PersonaField) map[string]string {
	values := map[string]string{}
	for _, p := range persona {
		values[p.Key] = p.Example
	}
	return values
}

// bound returns the honeytokens that bind every slot of a, as a deception with
// a honeytoken of each key places them.
func bound(a catalog.Artifact) map[string]catalog.Placed {
	placed := map[string]catalog.Placed{}
	for _, s := range a.Slots {
		placed[s.Key] = placedAs(s.Key)
	}
	return placed
}

// withoutOptional returns the honeytokens that bind the required slots of a.
func withoutOptional(a catalog.Artifact) map[string]catalog.Placed {
	placed := bound(a)
	for _, s := range a.Slots {
		if s.Optional {
			delete(placed, s.Key)
		}
	}
	return placed
}

// renderAlone renders the artifact with the examples of its persona, fixed
// secrets and every slot bound.
func renderAlone(t *testing.T, a catalog.Artifact) []byte {
	t.Helper()
	return renderWith(t, a, examples(a.Persona))
}

// renderWith renders the artifact like renderAlone, with the persona given.
func renderWith(t *testing.T, a catalog.Artifact, persona map[string]string) []byte {
	t.Helper()
	values, err := a.Values(bound(a), persona, goldenSecrets(a.Secrets))
	if err != nil {
		t.Fatalf("%s: Values() error = %v", a.ID, err)
	}
	out, err := a.Render(values)
	if err != nil {
		t.Fatalf("%s: Render() error = %v", a.ID, err)
	}
	return out
}

// Every artifact and guide of the embedded catalog is compared with its
// golden file, so that a change of a template shows as a diff of what
// operators receive. Regenerate them with go test ./internal/catalog/... -update.
func TestEmbeddedCatalog_RendersTheGoldenFiles(t *testing.T) {
	t.Parallel()

	c, err := catalog.Load(embedded.FS())
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "golden")
	var want []string
	check := func(name string, got []byte) {
		t.Helper()
		path := filepath.Join(golden, name)
		want = append(want, path)
		if *update {
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, got, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		file, err := os.ReadFile(path) //nolint:gosec // A golden file of this test.
		if err != nil {
			t.Errorf("%s: %v; run go test ./internal/catalog/... -update", path, err)
			return
		}
		if !bytes.Equal(got, file) {
			t.Errorf("%s differs from the rendered file; run go test ./internal/catalog/... -update and review the diff\ngot:\n%s", path, got)
		}
	}

	for _, a := range c.Artifacts() {
		out := renderAlone(t, a)
		if a.LineEndings == catalog.CRLF && bytes.Count(out, []byte("\n")) != bytes.Count(out, []byte("\r\n")) {
			t.Errorf("%s: not every line ends in CRLF", a.ID)
		}
		check(filepath.Join("artifacts", a.ID, a.FileName), out)
	}

	for _, d := range c.Deceptions() {
		placed := map[string]catalog.Placed{}
		for _, h := range d.Honeytokens {
			placed[h.Key] = placedAs(h.Key)
		}
		secrets := map[string]map[string]string{}
		for _, a := range d.Artifacts {
			secrets[a.ID] = goldenSecrets(a.Secrets)
		}
		// Applying renders the artifacts and the guide of one language, and
		// checks every artifact for markers, also for the identifiers of the
		// deception and of the artifact. A rendered artifact names neither the
		// product nor what it is, also not as metadata or in a comment, so
		// that whoever finds it cannot tell it from a real file.
		for _, lang := range catalog.Languages {
			r, err := d.Render(placed, examples(d.Persona), secrets, lang)
			if err != nil {
				t.Fatalf("%s/%s: Render() error = %v", d.ID, lang, err)
			}
			if len(r.Artifacts) != len(d.Artifacts) {
				t.Errorf("%s/%s: rendered %d artifacts, want %d", d.ID, lang, len(r.Artifacts), len(d.Artifacts))
			}
			// The artifacts of a story share values of the persona but may
			// give them other examples, so the artifact alone is rendered with
			// the examples of the deception.
			for _, a := range r.Artifacts {
				persona := map[string]string{}
				for _, p := range a.Persona {
					persona[p.Key] = examples(d.Persona)[p.Key]
				}
				if !bytes.Equal(a.Content, renderWith(t, a.Artifact, persona)) {
					t.Errorf("%s/%s: applying in %s renders another %s than the artifact with the same values", d.ID, a.ID, lang, a.FileName)
				}
			}
			check(filepath.Join("deceptions", d.ID, "guide."+lang+".md"), r.Guide)
		}
	}

	// A golden file without a template would hide that a file was removed.
	var have []string
	if err := filepath.WalkDir(golden, func(path string, e os.DirEntry, err error) error {
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

// Every artifact renders with its slots bound and with every optional slot
// empty, as pocket litter. A value that the catalog does not control, such as
// a persona of "decoy" or a host of that name, makes a file that uses it fail
// instead of leaving the server.
func TestEmbeddedCatalog_ArtifactsRenderWithBoundAndEmptySlots(t *testing.T) {
	t.Parallel()

	c, err := catalog.Load(embedded.FS())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range c.Artifacts() {
		persona := examples(a.Persona)
		secrets := goldenSecrets(a.Secrets)

		// Every optional slot is guarded on its own, so these two cover the
		// combinations.
		for name, placed := range map[string]map[string]catalog.Placed{"bound": bound(a), "without the optional slots": withoutOptional(a)} {
			values, err := a.Values(placed, persona, secrets)
			if err != nil {
				t.Errorf("%s %s: Values() error = %v", a.ID, name, err)
				continue
			}
			if _, err := a.Render(values); err != nil {
				t.Errorf("%s %s: Render() error = %v", a.ID, name, err)
			}
		}

		// A value that reveals what the file is stops it where the template
		// uses the value; a value that only the placing uses never reaches
		// the file.
		check := func(what string, placed map[string]catalog.Placed, persona map[string]string) {
			t.Helper()
			values, err := a.Values(placed, persona, secrets)
			if err != nil {
				t.Fatalf("%s: Values() error = %v", a.ID, err)
			}
			out, err := a.Render(values)
			if errors.Is(err, catalog.ErrArtifactReveals) {
				return
			}
			if err != nil || bytes.Contains(bytes.ToLower(out), []byte("decoy")) {
				t.Errorf("%s: Render(%s = decoy) = %q, %v, want ErrArtifactReveals or a file without it", a.ID, what, out, err)
			}
		}
		for _, p := range a.Persona {
			revealing := maps.Clone(persona)
			revealing[p.Key] = "decoy"
			check("persona "+p.Key, bound(a), revealing)
		}
		for _, s := range a.Slots {
			revealing := bound(a)
			revealing[s.Key] = catalog.Placed{Host: "decoy.d.example.net", URL: "https://decoy.example.net/x"}
			check("slot "+s.Key, revealing, persona)
		}
	}
}

// An artifact without a slot is pocket litter: it raises no event, whatever
// happens to it. Its placing text tells the administrator where to put it
// beside a lure and that it triggers nothing on its own, so that nobody takes
// it for a lure.
func TestEmbeddedCatalog_PocketLitterSaysWhereToPlaceIt(t *testing.T) {
	t.Parallel()

	c, err := catalog.Load(embedded.FS())
	if err != nil {
		t.Fatal(err)
	}
	litter := 0
	for _, a := range c.Artifacts() {
		if len(a.Slots) != 0 {
			continue
		}
		litter++
		for _, lang := range catalog.Languages {
			if a.Placing[lang] == nil {
				t.Errorf("%s: no placing text in %s", a.ID, lang)
			}
		}
	}
	if litter == 0 {
		t.Error("the embedded catalog has no pocket litter")
	}
}

// Applying any deception of the embedded catalog carries out activities that
// exist in Engage, at most as many as a scenario may name, and its lures.
// Pocket litter is among them exactly when the deception recommends an
// artifact without a slot.
func TestEmbeddedCatalog_DeceptionsCarryOutLures(t *testing.T) {
	t.Parallel()

	c, err := catalog.Load(embedded.FS())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range c.Deceptions() {
		placed := map[string]catalog.Placed{}
		for _, h := range d.Honeytokens {
			placed[h.Key] = placedAs(h.Key)
		}
		got := catalog.Activities(d.EngageActivities, d.Artifacts, placed, examples(d.Persona))
		if len(got) > 20 || !slices.Contains(got, catalog.ActivityLures) {
			t.Errorf("%s: activities = %v, want at most 20 with %s", d.ID, got, catalog.ActivityLures)
		}
		litter := slices.ContainsFunc(d.Artifacts, func(a catalog.Artifact) bool { return len(a.Slots) == 0 })
		if slices.Contains(got, catalog.ActivityPocketLitter) != litter {
			t.Errorf("%s: activities = %v, want pocket litter = %t: it follows from the artifacts without a slot", d.ID, got, litter)
		}
		for _, id := range got {
			if _, ok := engage.Lookup(id); !ok {
				t.Errorf("%s: activity %s is not in the bundled list", d.ID, id)
			}
		}
	}
}
