// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog_test

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	embedded "nyktus.org/nyktus/catalog"
	"nyktus.org/nyktus/internal/catalog"
)

var codeSpan = regexp.MustCompile("`[^`\n]+`")

// Commands, file names and values are the same in both languages of the guide
// of the accounts in the directory; only the prose is translated. A command
// that differs would send an administrator of one language to something else
// than the other.
func TestEmbeddedCatalog_DirectoryGuideNamesTheSameCodeInBothLanguages(t *testing.T) {
	t.Parallel()

	c, err := catalog.Load(embedded.FS())
	if err != nil {
		t.Fatal(err)
	}
	d, ok := c.Lookup("ad-decoy-accounts")
	if !ok {
		t.Fatal("the catalog has no ad-decoy-accounts")
	}
	placed := map[string]catalog.Placed{}
	for _, h := range d.Honeytokens {
		placed[h.Key] = placedAs(h.Key)
	}
	secrets := map[string]map[string]string{}
	for _, a := range d.Artifacts {
		secrets[a.ID] = goldenSecrets(a.Secrets)
	}
	spans := map[string][]string{}
	for _, lang := range catalog.Languages {
		r, err := d.Render(placed, examples(d.Persona), secrets, lang)
		if err != nil {
			t.Fatalf("%s: Render() error = %v", lang, err)
		}
		spans[lang] = codeSpan.FindAllString(string(r.Guide), -1)
		slices.Sort(spans[lang])
	}
	if len(spans["en"]) == 0 {
		t.Fatal("the guide names no code")
	}
	if !slices.Equal(spans["en"], spans["de"]) {
		t.Errorf("the guides name different code\nen: %q\nde: %q", spans["en"], spans["de"])
	}
}

// The scripts that add the accounts of the directory generate the password
// when they run and keep it nowhere. A password in the file would be readable
// with the permission to read artifacts, and it would be the same account
// that an intruder can sign in to.
func TestEmbeddedCatalog_DirectoryAccountScriptsGenerateTheirPasswordWhenRun(t *testing.T) {
	t.Parallel()

	c, err := catalog.Load(embedded.FS())
	if err != nil {
		t.Fatal(err)
	}
	d, ok := c.Lookup("ad-decoy-accounts")
	if !ok {
		t.Fatal("the catalog has no ad-decoy-accounts")
	}
	literal := regexp.MustCompile(`(?i)\$(plain|password)\s*=\s*['"]|ConvertTo-SecureString\s+['"]`)
	// The password comes from the bytes of the generator, in this order.
	generated := []string{"RandomNumberGenerator]::Create()", ".GetBytes($bytes)", "ToBase64String($bytes)", "$plain -AsPlainText"}
	for _, a := range d.Artifacts {
		if len(a.Secrets) != 0 {
			t.Errorf("%s: declares secrets %v, want none", a.ID, a.Secrets)
		}
		out := string(renderAlone(t, a))
		last := -1
		for _, part := range generated {
			i := strings.Index(out, part)
			if i < last || i < 0 {
				t.Errorf("%s: does not generate its password from the random number generator (missing or out of order: %q):\n%s", a.ID, part, out)
				break
			}
			last = i
		}
		if literal.MatchString(out) {
			t.Errorf("%s: assigns a literal to the password:\n%s", a.ID, out)
		}
	}
}
