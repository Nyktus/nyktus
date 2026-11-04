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

func load(t *testing.T) *catalog.Catalog {
	t.Helper()
	c, err := catalog.Load(embedded.FS())
	if err != nil {
		t.Fatalf("Load(embedded catalog) error = %v", err)
	}
	return c
}

// The server refuses to start with an invalid catalog, so every deception that
// ships must load: its files, markers, formats and slots.
func TestEmbeddedCatalog_IsValid(t *testing.T) {
	t.Parallel()

	c := load(t)
	if len(c.Deceptions()) == 0 {
		t.Fatal("the embedded catalog has no deceptions")
	}
	for _, d := range c.Deceptions() {
		if len(d.Honeytokens)+len(d.Honeypots) == 0 {
			t.Errorf("%s: asks for neither a honeytoken nor a honeypot", d.ID)
		}
		for _, f := range d.Files {
			if !f.Format.Valid() || len(f.Content) == 0 {
				t.Errorf("%s: file %s has format %q and %d bytes", d.ID, f.Name, f.Format, len(f.Content))
			}
		}
	}
}

// The guides are static Markdown. An action that is left over from a template
// would reach the administrator as it is.
func TestEmbeddedCatalog_GuidesAndFilesHoldNoTemplateActions(t *testing.T) {
	t.Parallel()

	for _, d := range load(t).Deceptions() {
		for lang, g := range d.Guide {
			if strings.Contains(g, "{{.") {
				t.Errorf("%s: the guide %s contains a template action", d.ID, lang)
			}
		}
		for _, f := range d.Files {
			if strings.Contains(string(f.Content), "{{.") {
				t.Errorf("%s: the file %s contains a template action", d.ID, f.Name)
			}
		}
	}
}

// A file that holds a honeytoken is a lure, one that holds none is pocket
// litter, and files of several formats are artifact diversity. The deception
// names what its files carry out, because nothing derives it.
func TestEmbeddedCatalog_DeceptionsNameWhatTheirFilesCarryOut(t *testing.T) {
	t.Parallel()

	const (
		lures        = "EAC0005"
		pocketLitter = "EAC0011"
		diversity    = "EAC0022"
	)
	placeholder := regexp.MustCompile(`Honeytoken-(Domain|URL)`)
	for _, d := range load(t).Deceptions() {
		formats := map[catalog.Format]bool{}
		for _, f := range d.Files {
			formats[f.Format] = true
			if !placeholder.Match(f.Content) && !slices.Contains(d.EngageActivities, pocketLitter) {
				t.Errorf("%s: %s holds no honeytoken, so the deception should name %s (pocket litter)", d.ID, f.Name, pocketLitter)
			}
		}
		if len(formats) > 1 && !slices.Contains(d.EngageActivities, diversity) {
			t.Errorf("%s: files of %d formats, so the deception should name %s (artifact diversity)", d.ID, len(formats), diversity)
		}
		if len(d.Honeytokens) > 0 && !slices.Contains(d.EngageActivities, lures) {
			t.Errorf("%s: asks for honeytokens, so the deception should name %s (lures)", d.ID, lures)
		}
	}
}

var codeSpan = regexp.MustCompile("`[^`\n]+`")

// Commands, file names and values are the same in both languages of the guide
// of the accounts in the directory; only the prose is translated. A command
// that differs would send an administrator of one language to something else
// than the other.
func TestEmbeddedCatalog_DirectoryGuideNamesTheSameCodeInBothLanguages(t *testing.T) {
	t.Parallel()

	d, ok := load(t).Lookup("ad-decoy-accounts")
	if !ok {
		t.Fatal("the catalog has no ad-decoy-accounts")
	}
	spans := map[string][]string{}
	for _, lang := range catalog.Languages {
		spans[lang] = codeSpan.FindAllString(d.Guide[lang], -1)
		slices.Sort(spans[lang])
	}
	if len(spans["en"]) == 0 {
		t.Fatal("the guide names no code")
	}
	if !slices.Equal(spans["en"], spans["de"]) {
		t.Errorf("the guides name different code\nen: %q\nde: %q", spans["en"], spans["de"])
	}
}

var codeBlock = regexp.MustCompile("(?s)```powershell\n(.*?)```")

// The scripts that add the accounts of the directory stand in the guide. They
// generate the password when they run and keep it nowhere: a password in the
// text would be the same in every installation, and the account one that an
// intruder can sign in to.
func TestEmbeddedCatalog_DirectoryAccountScriptsGenerateTheirPasswordWhenRun(t *testing.T) {
	t.Parallel()

	d, ok := load(t).Lookup("ad-decoy-accounts")
	if !ok {
		t.Fatal("the catalog has no ad-decoy-accounts")
	}
	literal := regexp.MustCompile(`(?i)\$(plain|password)\s*=\s*['"]|ConvertTo-SecureString\s+['"]`)
	// The password comes from the bytes of the generator, in this order.
	generated := []string{"RandomNumberGenerator]::Create()", ".GetBytes($bytes)", "ToBase64String($bytes)", "$plain -AsPlainText"}
	for _, lang := range catalog.Languages {
		blocks := codeBlock.FindAllStringSubmatch(d.Guide[lang], -1)
		if len(blocks) != 3 {
			t.Fatalf("%s: the guide holds %d scripts, want the three that add an account", lang, len(blocks))
		}
		for _, b := range blocks {
			out := b[1]
			last := -1
			for _, part := range generated {
				i := strings.Index(out, part)
				if i < last || i < 0 {
					t.Errorf("%s: a script does not generate its password from the random number generator (missing or out of order: %q):\n%s", lang, part, out)
					break
				}
				last = i
			}
			if literal.MatchString(out) {
				t.Errorf("%s: a script assigns a literal to the password:\n%s", lang, out)
			}
		}
	}
	// The accounts of the story are not files, because a file is placed as it
	// is.
	if len(d.Files) != 0 {
		t.Errorf("ad-decoy-accounts has %d files, want its scripts in the guide only", len(d.Files))
	}
}
