// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"nyktus.org/nyktus/internal/honeypot"
	"nyktus.org/nyktus/internal/honeytoken"
)

const validDeception = `{
  "schema_version": 3,
  "id": "sample",
  "category": "network",
  "title": {"en": "Sample", "de": "Beispiel"},
  "summary": {"en": "A sample.", "de": "Ein Beispiel."},
  "techniques": ["T1021.004"],
  "engage_activities": ["EAC0005"],
  "honeytokens": [
    {"label": {"en": "Gateway", "de": "Gateway"}, "type": "dns", "techniques": ["T1021.004"]},
    {"label": {"en": "Link", "de": "Link"}, "type": "web_url", "techniques": [], "severity": "high"}
  ],
  "honeypots": [
    {"label": {"en": "Database", "de": "Datenbank"}, "service": "postgres"}
  ],
  "files": [
    {"name": "config.ini", "format": "config", "file": "config.ini"},
    {"name": "Read me.txt", "format": "text", "file": "Read me.txt"}
  ],
  "guide": {"en": "guide.en.md", "de": "guide.de.md"}
}`

// Paths in the catalog of validFiles.
const (
	sampleJSON  = "deceptions/sample/deception.json"
	guideEn     = "deceptions/sample/guide.en.md"
	guideDe     = "deceptions/sample/guide.de.md"
	configFile  = "deceptions/sample/files/config.ini"
	noteFile    = "deceptions/sample/files/Read me.txt"
	filesPrefix = "deceptions/sample/files/"
)

func mapFile(content string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(content)} }

// validFiles returns a catalog with one valid deception, sample, and a second
// one, second, that has the same content. Tests break sample.
func validFiles() fstest.MapFS {
	fsys := fstest.MapFS{}
	for _, id := range []string{"sample", "second"} {
		dir := "deceptions/" + id + "/"
		fsys[dir+"deception.json"] = mapFile(strings.Replace(validDeception, `"id": "sample"`, `"id": "`+id+`"`, 1))
		fsys[dir+"guide.en.md"] = mapFile("Place `config.ini`, with Honeytoken-Domain as the host.\n")
		fsys[dir+"guide.de.md"] = mapFile("Legen Sie `config.ini` ab.\n")
		fsys[dir+"files/config.ini"] = mapFile("host=Honeytoken-Domain\nuser=svc-backup\npassword=example\n")
		fsys[dir+"files/Read me.txt"] = mapFile("Call the service desk, extension 4711.\n")
	}
	return fsys
}

// edit replaces old by replacement in the file name of the catalog, which
// must contain it.
func edit(t *testing.T, name, old, replacement string) func(fstest.MapFS) {
	t.Helper()
	return func(fsys fstest.MapFS) {
		s := string(fsys[name].Data)
		if !strings.Contains(s, old) {
			t.Fatalf("%s does not contain %q", name, old)
		}
		fsys[name] = mapFile(strings.Replace(s, old, replacement, 1))
	}
}

// set sets the file name to content, empty or not.
func set(name, content string) func(fstest.MapFS) {
	return func(fsys fstest.MapFS) { fsys[name] = mapFile(content) }
}

// file sets the file name, or removes it for an empty content.
func file(name, content string) func(fstest.MapFS) {
	return func(fsys fstest.MapFS) {
		if content == "" {
			delete(fsys, name)
			return
		}
		fsys[name] = mapFile(content)
	}
}

func TestLoad_ReadsAValidCatalog(t *testing.T) {
	t.Parallel()

	c, err := Load(validFiles())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	ds := c.Deceptions()
	if len(ds) != 2 || ds[0].ID != "sample" || ds[1].ID != "second" {
		t.Fatalf("Deceptions() = %v, want sample and second in order", ds)
	}
	d, ok := c.Lookup("second")
	if !ok || d.ID != "second" {
		t.Fatalf("Lookup(second) = %v, %v", d, ok)
	}
	if _, ok := c.Lookup("missing"); ok {
		t.Error("Lookup(missing) found a deception")
	}

	d, _ = c.Lookup("sample")
	if got := d.Honeytokens[0].Severity; got != honeytoken.TypeDNS.DefaultSeverity() {
		t.Errorf("severity without a choice = %q, want the default of its type", got)
	}
	if got := d.Honeytokens[1].Severity; got != "high" {
		t.Errorf("severity of the second honeytoken = %q, want high", got)
	}
	if len(d.Honeypots) != 1 || d.Honeypots[0].Service != honeypot.ServicePostgres || d.Honeypots[0].Label["de"] != "Datenbank" {
		t.Errorf("Honeypots = %+v, want the postgres slot", d.Honeypots)
	}
	f, ok := d.File("config.ini")
	if !ok || f.Format != FormatConfig || !strings.Contains(string(f.Content), "svc-backup") {
		t.Errorf("File(config.ini) = %+v, %v", f, ok)
	}
	if _, ok := d.File("missing"); ok {
		t.Error("File(missing) found a file")
	}
	if !strings.Contains(d.Guide["en"], "Honeytoken-Domain") || d.Guide["de"] == "" {
		t.Errorf("Guide = %v", d.Guide)
	}
}

// The files of a deception are static: the loader stores them as they are, with
// their line endings, and renders nothing.
func TestLoad_KeepsFilesAsTheyAre(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	fsys[configFile] = mapFile("host=Honeytoken-Domain\r\nname={{.Persona.Name}}\r\n")
	c, err := Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := c.Lookup("sample")
	f, _ := d.File("config.ini")
	if got, want := string(f.Content), "host=Honeytoken-Domain\r\nname={{.Persona.Name}}\r\n"; got != want {
		t.Errorf("content = %q, want %q", got, want)
	}
}

// The placeholders stand where the administrator enters a honeytoken, so they
// are the one place where the words of the markers are allowed.
func TestLoad_AllowsThePlaceholdersInFilesAndMarkersInGuides(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	fsys[configFile] = mapFile("a=Honeytoken-Domain\nb=Honeytoken-URL\n")
	fsys[guideEn] = mapFile("This honeytoken is part of a deception that Nyktus created, with Honeytoken-Domain.\n")
	if _, err := Load(fsys); err != nil {
		t.Errorf("Load() error = %v, want the placeholders and the markers in the guide accepted", err)
	}

	// Where a kind has several honeytokens, every placeholder names its slot.
	several := validFiles()
	edit(t, sampleJSON, `"type": "web_url"`, `"type": "dns"`)(several)
	several[configFile] = mapFile("a=Honeytoken-Domain-Gateway\nb=Honeytoken-Domain-Link\n")
	several[guideEn] = mapFile("Place `config.ini` with Honeytoken-Domain-Gateway.\n")
	if _, err := Load(several); err != nil {
		t.Errorf("Load() error = %v, want the placeholders with the names of their slots accepted", err)
	}
}

func TestLoad_RejectsInvalidDeceptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(fstest.MapFS)
		want   string
	}{
		{"unknown member", edit(t, sampleJSON, `"category": "network",`, `"category": "network", "persona": [],`), "unknown field"},
		{"data after the definition", edit(t, sampleJSON, `"guide": {"en": "guide.en.md", "de": "guide.de.md"}
}`, `"guide": {"en": "guide.en.md", "de": "guide.de.md"}
} {}`), "unexpected data"},
		{"older schema", edit(t, sampleJSON, `"schema_version": 3`, `"schema_version": 2`), "schema version 2"},
		{"identifier differs from the directory", edit(t, sampleJSON, `"id": "sample"`, `"id": "other"`), "differs from the name"},
		{"unknown category", edit(t, sampleJSON, `"network"`, `"cellar"`), "unknown category"},
		{"title in one language only", edit(t, sampleJSON, `"title": {"en": "Sample", "de": "Beispiel"}`, `"title": {"en": "Sample"}`), "title"},
		{"unknown technique", edit(t, sampleJSON, `"techniques": ["T1021.004"],
  "engage`, `"techniques": ["T0000"],
  "engage`), "techniques"},
		{"unknown Engage activity", edit(t, sampleJSON, `["EAC0005"]`, `["EAC9999"]`), "engage_activities"},
		{"no slot", func(fsys fstest.MapFS) {
			edit(t, sampleJSON, `"honeypots": [
    {"label": {"en": "Database", "de": "Datenbank"}, "service": "postgres"}
  ],`, `"honeypots": [],`)(fsys)
			edit(t, sampleJSON, `"honeytokens": [
    {"label": {"en": "Gateway", "de": "Gateway"}, "type": "dns", "techniques": ["T1021.004"]},
    {"label": {"en": "Link", "de": "Link"}, "type": "web_url", "techniques": [], "severity": "high"}
  ],`, `"honeytokens": [],`)(fsys)
		}, "detects nothing"},
		{"unknown honeytoken type", edit(t, sampleJSON, `"type": "dns"`, `"type": "qr"`), "unknown type"},
		{"honeytoken severity info", edit(t, sampleJSON, `"severity": "high"`, `"severity": "info"`), "severity"},
		{"honeytoken label too long", edit(t, sampleJSON, `"label": {"en": "Link", "de": "Link"}`, `"label": {"en": "`+strings.Repeat("x", 61)+`", "de": "Link"}`), "label"},
		{"honeytoken label that is no name", edit(t, sampleJSON, `"label": {"en": "Link", "de": "Link"}`, `"label": {"en": "Link", "de": "Li\u0007nk"}`), "label"},
		{"unknown honeypot service", edit(t, sampleJSON, `"service": "postgres"`, `"service": "tcp"`), "unknown service"},
		{"honeypot label empty", edit(t, sampleJSON, `"label": {"en": "Database", "de": "Datenbank"}`, `"label": {"en": "", "de": "Datenbank"}`), "label"},
		{"file with a path as its name", edit(t, sampleJSON, `"name": "config.ini"`, `"name": "../config.ini"`), "name that every system accepts"},
		{"file named like a device of Windows", edit(t, sampleJSON, `"name": "config.ini"`, `"name": "Aux.txt"`), "name that every system accepts"},
		{"file named after a device of Windows without an extension", edit(t, sampleJSON, `"name": "config.ini"`, `"name": "NUL"`), "name that every system accepts"},
		{"file with a leading dot", edit(t, sampleJSON, `"name": "config.ini"`, `"name": ".env"`), "name that every system accepts"},
		{"file with an unknown format", edit(t, sampleJSON, `"format": "config"`, `"format": "binary"`), "known format"},
		{"two files with the same name apart from case", edit(t, sampleJSON, `"name": "Read me.txt"`, `"name": "CONFIG.ini"`), "used twice"},
		{"file that is missing", file(configFile, ""), "missing"},
		{"file that nothing lists", file(filesPrefix+"extra.txt", "x\n"), "not referenced"},
		{"files in a directory that the definition does not list", edit(t, sampleJSON, `"files": [
    {"name": "config.ini", "format": "config", "file": "config.ini"},
    {"name": "Read me.txt", "format": "text", "file": "Read me.txt"}
  ],`, `"files": [],`), "not referenced"},
		{"files listed without a directory", func(fsys fstest.MapFS) {
			file(configFile, "")(fsys)
			file(noteFile, "")(fsys)
		}, "missing"},
		{"empty file", set(configFile, ""), "want 1 to"},
		{"file that is not UTF-8", file(configFile, "host=\xff\n"), "UTF-8"},
		{"file with a NUL", file(configFile, "host=a\x00b\n"), "U+0000"},
		{"file with an escape sequence", file(configFile, "host=\x1b[31m\n"), "U+001B"},
		{"file with a byte order mark", file(configFile, "\xef\xbb\xbfhost=a\n"), "byte order mark"},
		{"file larger than the limit", file(configFile, strings.Repeat("a", MaxFileBytes+1)), "larger than"},
		{"file with a product name", edit(t, configFile, "svc-backup", "nyktus"), `"nyktus"`},
		{"file with the word honeytoken", edit(t, configFile, "svc-backup", "honeytoken"), `"honeytoken"`},
		{"file with the word decoy", edit(t, configFile, "svc-backup", "Decoy"), `"decoy"`},
		{"file with a license notice", edit(t, configFile, "svc-backup", "CC BY 4.0"), "cc by"},
		{"file with the identifier of the deception", edit(t, configFile, "svc-backup", "sample"), `"sample"`},
		{"file named after a marker", edit(t, sampleJSON, `"name": "Read me.txt"`, `"name": "canary.txt"`), "canary"},
		{"placeholder that is not a placeholder", edit(t, configFile, "svc-backup", "Honeytoken-Host"), `"honeytoken"`},
		{"placeholder of the lower case", edit(t, configFile, "svc-backup", "honeytoken-domain"), `"honeytoken"`},
		{"placeholder of a DNS honeytoken without one", edit(t, sampleJSON, `"type": "dns"`, `"type": "web_image"`), "does not have"},
		{"placeholder that names a slot of the only honeytoken of its kind", edit(t, configFile, "svc-backup", "Honeytoken-Domain-Gateway"), "names a slot"},
		{"placeholder without a slot of one of several honeytokens", func(fsys fstest.MapFS) {
			edit(t, sampleJSON, `"type": "web_url"`, `"type": "dns"`)(fsys)
			edit(t, configFile, "svc-backup", "Honeytoken-Domain")(fsys)
			set(guideEn, "Place `config.ini`.\n")(fsys)
		}, "does not say which of the 2"},
		{"placeholder in a guide that does not fit", set(guideEn, "Replace Honeytoken-Domain-Gateway.\n"), "guide en"},
		{"placeholder of a URL without one", func(fsys fstest.MapFS) {
			set(configFile, "host=Honeytoken-URL\n")(fsys)
			set(guideEn, "Place `config.ini`.\n")(fsys)
			edit(t, sampleJSON, `"type": "web_url"`, `"type": "dns"`)(fsys)
		}, "does not have"},
		{"guide missing", file(guideDe, ""), "guide de"},
		{"one guide for both languages", edit(t, sampleJSON, `"de": "guide.de.md"`, `"de": "guide.en.md"`), "same file"},
		{"two honeytokens with the label of one", edit(t, sampleJSON, `"label": {"en": "Link", "de": "Link"}`, `"label": {"en": "Gateway", "de": "Gateway"}`), "one name"},
		{"two honeypots with the label of one", edit(t, sampleJSON, `"honeypots": [
    {"label": {"en": "Database", "de": "Datenbank"}, "service": "postgres"}
  ],`, `"honeypots": [
    {"label": {"en": "Database", "de": "Datenbank"}, "service": "postgres"},
    {"label": {"en": "Other", "de": "Datenbank"}, "service": "ssh"}
  ],`), "one name"},
		{"guide with another name", edit(t, sampleJSON, `"de": "guide.de.md"`, `"de": "guide.md"`), "guide de"},
		{"guide in a language that does not exist", edit(t, sampleJSON, `"de": "guide.de.md"`, `"fr": "guide.de.md"`), "not a language"},
		{"guide empty", set(guideEn, ""), "want 1 to"},
		{"guide with a NUL", file(guideEn, "a\x00b"), "U+0000"},
		{"file that nothing lists next to the definition", file("deceptions/sample/notes.md", "x\n"), "not referenced"},
		{"not a regular file next to the definition", file("deceptions/sample/script.sh", "x"), "may hold"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fsys := validFiles()
			tt.mutate(fsys)
			_, err := Load(fsys)
			if !errors.Is(err, ErrInvalidDeception) {
				t.Fatalf("Load() error = %v, want ErrInvalidDeception", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Load() error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestLoad_RejectsAnInvalidCatalog(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		fsys   func() fstest.MapFS
		mutate func(fstest.MapFS)
		want   string
	}{
		{"no directory of deceptions", func() fstest.MapFS { return fstest.MapFS{} }, nil, "load catalog"},
		{"no deception", func() fstest.MapFS {
			return fstest.MapFS{"deceptions/.keep": mapFile("")}
		}, nil, "is not a directory"},
		{"a file between the deceptions", validFiles, file("deceptions/readme.md", "x"), "is not a directory"},
		{"identifier that is no identifier", validFiles, func(fsys fstest.MapFS) {
			fsys["deceptions/Bad_Name/deception.json"] = mapFile(strings.Replace(validDeception, `"sample"`, `"Bad_Name"`, 1))
		}, "not a valid identifier"},
		{"definition missing", validFiles, file("deceptions/second/deception.json", ""), "deception.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fsys := tt.fsys()
			if tt.mutate != nil {
				tt.mutate(fsys)
			}
			_, err := Load(fsys)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

// A deception that only asks for honeypots, and one that only has files for
// honeytokens that the story asks for elsewhere, are valid.
func TestLoad_AcceptsADeceptionWithHoneypotsOnly(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	edit(t, sampleJSON, `"honeytokens": [
    {"label": {"en": "Gateway", "de": "Gateway"}, "type": "dns", "techniques": ["T1021.004"]},
    {"label": {"en": "Link", "de": "Link"}, "type": "web_url", "techniques": [], "severity": "high"}
  ],`, `"honeytokens": [],`)(fsys)
	fsys[configFile] = mapFile("host=db.internal\n")
	fsys[guideEn] = mapFile("Place `config.ini`.\n")
	if _, err := Load(fsys); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestFindMarker(t *testing.T) {
	t.Parallel()

	tests := []struct {
		text string
		want string
	}{
		{"host=Honeytoken-Domain", ""},
		{"host=Honeytoken-Domain-Database and Honeytoken-URL-Link", ""},
		{"host=honeytoken-Domain", "honeytoken"},
		{"a Honeytoken here", "honeytoken"},
		{"Generated By a tool", "generated by"},
		{"cc-by-sa", "cc-by"},
		{"gcc by default", ""},
		{"nothing", ""},
	}
	for _, tt := range tests {
		if got := findMarker(tt.text); got != tt.want {
			t.Errorf("findMarker(%q) = %q, want %q", tt.text, got, tt.want)
		}
	}
}
