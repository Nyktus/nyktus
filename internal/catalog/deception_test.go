// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"nyktus.org/nyktus/internal/honeytoken"
)

const validDeception = `{
  "schema_version": 2,
  "id": "sample",
  "category": "network",
  "title": {"en": "Sample", "de": "Beispiel"},
  "summary": {"en": "A sample.", "de": "Ein Beispiel."},
  "techniques": ["T1021.004"],
  "engage_activities": ["EAC0005"],
  "honeytokens": [
    {"key": "Gateway", "type": "dns", "label": {"en": "Gateway", "de": "Gateway"}, "techniques": ["T1021.004"]},
    {"key": "Link", "type": "web_url", "label": {"en": "Link", "de": "Link"}, "techniques": []}
  ],
  "persona": [
    {"key": "Domain", "kind": "host", "label": {"en": "Domain", "de": "Domain"}, "example": "corp.example.com"},
    {"key": "Company", "kind": "text", "label": {"en": "Company", "de": "Firma"}, "example": "Example Ltd"}
  ],
  "artifacts": ["config", "note"],
  "guide": {"en": "guide.en.md.tmpl", "de": "guide.de.md.tmpl"}
}`

// configArtifact needs a honeytoken and generates a secret.
const configArtifact = `{
  "schema_version": 1,
  "id": "config",
  "category": "network",
  "title": {"en": "Config", "de": "Einstellung"},
  "summary": {"en": "A configuration.", "de": "Eine Einstellung."},
  "slots": [{"key": "Gateway", "accepts": ["dns"], "optional": false}],
  "persona": [],
  "secrets": [{"key": "Password", "length": 16}],
  "file_name": "config",
  "format": "config",
  "line_endings": "lf",
  "template": "config.tmpl"
}`

// noteArtifact asks for the persona, carries a honeytoken in an optional slot
// and is pocket litter without it.
const noteArtifact = `{
  "schema_version": 1,
  "id": "note",
  "category": "data",
  "title": {"en": "Note", "de": "Notiz"},
  "summary": {"en": "A note.", "de": "Eine Notiz."},
  "slots": [{"key": "Link", "accepts": ["web_url", "web_image"], "optional": true}],
  "persona": [
    {"key": "Domain", "kind": "host", "label": {"en": "Domain", "de": "Domain"}, "example": "corp.example.com"},
    {"key": "Company", "kind": "text", "label": {"en": "Company", "de": "Firma"}, "example": "Example Ltd"}
  ],
  "secrets": [],
  "file_name": "Read me.txt",
  "format": "text",
  "line_endings": "crlf",
  "template": "note.txt.tmpl"
}`

const (
	configTemplate = "Host {{.Honeytokens.Gateway.Host}}\nPassword {{.Secrets.Password}}\n"
	noteTemplate   = "{{.Persona.Company}}{{if .Honeytokens.Link.URL}}: {{.Honeytokens.Link.URL}}{{end}} on {{.Persona.Domain}}\n"
)

// Paths in the catalog of validFiles.
const (
	sampleJSON   = "deceptions/sample/deception.json"
	configJSON   = "artifacts/config/artifact.json"
	configTmpl   = "artifacts/config/config.tmpl"
	noteJSON     = "artifacts/note/artifact.json"
	noteTmpl     = "artifacts/note/note.txt.tmpl"
	guideEnTmpl  = "deceptions/sample/guide.en.md.tmpl"
	guideDeTmpl  = "deceptions/sample/guide.de.md.tmpl"
	secondJSON   = "deceptions/second/deception.json"
	deceptionDir = "deceptions/"
)

func mapFile(content string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(content)} }

// validFiles returns a catalog with two artifacts, config and note, and two
// valid deceptions, sample and second, that recommend both and whose templates
// reference every value. Tests break sample, config and note.
func validFiles() fstest.MapFS {
	fsys := fstest.MapFS{
		configJSON: mapFile(configArtifact),
		configTmpl: mapFile(configTemplate),
		noteJSON:   mapFile(noteArtifact),
		noteTmpl:   mapFile(noteTemplate),
	}
	for _, id := range []string{"sample", "second"} {
		fsys[deceptionDir+id+"/deception.json"] = mapFile(strings.Replace(validDeception, `"id": "sample"`, `"id": "`+id+`"`, 1))
		fsys[deceptionDir+id+"/guide.en.md.tmpl"] = mapFile("Place the honeytoken {{.Honeytokens.Gateway.Host}} for {{.Persona.Company}}.\n")
		fsys[deceptionDir+id+"/guide.de.md.tmpl"] = mapFile("Legen Sie den Honeytoken {{.Honeytokens.Gateway.Host}} ab.\n")
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
	d, ok := c.Lookup("sample")
	if !ok || d.Category != CategoryNetwork || d.Title["de"] != "Beispiel" || len(d.Honeytokens) != 2 ||
		d.Honeytokens[1].Type != honeytoken.TypeWebURL || len(d.Persona) != 2 ||
		len(d.Artifacts) != 2 || d.Artifacts[0].ID != "config" || d.Artifacts[1].FileName != "Read me.txt" || d.Guide["de"] == nil {
		t.Errorf("Lookup(sample) = %+v, %v", d, ok)
	}
	if _, ok := c.Lookup("third"); ok {
		t.Error("Lookup(third) found a deception")
	}

	as := c.Artifacts()
	if len(as) != 2 || as[0].ID != "config" || as[1].ID != "note" {
		t.Fatalf("Artifacts() = %v, want config and note in order", as)
	}
	a, ok := c.LookupArtifact("config")
	if !ok || a.Category != CategoryNetwork || a.Title["de"] != "Einstellung" || a.Secrets[0].Length != 16 ||
		len(a.Slots) != 1 || a.Slots[0].Key != "Gateway" || a.Slots[0].Optional || a.Placing != nil {
		t.Errorf("LookupArtifact(config) = %+v, %v", a, ok)
	}
	if n, _ := c.LookupArtifact("note"); !n.Slots[0].Optional || len(n.Slots[0].Accepts) != 2 || len(n.Persona) != 2 {
		t.Errorf("LookupArtifact(note) = %+v", n)
	}
	if _, ok := c.LookupArtifact("third"); ok {
		t.Error("LookupArtifact(third) found an artifact")
	}

	// Guides are Markdown.
	out, err := d.Guide["en"].Render(map[string]string{"Honeytokens.Gateway.Host": "abc.d.example.net", "Persona.Company": "A<b>"})
	if err != nil || string(out) != "Place the honeytoken abc.d.example.net for A\\<b\\>.\n" {
		t.Errorf("Render(guide) = %q, %v", out, err)
	}
}

func TestDeception_Fields(t *testing.T) {
	t.Parallel()

	c, err := Load(validFiles())
	if err != nil {
		t.Fatal(err)
	}
	d, _ := c.Lookup("sample")
	want := Fields{
		"Honeytokens.Gateway.Host": KindHost,
		"Honeytokens.Link.URL":     KindURL,
		"Persona.Domain":           KindHost,
		"Persona.Company":          KindText,
	}
	got := d.Fields()
	if len(got) != len(want) {
		t.Fatalf("Fields() = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("Fields()[%s] = %q, want %q", k, got[k], v)
		}
	}
}

// Every rule of a deception has a case that breaks only that rule, in the
// deception sample, and leaves the catalog otherwise valid.
func TestLoad_RejectsInvalidDeceptions(t *testing.T) {
	t.Parallel()

	def := func(old, replacement string) func(fstest.MapFS) { return edit(t, sampleJSON, old, replacement) }

	for name, c := range map[string]struct {
		change func(fstest.MapFS)
		// want is part of the error, so that a case cannot pass because
		// another rule rejects it.
		want string
	}{
		// The directory and its files.
		"malformed directory":    {func(fsys fstest.MapFS) { moveDir(fsys, "sample", "Sample") }, "not a valid identifier"},
		"long directory":         {func(fsys fstest.MapFS) { moveDir(fsys, "sample", strings.Repeat("a", 65)) }, "not a valid identifier"},
		"missing definition":     {file(sampleJSON, ""), "deception.json is missing"},
		"unreferenced file":      {file(deceptionDir+"sample/extra.tmpl", "x"), "extra.tmpl is not referenced"},
		"file of another name":   {file(deceptionDir+"sample/notes.txt", "x"), "notes.txt is not a template"},
		"subdirectory":           {file(deceptionDir+"sample/x.tmpl/guide.tmpl", "x"), "x.tmpl is not a template"},
		"file too large":         {file(guideDeTmpl, strings.Repeat("a", maxFileBytes+1)), "guide.de.md.tmpl is larger than"},
		"missing guide file":     {file(guideDeTmpl, ""), "the template guide.de.md.tmpl is missing"},
		"unknown field":          {def(`"schema_version": 2,`, `"schema_version": 2, "author": "x",`), "unknown field"},
		"unknown member":         {def(`"artifacts": ["config", "note"],`, `"artifacts": ["config", "note"], "secrets": [],`), "unknown field"},
		"trailing data":          {func(fsys fstest.MapFS) { appendTo(fsys, sampleJSON, " {}") }, "unexpected data"},
		"malformed JSON":         {def(`"schema_version": 2,`, `"schema_version": 2`), "deception.json:"},
		"schema version":         {def(`"schema_version": 2`, `"schema_version": 1`), "schema version 1"},
		"identifier":             {def(`"id": "sample"`, `"id": "other"`), "differs from the name"},
		"category":               {def(`"category": "network"`, `"category": "mainframe"`), "unknown category"},
		"title language missing": {def(`"title": {"en": "Sample", "de": "Beispiel"}`, `"title": {"en": "Sample"}`), "title: want a text in each"},
		"title language unknown": {def(`"title": {"en": "Sample", "de": "Beispiel"}`, `"title": {"en": "Sample", "fr": "Modele"}`), "title: de: want 1 to"},
		"title extra language":   {def(`"title": {"en": "Sample", "de": "Beispiel"}`, `"title": {"en": "Sample", "de": "Beispiel", "fr": "Modele"}`), "title: want a text in each"},
		"title empty":            {def(`"de": "Beispiel"`, `"de": ""`), "title: de: want 1 to"},
		"title spaces":           {def(`"de": "Beispiel"`, `"de": " Beispiel"`), "title: de: want 1 to"},
		"title too long":         {def(`"de": "Beispiel"`, `"de": "`+strings.Repeat("a", maxTitleLength+1)+`"`), "title: de: want 1 to"},
		"title line break":       {def(`"de": "Beispiel"`, `"de": "Bei\nspiel"`), "title: de: contains"},
		"summary too long":       {def(`"de": "Ein Beispiel."`, `"de": "`+strings.Repeat("a", maxSummaryLength+1)+`"`), "summary: de: want 1 to"},
		"no techniques":          {def(`"techniques": ["T1021.004"],`+"\n  \"engage", `"techniques": [],`+"\n  \"engage"), "techniques: want"},
		"unknown technique":      {def(`"techniques": ["T1021.004"],`+"\n  \"engage", `"techniques": ["T9999"],`+"\n  \"engage"), "techniques: want"},
		"repeated technique":     {def(`"techniques": ["T1021.004"],`+"\n  \"engage", `"techniques": ["T1021.004", "T1021.004"],`+"\n  \"engage"), "techniques: want"},
		"no activities":          {def(`"engage_activities": ["EAC0005"]`, `"engage_activities": []`), "want 1 to 20 activities"},
		"strategic activity":     {def(`"engage_activities": ["EAC0005"]`, `"engage_activities": ["SAC0001"]`), "\"SAC0001\" is unknown"},
		"repeated activity":      {def(`"engage_activities": ["EAC0005"]`, `"engage_activities": ["EAC0005", "EAC0005"]`), "\"EAC0005\" is unknown or listed twice"},
		"too many activities":    {def(`"engage_activities": ["EAC0005"]`, `"engage_activities": ["EAC0001", "EAC0002", "EAC0003", "EAC0004", "EAC0005", "EAC0006", "EAC0007", "EAC0008", "EAC0009", "EAC0010", "EAC0011", "EAC0012", "EAC0013", "EAC0014", "EAC0015", "EAC0016", "EAC0017", "EAC0018", "EAC0019", "EAC0020", "EAC0021"]`), "want 1 to 20 activities"},

		// Honeytokens.
		"no honeytokens":           {noHoneytokens, "want 1 to 10 honeytokens"},
		"too many honeytokens":     {manyHoneytokens, "want 1 to 10 honeytokens"},
		"malformed honeytoken key": {def(`"key": "Link"`, `"key": "link"`), "the key \"link\" is malformed"},
		"repeated honeytoken key":  {def(`"key": "Link"`, `"key": "Gateway"`), "the key \"Gateway\" is malformed or used twice"},
		"honeytoken type":          {def(`"type": "web_url"`, `"type": "qr_code"`), "unknown type"},
		"honeytoken label":         {def(`"label": {"en": "Link", "de": "Link"}`, `"label": {"en": "Link"}`), "honeytoken Link: label"},
		"honeytoken label as name": {def(`"label": {"en": "Link", "de": "Link"}`, `"label": {"en": "Link", "de": "z.\u202fB. Link"}`), "honeytoken Link: label: de is not a valid name"},
		"honeytoken technique":     {def(`"techniques": []`, `"techniques": ["T1003.999"]`), "honeytoken Link: want up to"},
		"honeytoken severity info": {def(`"techniques": []}`, `"techniques": [], "severity": "info"}`), "honeytoken Link: the severity \"info\""},
		"honeytoken severity":      {def(`"techniques": []}`, `"techniques": [], "severity": "urgent"}`), "honeytoken Link: the severity \"urgent\""},

		// Persona.
		"persona kind url":        {def(`"kind": "host"`, `"kind": "url"`), "is not host, name or text"},
		"persona kind secret":     {def(`"kind": "host"`, `"kind": "secret"`), "is not host, name or text"},
		"persona kind unknown":    {def(`"kind": "host"`, `"kind": "port"`), "is not host, name or text"},
		"persona example missing": {def(`"example": "corp.example.com"`, `"example": ""`), "want an example"},
		"persona example invalid": {def(`"example": "corp.example.com"`, `"example": "Corp Example"`), "want an example"},
		"persona label":           {def(`"label": {"en": "Domain", "de": "Domain"}`, `"label": {"en": "Domain", "de": "`+strings.Repeat("a", maxLabelLength+1)+`"}`), "persona Domain: label"},
		"repeated persona key":    {def(`"key": "Company"`, `"key": "Domain"`), "the key \"Domain\" is malformed or used twice"},
		"too much persona":        {manyPersona, "want at most 10 values of the persona"},

		// The artifacts that the deception recommends.
		"unknown artifact":        {def(`"artifacts": ["config", "note"]`, `"artifacts": ["config", "memo"]`), "artifact memo: not in the catalog"},
		"malformed artifact id":   {def(`"artifacts": ["config", "note"]`, `"artifacts": ["config", "Note"]`), "artifacts: \"Note\" is malformed or listed twice"},
		"repeated artifact":       {def(`"artifacts": ["config", "note"]`, `"artifacts": ["config", "config"]`), "artifacts: \"config\" is malformed or listed twice"},
		"too many artifacts":      {manyArtifacts, "want at most 20 artifacts"},
		"too much to render":      {largeArtifacts, "its artifacts and guide can render"},
		"slot without honeytoken": {def(`{"key": "Gateway", "type": "dns", "label": {"en": "Gateway", "de": "Gateway"}, "techniques": ["T1021.004"]},`, `{"key": "Host", "type": "dns", "label": {"en": "Gateway", "de": "Gateway"}, "techniques": ["T1021.004"]},`), "artifact config: the slot Gateway has no honeytoken of that key"},
		"slot of another type":    {def(`{"key": "Gateway", "type": "dns"`, `{"key": "Gateway", "type": "web_url"`), "artifact config: the slot Gateway does not take honeytokens of the type web_url"},
		"persona of the artifact not in the deception": {
			def(`    {"key": "Company", "kind": "text", "label": {"en": "Company", "de": "Firma"}, "example": "Example Ltd"}`, `    {"key": "Firm", "kind": "text", "label": {"en": "Company", "de": "Firma"}, "example": "Example Ltd"}`),
			"artifact note: the persona Company of kind text is not a value of the deception",
		},
		"persona of the artifact of another kind": {
			def(`"key": "Company", "kind": "text", "label": {"en": "Company", "de": "Firma"}, "example": "Example Ltd"`, `"key": "Company", "kind": "name", "label": {"en": "Company", "de": "Firma"}, "example": "company"`),
			"artifact note: the persona Company of kind text is not a value of the deception",
		},
		"identifier as marker": {file(configTmpl, "# SAMPLE\nHost {{.Honeytokens.Gateway.Host}}\nPassword {{.Secrets.Password}}\n"), "artifact config: the template contains \"sample\""},

		// Values that nothing references.
		"unreferenced honeytoken": {noteWithoutLink, "no template references .Honeytokens.Link.URL"},
		"unreferenced persona":    {noteWithoutDomain, "no template references .Persona.Domain"},

		// Guides.
		"guide language missing": {def(`"guide": {"en": "guide.en.md.tmpl", "de": "guide.de.md.tmpl"}`, `"guide": {"en": "guide.en.md.tmpl"}`), "guide: want a template for each"},
		"guide language unknown": {def(`"guide": {"en": "guide.en.md.tmpl", "de": "guide.de.md.tmpl"}`, `"guide": {"en": "guide.en.md.tmpl", "fr": "guide.de.md.tmpl"}`), "guide: \"fr\" is not a language"},
		"guide template":         {file(guideDeTmpl, "{{template \"x\"}}"), "guide de:"},
		"guide undeclared value": {file(guideDeTmpl, "{{.Secrets.Token}}"), "guide de:"},
		"guide with a secret":    {file(guideDeTmpl, "{{.Secrets.Password}}"), "guide de:"},
	} {
		fsys := validFiles()
		c.change(fsys)
		if _, err := Load(fsys); !errors.Is(err, ErrInvalidDeception) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Load() error = %v, want ErrInvalidDeception with %q", name, err, c.want)
		}
	}
}

// A value that only the guide references is used, for example the URL of an
// image that the administrator embeds in a document of their own, and so is a
// deception without artifacts.
func TestLoad_AcceptsValuesThatOnlyTheGuideReferences(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	edit(t, sampleJSON, `"artifacts": ["config", "note"]`, `"artifacts": ["config"]`)(fsys)
	fsys[guideEnTmpl] = mapFile("{{.Honeytokens.Gateway.Host}} {{.Honeytokens.Link.URL}} {{.Persona.Company}} {{.Persona.Domain}}\n")
	if _, err := Load(fsys); err != nil {
		t.Errorf("Load() error = %v", err)
	}

	bare := validFiles()
	edit(t, sampleJSON, `"artifacts": ["config", "note"]`, `"artifacts": []`)(bare)
	bare[guideEnTmpl] = mapFile("{{.Honeytokens.Gateway.Host}} {{.Honeytokens.Link.URL}} {{.Persona.Company}} {{.Persona.Domain}}\n")
	if _, err := Load(bare); err != nil {
		t.Errorf("Load(deception without artifacts) error = %v", err)
	}
}

// An artifact binds the honeytoken of its key, and an optional slot may stay
// empty: the deception then lacks the honeytoken.
func TestLoad_AcceptsAnOptionalSlotWithoutHoneytoken(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	edit(t, sampleJSON, `,
    {"key": "Link", "type": "web_url", "label": {"en": "Link", "de": "Link"}, "techniques": []}`, ``)(fsys)
	c, err := Load(fsys)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if d, _ := c.Lookup("sample"); len(d.Honeytokens) != 1 || len(d.Artifacts) != 2 {
		t.Errorf("Lookup(sample) = %+v, want one honeytoken and both artifacts", d)
	}
}

// Two artifacts of a deception must not share a file name, also in another
// case: they are the same file on Windows and macOS.
func TestLoad_RejectsArtifactsWithTheSameFileName(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	edit(t, noteJSON, `"file_name": "Read me.txt"`, `"file_name": "CONFIG"`)(fsys)
	if _, err := Load(fsys); err == nil || !strings.Contains(err.Error(), `artifact note: the file name "CONFIG" is also that of artifact config`) {
		t.Errorf("Load() error = %v, want the file name used twice", err)
	}
}

// A slot takes the types it declares: the note takes a web_url and a
// web_image, which both give a URL.
func TestLoad_BindsASlotToEveryTypeItAccepts(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	edit(t, sampleJSON, `"key": "Link", "type": "web_url"`, `"key": "Link", "type": "web_image"`)(fsys)
	if _, err := Load(fsys); err != nil {
		t.Errorf("Load() error = %v", err)
	}
}

// Guides are read by administrators and may name what the deception is.
func TestLoad_AllowsMarkersInGuides(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	fsys[guideEnTmpl] = mapFile("This deception of Nyktus creates a honeytoken, a decoy for the sample {{.Honeytokens.Gateway.Host}} of {{.Persona.Company}}.\n")
	if _, err := Load(fsys); err != nil {
		t.Errorf("Load() error = %v", err)
	}
}

func TestLoad_RejectsAnInvalidCatalog(t *testing.T) {
	t.Parallel()

	if _, err := Load(fstest.MapFS{}); err == nil {
		t.Error("Load(empty) error = nil")
	}
	for name, c := range map[string]struct {
		change func(fstest.MapFS)
		want   error
		in     string
	}{
		"file beside the deceptions": {file("deceptions/README.md", "x"), ErrInvalidDeception, "deceptions/README.md is not a directory"},
		"file beside the artifacts":  {file("artifacts/README.md", "x"), ErrInvalidArtifact, "artifacts/README.md is not a directory"},
		"no deceptions":              {emptyDir(deceptionDir), nil, "no entries in deceptions"},
		"no artifacts":               {emptyDir("artifacts/"), nil, "no entries in artifacts"},
		"missing deceptions":         {missingDir(deceptionDir), nil, "load catalog"},
		"missing artifacts":          {missingDir("artifacts/"), nil, "load catalog"},
	} {
		fsys := validFiles()
		c.change(fsys)
		_, err := Load(fsys)
		if err == nil || !strings.Contains(err.Error(), c.in) || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: Load() error = %v, want %v with %q", name, err, c.want, c.in)
		}
	}
}

// emptyDir leaves the directory dir without entries.
func emptyDir(dir string) func(fstest.MapFS) {
	return func(fsys fstest.MapFS) {
		missingDir(dir)(fsys)
		fsys[strings.TrimSuffix(dir, "/")] = &fstest.MapFile{Mode: fs.ModeDir}
	}
}

// missingDir removes the directory dir.
func missingDir(dir string) func(fstest.MapFS) {
	return func(fsys fstest.MapFS) {
		for n := range fsys {
			if strings.HasPrefix(n, dir) {
				delete(fsys, n)
			}
		}
	}
}

func moveDir(fsys fstest.MapFS, from, to string) {
	for name, f := range fsys {
		if rest, ok := strings.CutPrefix(name, deceptionDir+from+"/"); ok {
			delete(fsys, name)
			fsys[deceptionDir+to+"/"+rest] = f
		}
	}
	if s := string(fsys[deceptionDir+to+"/deception.json"].Data); s != "" {
		fsys[deceptionDir+to+"/deception.json"] = mapFile(strings.Replace(s, `"id": "`+from+`"`, `"id": "`+to+`"`, 1))
	}
}

func appendTo(fsys fstest.MapFS, name, s string) {
	fsys[name] = &fstest.MapFile{Data: append(append([]byte{}, fsys[name].Data...), s...)}
}

// noHoneytokens removes the honeytokens and every reference to them.
func noHoneytokens(fsys fstest.MapFS) {
	s := string(fsys[sampleJSON].Data)
	start := strings.Index(s, `"honeytokens": [`)
	end := strings.Index(s, `"persona": [`)
	fsys[sampleJSON] = mapFile(s[:start] + `"honeytokens": [],` + "\n  " + s[end:])
	fsys[sampleJSON] = mapFile(strings.Replace(string(fsys[sampleJSON].Data), `"artifacts": ["config", "note"]`, `"artifacts": []`, 1))
	fsys[guideEnTmpl] = mapFile("guide {{.Persona.Company}} {{.Persona.Domain}}\n")
	fsys[guideDeTmpl] = mapFile("Anleitung\n")
}

func manyHoneytokens(fsys fstest.MapFS) {
	var extra strings.Builder
	for i := range maxHoneytokens - 1 {
		extra.WriteString(`{"key": "Extra` + string(rune('A'+i)) + `", "type": "dns", "label": {"en": "x", "de": "x"}, "techniques": []},`)
	}
	s := strings.Replace(string(fsys[sampleJSON].Data), `"honeytokens": [`, `"honeytokens": [`+extra.String(), 1)
	fsys[sampleJSON] = mapFile(s)
}

func manyPersona(fsys fstest.MapFS) {
	var extra strings.Builder
	for i := range maxPersona - 1 {
		extra.WriteString(`{"key": "Extra` + string(rune('A'+i)) + `", "kind": "name", "label": {"en": "x", "de": "x"}, "example": "x"},`)
	}
	s := strings.Replace(string(fsys[sampleJSON].Data), `"persona": [`, `"persona": [`+extra.String(), 1)
	fsys[sampleJSON] = mapFile(s)
}

// noteWithoutLink drops the slot from the note, which leaves the deception
// with a honeytoken that nobody places.
func noteWithoutLink(fsys fstest.MapFS) {
	s := strings.Replace(string(fsys[noteJSON].Data), `"slots": [{"key": "Link", "accepts": ["web_url", "web_image"], "optional": true}]`, `"slots": []`, 1)
	fsys[noteJSON] = mapFile(s)
	fsys[noteTmpl] = mapFile("{{.Persona.Company}} on {{.Persona.Domain}}\n")
}

// noteWithoutDomain drops the domain from the note, which leaves the deception
// asking for a value that nobody uses.
func noteWithoutDomain(fsys fstest.MapFS) {
	s := string(fsys[noteJSON].Data)
	s = strings.Replace(s, `    {"key": "Domain", "kind": "host", "label": {"en": "Domain", "de": "Domain"}, "example": "corp.example.com"},
`, "", 1)
	fsys[noteJSON] = mapFile(s)
	fsys[noteTmpl] = mapFile("{{.Persona.Company}}{{if .Honeytokens.Link.URL}}: {{.Honeytokens.Link.URL}}{{end}}\n")
}

// addPlainArtifacts adds n artifacts of the format text without values, each
// with a template of size bytes, and lets the deception sample recommend them
// instead of its own. The ids are plain-a, plain-b, ...
func addPlainArtifacts(fsys fstest.MapFS, n, size int) {
	ids := make([]string, n)
	for i := range n {
		id := "plain-" + string(rune('a'+i))
		ids[i] = `"` + id + `"`
		fsys["artifacts/"+id+"/artifact.json"] = mapFile(`{
  "schema_version": 1, "id": "` + id + `", "category": "data",
  "title": {"en": "Plain", "de": "Schlicht"}, "summary": {"en": "Plain.", "de": "Schlicht."},
  "slots": [], "persona": [], "secrets": [],
  "file_name": "` + id + `", "format": "text", "line_endings": "lf", "template": "plain.tmpl"
}`)
		fsys["artifacts/"+id+"/plain.tmpl"] = mapFile(strings.Repeat("x", size))
	}
	s := strings.Replace(string(fsys[sampleJSON].Data), `"artifacts": ["config", "note"]`, `"artifacts": [`+strings.Join(ids, ", ")+`]`, 1)
	fsys[sampleJSON] = mapFile(s)
	fsys[guideEnTmpl] = mapFile("{{.Honeytokens.Gateway.Host}} {{.Honeytokens.Link.URL}} {{.Persona.Company}} {{.Persona.Domain}}\n")
}

func manyArtifacts(fsys fstest.MapFS) {
	addPlainArtifacts(fsys, maxArtifacts+1, 1)
}

// largeArtifacts adds artifacts that together can render more than
// MaxRenderedBytes, each within the limit of a file.
func largeArtifacts(fsys fstest.MapFS) {
	n := maxArtifacts - 2
	addPlainArtifacts(fsys, n, MaxRenderedBytes/n+1024)
}

// The persona belongs to the scenario and only grows, so a key of the persona has
// one kind in the whole catalog: otherwise a scenario could hold a value that an
// entry that joins it later cannot accept, and never change it.
func TestLoad_RejectsAKeyOfThePersonaOfTwoKinds(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	fsys["artifacts/orphan/artifact.json"] = mapFile(`{
  "schema_version": 1,
  "id": "orphan",
  "category": "data",
  "title": {"en": "Orphan", "de": "Waise"},
  "summary": {"en": "An orphan.", "de": "Eine Waise."},
  "slots": [],
  "persona": [
    {"key": "Company", "kind": "host", "label": {"en": "Company", "de": "Firma"}, "example": "example.com"}
  ],
  "secrets": [],
  "file_name": "orphan.txt",
  "format": "text",
  "line_endings": "lf",
  "template": "orphan.txt.tmpl"
}`)
	fsys["artifacts/orphan/orphan.txt.tmpl"] = mapFile("{{.Persona.Company}}\n")
	_, err := Load(fsys)
	if !errors.Is(err, ErrInvalidDeception) || !strings.Contains(err.Error(), "Company is text in note and host in orphan") {
		t.Errorf("Load() error = %v, want the key Company named with its two kinds", err)
	}
}
