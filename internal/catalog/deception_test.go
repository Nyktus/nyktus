// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"nyktus.org/nyktus/internal/honeytoken"
)

const validDefinition = `{
  "schema_version": 1,
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
  "secrets": [{"key": "Password", "length": 16}],
  "artifacts": [
    {"key": "config", "file_name": "config", "format": "config", "line_endings": "lf", "template": "config.tmpl"},
    {"key": "note", "file_name": "Read me.txt", "format": "text", "line_endings": "crlf", "template": "note.txt.tmpl"}
  ],
  "guide": {"en": "guide.en.md.tmpl", "de": "guide.de.md.tmpl"}
}`

// validFiles returns a catalog with two valid deceptions, sample and second,
// whose templates reference every value. Tests break sample.
func validFiles() fstest.MapFS {
	fsys := fstest.MapFS{}
	for _, id := range []string{"sample", "second"} {
		fsys[id+"/deception.json"] = &fstest.MapFile{Data: []byte(strings.Replace(validDefinition, `"id": "sample"`, `"id": "`+id+`"`, 1))}
		fsys[id+"/config.tmpl"] = &fstest.MapFile{Data: []byte("Host {{.Honeytokens.Gateway.Host}}\nPassword {{.Secrets.Password}}\n")}
		fsys[id+"/note.txt.tmpl"] = &fstest.MapFile{Data: []byte("{{.Persona.Company}}: {{.Honeytokens.Link.URL}} on {{.Persona.Domain}}\n")}
		fsys[id+"/guide.en.md.tmpl"] = &fstest.MapFile{Data: []byte("Place the honeytoken {{.Honeytokens.Gateway.Host}} for {{.Persona.Company}}.\n")}
		fsys[id+"/guide.de.md.tmpl"] = &fstest.MapFile{Data: []byte("Legen Sie den Honeytoken {{.Honeytokens.Gateway.Host}} ab.\n")}
	}
	return fsys
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
		d.Honeytokens[1].Type != honeytoken.TypeWebURL || len(d.Persona) != 2 || d.Secrets[0].Length != 16 ||
		len(d.Artifacts) != 2 || d.Artifacts[1].FileName != "Read me.txt" || d.Guide["de"] == nil {
		t.Errorf("Lookup(sample) = %+v, %v", d, ok)
	}
	if _, ok := c.Lookup("third"); ok {
		t.Error("Lookup(third) found a deception")
	}

	out, err := d.Artifacts[0].Render(map[string]string{
		"Honeytokens.Gateway.Host": "abc.d.example.net", "Secrets.Password": "aaaabbbbccccdddd",
	})
	if err != nil || string(out) != "Host abc.d.example.net\nPassword aaaabbbbccccdddd\n" {
		t.Errorf("Render(config) = %q, %v", out, err)
	}
	// The note declares CRLF.
	out, err = d.Artifacts[1].Render(map[string]string{
		"Persona.Company": "A", "Honeytokens.Link.URL": "https://t.example.net/x", "Persona.Domain": "corp.example.com",
	})
	if err != nil || string(out) != "A: https://t.example.net/x on corp.example.com\r\n" {
		t.Errorf("Render(note) = %q, %v", out, err)
	}
	// Guides are Markdown.
	out, err = d.Guide["en"].Render(map[string]string{"Honeytokens.Gateway.Host": "abc.d.example.net", "Persona.Company": "A<b>"})
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
		"Secrets.Password":         KindSecret,
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

	def := func(old, replacement string) func(fstest.MapFS) {
		return func(fsys fstest.MapFS) {
			s := string(fsys["sample/deception.json"].Data)
			if !strings.Contains(s, old) {
				t.Fatalf("the definition does not contain %q", old)
			}
			fsys["sample/deception.json"] = &fstest.MapFile{Data: []byte(strings.Replace(s, old, replacement, 1))}
		}
	}
	file := func(name, content string) func(fstest.MapFS) {
		return func(fsys fstest.MapFS) {
			if content == "" {
				delete(fsys, name)
				return
			}
			fsys[name] = &fstest.MapFile{Data: []byte(content)}
		}
	}

	for name, c := range map[string]struct {
		change func(fstest.MapFS)
		// want is part of the error, so that a case cannot pass because
		// another rule rejects it.
		want string
	}{
		// The directory and its files.
		"malformed directory":    {func(fsys fstest.MapFS) { moveDir(fsys, "sample", "Sample") }, "not a valid identifier"},
		"long directory":         {func(fsys fstest.MapFS) { moveDir(fsys, "sample", strings.Repeat("a", 65)) }, "not a valid identifier"},
		"missing definition":     {file("sample/deception.json", ""), "deception.json is missing"},
		"unreferenced file":      {file("sample/extra.tmpl", "x"), "extra.tmpl is not referenced"},
		"file of another name":   {file("sample/notes.txt", "x"), "notes.txt is not a template"},
		"subdirectory":           {file("sample/x.tmpl/config.tmpl", "x"), "x.tmpl is not a template"},
		"file too large":         {file("sample/note.txt.tmpl", strings.Repeat("a", maxFileBytes+1)), "note.txt.tmpl is larger than"},
		"missing artifact file":  {file("sample/note.txt.tmpl", ""), "the template note.txt.tmpl is missing"},
		"missing guide file":     {file("sample/guide.de.md.tmpl", ""), "the template guide.de.md.tmpl is missing"},
		"unknown field":          {def(`"schema_version": 1,`, `"schema_version": 1, "author": "x",`), "unknown field"},
		"unknown nested field":   {def(`"length": 16}`, `"length": 16, "charset": "x"}`), "unknown field"},
		"trailing data":          {func(fsys fstest.MapFS) { appendTo(fsys, "sample/deception.json", " {}") }, "unexpected data"},
		"malformed JSON":         {def(`"schema_version": 1,`, `"schema_version": 1`), "deception.json:"},
		"schema version":         {def(`"schema_version": 1`, `"schema_version": 2`), "schema version 2"},
		"identifier":             {def(`"id": "sample"`, `"id": "other"`), "differs from the name"},
		"category":               {def(`"category": "network"`, `"category": "cloud"`), "unknown category"},
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

		// Persona and secrets.
		"persona kind url":        {def(`"kind": "host"`, `"kind": "url"`), "is not host, name or text"},
		"persona kind secret":     {def(`"kind": "host"`, `"kind": "secret"`), "is not host, name or text"},
		"persona kind unknown":    {def(`"kind": "host"`, `"kind": "port"`), "is not host, name or text"},
		"persona example missing": {def(`"example": "corp.example.com"`, `"example": ""`), "want an example"},
		"persona example invalid": {def(`"example": "corp.example.com"`, `"example": "Corp Example"`), "want an example"},
		"persona label":           {def(`"label": {"en": "Domain", "de": "Domain"}`, `"label": {"en": "Domain", "de": "`+strings.Repeat("a", maxLabelLength+1)+`"}`), "persona Domain: label"},
		"repeated persona key":    {def(`"key": "Company"`, `"key": "Domain"`), "the key \"Domain\" is malformed or used twice"},
		"malformed secret key":    {def(`"key": "Password"`, `"key": "Pass-word"`), "the key \"Pass-word\" is malformed"},
		"secret too short":        {def(`"length": 16`, `"length": 7`), "want a length"},
		"secret too long":         {def(`"length": 16`, `"length": 65`), "want a length"},

		// Artifacts.
		"malformed artifact key":   {def(`"key": "note"`, `"key": "Note"`), "artifact \"Note\": the key"},
		"repeated artifact key":    {def(`"key": "note"`, `"key": "config"`), "artifact \"config\": the key"},
		"file name with separator": {def(`"file_name": "Read me.txt"`, `"file_name": "docs/Read me.txt"`), "the file name"},
		"file name with backslash": {def(`"file_name": "Read me.txt"`, `"file_name": "docs\\Read me.txt"`), "the file name"},
		"hidden file name":         {def(`"file_name": "Read me.txt"`, `"file_name": ".netrc"`), "the file name"},
		"file name trailing dot":   {def(`"file_name": "Read me.txt"`, `"file_name": "Read me."`), "the file name"},
		"file name in other case":  {def(`"file_name": "Read me.txt"`, `"file_name": "CONFIG"`), "the file name"},
		"artifact format":          {def(`"format": "text"`, `"format": "yaml"`), "artifact note: unknown format"},
		"line endings":             {def(`"line_endings": "crlf"`, `"line_endings": "cr"`), "the line endings \"cr\" are not lf or crlf"},
		"line endings missing":     {def(`, "line_endings": "crlf"`, ``), "the line endings \"\" are not lf or crlf"},
		"artifact template name":   {def(`"template": "note.txt.tmpl"`, `"template": "../note.txt.tmpl"`), "is not the name of a template"},
		"artifact template":        {file("sample/note.txt.tmpl", "{{range .Persona.Company}}x{{end}}"), "only text, values"},
		"free text in config":      {file("sample/config.tmpl", "Host {{.Persona.Company}}\n"), "free text"},
		"undeclared value":         {file("sample/config.tmpl", "Host {{.Honeytokens.Link.Host}}\n"), "unknown value"},
		"marker":                   {file("sample/note.txt.tmpl", "Nyktus\n"), "contains \"nyktus\""},
		"marker in a branch":       {file("sample/note.txt.tmpl", "{{if .Persona.Company}}x{{else}}a HoneyToken{{end}}\n"), "contains \"honeytoken\""},
		"identifier as marker":     {file("sample/config.tmpl", "# SAMPLE\n"), "contains \"sample\""},
		"attribution as marker":    {file("sample/note.txt.tmpl", "Generated by a tool\n"), "contains \"generated by\""},
		"license as marker":        {file("sample/note.txt.tmpl", "Licensed CC-BY-SA 4.0\n"), "contains \"cc-by\""},
		"unreferenced honeytoken":  {file("sample/note.txt.tmpl", "{{.Persona.Company}} on {{.Persona.Domain}}\n"), "no template references .Honeytokens.Link.URL"},
		"unreferenced persona":     {file("sample/note.txt.tmpl", "{{.Persona.Company}}: {{.Honeytokens.Link.URL}}\n"), "no template references .Persona.Domain"},
		"unreferenced secret":      {file("sample/config.tmpl", "Host {{.Honeytokens.Gateway.Host}}\n"), "no template references .Secrets.Password"},
		"too many artifacts":       {manyArtifacts, "want at most 20 artifacts"},
		"too much to render":       {largeArtifacts, "its artifacts and guide can render"},
		"file too large to render": {file("sample/note.txt.tmpl", strings.Repeat("{{.Persona.Company}}\n", 250)+"{{.Honeytokens.Link.URL}}{{.Persona.Domain}}"), "artifact note can render"},

		// Guides.
		"guide language missing": {def(`"guide": {"en": "guide.en.md.tmpl", "de": "guide.de.md.tmpl"}`, `"guide": {"en": "guide.en.md.tmpl"}`), "guide: want a template for each"},
		"guide language unknown": {def(`"guide": {"en": "guide.en.md.tmpl", "de": "guide.de.md.tmpl"}`, `"guide": {"en": "guide.en.md.tmpl", "fr": "guide.de.md.tmpl"}`), "guide: \"fr\" is not a language"},
		"guide template":         {file("sample/guide.de.md.tmpl", "{{template \"x\"}}"), "guide de:"},
		"guide undeclared value": {file("sample/guide.de.md.tmpl", "{{.Secrets.Token}}"), "guide de:"},
	} {
		fsys := validFiles()
		c.change(fsys)
		if _, err := Load(fsys); !errors.Is(err, ErrInvalidDeception) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Load() error = %v, want ErrInvalidDeception with %q", name, err, c.want)
		}
	}
}

// A value that only the guide references is used, for example the URL of an
// image that the administrator embeds in a document of their own.
func TestLoad_AcceptsValuesThatOnlyTheGuideReferences(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	fsys["sample/note.txt.tmpl"] = &fstest.MapFile{Data: []byte("{{.Honeytokens.Link.URL}} on {{.Persona.Domain}}\n")}
	if _, err := Load(fsys); err != nil {
		t.Errorf("Load() error = %v", err)
	}
}

// Guides are read by administrators and may name what the deception is.
func TestLoad_AllowsMarkersInGuides(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	fsys["sample/guide.en.md.tmpl"] = &fstest.MapFile{Data: []byte("This deception of Nyktus creates a honeytoken, a decoy for the sample.\n")}
	if _, err := Load(fsys); err != nil {
		t.Errorf("Load() error = %v", err)
	}
}

func TestLoad_RejectsAnInvalidCatalog(t *testing.T) {
	t.Parallel()

	if _, err := Load(fstest.MapFS{}); err == nil {
		t.Error("Load(empty) error = nil")
	}
	fsys := validFiles()
	fsys["README.md"] = &fstest.MapFile{Data: []byte("x")}
	if _, err := Load(fsys); !errors.Is(err, ErrInvalidDeception) || !strings.Contains(err.Error(), "README.md is not the directory") {
		t.Errorf("Load(file beside the deceptions) error = %v, want ErrInvalidDeception for README.md", err)
	}
}

func moveDir(fsys fstest.MapFS, from, to string) {
	for name, f := range fsys {
		if rest, ok := strings.CutPrefix(name, from+"/"); ok {
			delete(fsys, name)
			fsys[to+"/"+rest] = f
		}
	}
	if s := string(fsys[to+"/deception.json"].Data); s != "" {
		fsys[to+"/deception.json"] = &fstest.MapFile{Data: []byte(strings.Replace(s, `"id": "`+from+`"`, `"id": "`+to+`"`, 1))}
	}
}

func appendTo(fsys fstest.MapFS, name, s string) {
	fsys[name] = &fstest.MapFile{Data: append(append([]byte{}, fsys[name].Data...), s...)}
}

// noHoneytokens removes the honeytokens and every reference to them.
func noHoneytokens(fsys fstest.MapFS) {
	s := string(fsys["sample/deception.json"].Data)
	start := strings.Index(s, `"honeytokens": [`)
	end := strings.Index(s, `"persona": [`)
	fsys["sample/deception.json"] = &fstest.MapFile{Data: []byte(s[:start] + `"honeytokens": [],` + "\n  " + s[end:])}
	fsys["sample/config.tmpl"] = &fstest.MapFile{Data: []byte("Password {{.Secrets.Password}}\n")}
	fsys["sample/note.txt.tmpl"] = &fstest.MapFile{Data: []byte("{{.Persona.Company}}\n")}
	fsys["sample/guide.en.md.tmpl"] = &fstest.MapFile{Data: []byte("guide\n")}
	fsys["sample/guide.de.md.tmpl"] = &fstest.MapFile{Data: []byte("Anleitung\n")}
}

func manyHoneytokens(fsys fstest.MapFS) {
	var extra strings.Builder
	for i := range maxHoneytokens - 1 {
		extra.WriteString(`{"key": "Extra` + string(rune('A'+i)) + `", "type": "dns", "label": {"en": "x", "de": "x"}, "techniques": []},`)
	}
	s := strings.Replace(string(fsys["sample/deception.json"].Data), `"honeytokens": [`, `"honeytokens": [`+extra.String(), 1)
	fsys["sample/deception.json"] = &fstest.MapFile{Data: []byte(s)}
}

func manyArtifacts(fsys fstest.MapFS) {
	var extra strings.Builder
	for i := range maxArtifacts - 1 {
		c := string(rune('a' + i))
		extra.WriteString(`{"key": "extra-` + c + `", "file_name": "extra-` + c + `", "format": "text", "line_endings": "lf", "template": "extra-` + c + `.tmpl"},`)
		fsys["sample/extra-"+c+".tmpl"] = &fstest.MapFile{Data: []byte("x")}
	}
	s := strings.Replace(string(fsys["sample/deception.json"].Data), `"artifacts": [`, `"artifacts": [`+extra.String(), 1)
	fsys["sample/deception.json"] = &fstest.MapFile{Data: []byte(s)}
}

// largeArtifacts adds artifacts that together can render more than
// MaxRenderedBytes, each within the limit of a file.
func largeArtifacts(fsys fstest.MapFS) {
	var extra strings.Builder
	size := MaxRenderedBytes/(maxArtifacts-2) + 1024
	for i := range maxArtifacts - 2 {
		c := string(rune('a' + i))
		extra.WriteString(`{"key": "large-` + c + `", "file_name": "large-` + c + `", "format": "text", "line_endings": "lf", "template": "large-` + c + `.tmpl"},`)
		fsys["sample/large-"+c+".tmpl"] = &fstest.MapFile{Data: []byte(strings.Repeat("x", size))}
	}
	s := strings.Replace(string(fsys["sample/deception.json"].Data), `"artifacts": [`, `"artifacts": [`+extra.String(), 1)
	fsys["sample/deception.json"] = &fstest.MapFile{Data: []byte(s)}
}
