// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

const (
	placingEnTmpl = "artifacts/note/placing.en.md.tmpl"
	placingDeTmpl = "artifacts/note/placing.de.md.tmpl"
)

// Every rule of an artifact has a case that breaks only that rule, in the
// artifacts config and note, and leaves the catalog otherwise valid.
func TestLoad_RejectsInvalidArtifacts(t *testing.T) {
	t.Parallel()

	cfg := func(old, replacement string) func(fstest.MapFS) { return edit(t, configJSON, old, replacement) }
	note := func(old, replacement string) func(fstest.MapFS) { return edit(t, noteJSON, old, replacement) }
	placing := `"placing": {"en": "placing.en.md.tmpl", "de": "placing.de.md.tmpl"}`
	withPlacing := func(fsys fstest.MapFS) {
		note(`"template": "note.txt.tmpl"`, `"template": "note.txt.tmpl", `+placing)(fsys)
		fsys[placingEnTmpl] = mapFile("Put it on {{.Persona.Domain}}.\n")
		fsys[placingDeTmpl] = mapFile("Legen Sie es auf {{.Persona.Domain}}.\n")
	}
	// optionalLink replaces the template of the note.
	optionalLink := func(tmpl string) func(fstest.MapFS) {
		return file(noteTmpl, tmpl)
	}

	for name, c := range map[string]struct {
		change func(fstest.MapFS)
		// want is part of the error, so that a case cannot pass because
		// another rule rejects it.
		want string
	}{
		// The directory and its files.
		"malformed directory":  {func(fsys fstest.MapFS) { moveArtifact(fsys, "config", "Config") }, "not a valid identifier"},
		"long directory":       {func(fsys fstest.MapFS) { moveArtifact(fsys, "config", strings.Repeat("a", 65)) }, "not a valid identifier"},
		"missing definition":   {file(configJSON, ""), "artifact.json is missing"},
		"unreferenced file":    {file("artifacts/config/extra.tmpl", "x"), "extra.tmpl is not referenced"},
		"file of another name": {file("artifacts/config/notes.txt", "x"), "notes.txt is not a template"},
		"subdirectory":         {file("artifacts/config/x.tmpl/config.tmpl", "x"), "x.tmpl is not a template"},
		"file too large":       {file(configTmpl, strings.Repeat("a", maxFileBytes+1)), "config.tmpl is larger than"},
		"missing template":     {file(configTmpl, ""), "the template config.tmpl is missing"},
		"unknown field":        {cfg(`"schema_version": 1,`, `"schema_version": 1, "author": "x",`), "unknown field"},
		"unknown member":       {cfg(`"template": "config.tmpl"`, `"template": "config.tmpl", "techniques": ["T1021.004"]`), "unknown field"},
		"unknown nested field": {cfg(`"length": 16}`, `"length": 16, "charset": "x"}`), "unknown field"},
		"trailing data":        {func(fsys fstest.MapFS) { appendTo(fsys, configJSON, " {}") }, "unexpected data"},
		"malformed JSON":       {cfg(`"schema_version": 1,`, `"schema_version": 1`), "artifact.json:"},
		"schema version":       {cfg(`"schema_version": 1`, `"schema_version": 2`), "schema version 2"},
		"identifier":           {cfg(`"id": "config"`, `"id": "other"`), "differs from the name"},
		"category":             {cfg(`"category": "network"`, `"category": "cloud"`), "unknown category"},
		"title language":       {cfg(`"title": {"en": "Config", "de": "Einstellung"}`, `"title": {"en": "Config"}`), "title: want a text in each"},
		"title too long":       {cfg(`"de": "Einstellung"`, `"de": "`+strings.Repeat("a", maxTitleLength+1)+`"`), "title: de: want 1 to"},
		"summary too long":     {cfg(`"de": "Eine Einstellung."`, `"de": "`+strings.Repeat("a", maxSummaryLength+1)+`"`), "summary: de: want 1 to"},
		"activities":           {cfg(`"slots":`, `"engage_activities": ["EAC0011"], "slots":`), "unknown field"},

		// Slots.
		"too many slots":       {manySlots, "want at most 10 slots"},
		"malformed slot key":   {cfg(`"key": "Gateway"`, `"key": "gateway"`), "the key \"gateway\" is malformed"},
		"repeated slot key":    {note(`"slots": [{"key": "Link", "accepts": ["web_url", "web_image"], "optional": true}]`, `"slots": [{"key": "Link", "accepts": ["web_url"], "optional": true}, {"key": "Link", "accepts": ["web_url"], "optional": true}]`), "the key \"Link\" is malformed or used twice"},
		"slot accepts nothing": {cfg(`"accepts": ["dns"]`, `"accepts": []`), "slot Gateway: accepts no type"},
		"slot type":            {cfg(`"accepts": ["dns"]`, `"accepts": ["qr_code"]`), "the type \"qr_code\" is unknown"},
		"slot type repeated":   {note(`"accepts": ["web_url", "web_image"]`, `"accepts": ["web_url", "web_url"]`), "the type \"web_url\" is unknown or listed twice"},
		"slot host and URL":    {cfg(`"accepts": ["dns"]`, `"accepts": ["dns", "web_url"]`), "one slot cannot take both"},
		"slot URL and host":    {note(`"accepts": ["web_url", "web_image"]`, `"accepts": ["web_url", "dns"]`), "one slot cannot take both"},

		// Persona and secrets.
		"persona kind url":        {note(`"kind": "host"`, `"kind": "url"`), "is not host, name or text"},
		"persona kind secret":     {note(`"kind": "host"`, `"kind": "secret"`), "is not host, name or text"},
		"persona example missing": {note(`"example": "corp.example.com"`, `"example": ""`), "want an example"},
		"persona example invalid": {note(`"example": "corp.example.com"`, `"example": "Corp Example"`), "want an example"},
		"repeated persona key":    {note(`"key": "Company"`, `"key": "Domain"`), "the key \"Domain\" is malformed or used twice"},
		"malformed secret key":    {cfg(`"key": "Password"`, `"key": "Pass-word"`), "the key \"Pass-word\" is malformed"},
		"repeated secret key":     {cfg(`[{"key": "Password", "length": 16}]`, `[{"key": "Password", "length": 16}, {"key": "Password", "length": 16}]`), "the key \"Password\" is malformed or used twice"},
		"secret too short":        {cfg(`"length": 16`, `"length": 7`), "want a length"},
		"secret too long":         {cfg(`"length": 16`, `"length": 65`), "want a length"},
		"too many secrets":        {manySecrets, "want at most 10 secrets"},

		// The file.
		"file name with separator": {note(`"file_name": "Read me.txt"`, `"file_name": "docs/Read me.txt"`), "the file name"},
		"file name with backslash": {note(`"file_name": "Read me.txt"`, `"file_name": "docs\\Read me.txt"`), "the file name"},
		"hidden file name":         {note(`"file_name": "Read me.txt"`, `"file_name": ".netrc"`), "the file name"},
		"file name trailing dot":   {note(`"file_name": "Read me.txt"`, `"file_name": "Read me."`), "the file name"},
		"format":                   {note(`"format": "text"`, `"format": "yaml"`), "unknown format"},
		"line endings":             {note(`"line_endings": "crlf"`, `"line_endings": "cr"`), "the line endings \"cr\" are not lf or crlf"},
		"line endings missing":     {note(`"line_endings": "crlf",`, ``), "the line endings \"\" are not lf or crlf"},
		"template name":            {note(`"template": "note.txt.tmpl"`, `"template": "../note.txt.tmpl"`), "is not the name of a template"},
		"template construct":       {file(noteTmpl, "{{range .Persona.Company}}x{{end}}"), "only text, values"},
		"free text in config":      {note(`"format": "text"`, `"format": "config"`), "free text"},
		"undeclared value":         {file(configTmpl, "Host {{.Honeytokens.Link.Host}}\n"), "unknown value"},
		"too large to render":      {optionalLink(strings.Repeat("{{.Persona.Company}}\n", 250) + "{{if .Honeytokens.Link.URL}}{{.Honeytokens.Link.URL}}{{end}}{{.Persona.Domain}}"), "it can render"},

		// Markers of the template, including the identifier of the artifact.
		"marker":                {optionalLink("Nyktus {{.Persona.Company}} {{.Persona.Domain}}{{if .Honeytokens.Link.URL}}{{.Honeytokens.Link.URL}}{{end}}\n"), "contains \"nyktus\""},
		"marker in a branch":    {optionalLink("{{if .Persona.Company}}x{{else}}a HoneyToken{{end}}{{.Persona.Domain}}{{if .Honeytokens.Link.URL}}{{.Honeytokens.Link.URL}}{{end}}\n"), "contains \"honeytoken\""},
		"identifier as marker":  {file(configTmpl, "# CONFIG\nHost {{.Honeytokens.Gateway.Host}}\nPassword {{.Secrets.Password}}\n"), "the template contains \"config\""},
		"attribution as marker": {optionalLink("Generated by a tool {{.Persona.Company}} {{.Persona.Domain}}{{if .Honeytokens.Link.URL}}{{.Honeytokens.Link.URL}}{{end}}\n"), "contains \"generated by\""},
		"license as marker":     {optionalLink("Licensed CC-BY-SA 4.0 {{.Persona.Company}} {{.Persona.Domain}}{{if .Honeytokens.Link.URL}}{{.Honeytokens.Link.URL}}{{end}}\n"), "contains \"cc-by\""},

		// An optional slot is empty when the file is pocket litter, so the
		// template references it only where it is set.
		"optional slot unguarded":                {optionalLink("{{.Persona.Company}} {{.Honeytokens.Link.URL}} {{.Persona.Domain}}\n"), "optional value .Honeytokens.Link.URL outside {{if .Honeytokens.Link.URL}}"},
		"optional slot in else":                  {optionalLink("{{if .Honeytokens.Link.URL}}x{{else}}{{.Honeytokens.Link.URL}}{{end}} {{.Persona.Company}} {{.Persona.Domain}}\n"), "optional value .Honeytokens.Link.URL outside"},
		"optional slot guarded by another value": {optionalLink("{{if .Persona.Company}}{{.Honeytokens.Link.URL}}{{end}} {{.Persona.Company}} {{.Persona.Domain}}\n"), "optional value .Honeytokens.Link.URL outside"},

		// Values that nothing references.
		"unreferenced slot":    {file(configTmpl, "Password {{.Secrets.Password}}\n"), "no template references .Honeytokens.Gateway.Host"},
		"optional slot unused": {optionalLink("{{.Persona.Company}} on {{.Persona.Domain}}\n"), "no template references .Honeytokens.Link.URL"},
		"unreferenced persona": {optionalLink("{{.Persona.Company}}{{if .Honeytokens.Link.URL}}{{.Honeytokens.Link.URL}}{{end}}\n"), "no template references .Persona.Domain"},
		"unreferenced secret":  {file(configTmpl, "Host {{.Honeytokens.Gateway.Host}}\n"), "no template references .Secrets.Password"},

		// Placing.
		"placing language missing": {func(fsys fstest.MapFS) {
			withPlacing(fsys)
			note(placing, `"placing": {"en": "placing.en.md.tmpl"}`)(fsys)
		}, "placing: want a template for each"},
		"placing language unknown": {func(fsys fstest.MapFS) {
			withPlacing(fsys)
			note(placing, `"placing": {"en": "placing.en.md.tmpl", "fr": "placing.de.md.tmpl"}`)(fsys)
		}, "placing: \"fr\" is not a language"},
		"placing file missing":     {func(fsys fstest.MapFS) { withPlacing(fsys); delete(fsys, placingDeTmpl) }, "placing de: the template placing.de.md.tmpl is missing"},
		"placing template":         {func(fsys fstest.MapFS) { withPlacing(fsys); fsys[placingEnTmpl] = mapFile("{{template \"x\"}}") }, "placing en:"},
		"placing undeclared value": {func(fsys fstest.MapFS) { withPlacing(fsys); fsys[placingEnTmpl] = mapFile("{{.Secrets.Token}}") }, "placing en:"},
	} {
		fsys := validFiles()
		c.change(fsys)
		if _, err := Load(fsys); !errors.Is(err, ErrInvalidArtifact) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Load() error = %v, want ErrInvalidArtifact with %q", name, err, c.want)
		}
	}
}

// An optional slot may be referenced inside nested conditions, and a required
// one anywhere.
func TestLoad_AcceptsOptionalSlotsInsideTheirCondition(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	fsys[noteTmpl] = mapFile("{{.Persona.Domain}}{{if .Persona.Company}}{{if .Honeytokens.Link.URL}} {{.Honeytokens.Link.URL}}{{else}} none{{end}}{{end}}\n")
	fsys[configTmpl] = mapFile("Host {{if .Secrets.Password}}{{.Honeytokens.Gateway.Host}}{{end}} {{.Secrets.Password}}\n")
	if _, err := Load(fsys); err != nil {
		t.Errorf("Load() error = %v", err)
	}
}

// Placing is optional and comes in both languages. It is read by
// administrators, so it may name what the artifact is, and a value that only
// it references is used.
func TestLoad_ReadsThePlacingOfAnArtifact(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	edit(t, noteJSON, `"template": "note.txt.tmpl"`, `"template": "note.txt.tmpl", "placing": {"en": "placing.en.md.tmpl", "de": "placing.de.md.tmpl"}`)(fsys)
	fsys[noteTmpl] = mapFile("{{.Persona.Company}}{{if .Honeytokens.Link.URL}}: {{.Honeytokens.Link.URL}}{{end}}\n")
	fsys[placingEnTmpl] = mapFile("This honeytoken of Nyktus belongs on the share of {{.Persona.Domain}}.\n")
	fsys[placingDeTmpl] = mapFile("Dieser Honeytoken geh\u00f6rt auf die Freigabe von {{.Persona.Domain}}.\n")
	c, err := Load(fsys)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	a, _ := c.LookupArtifact("note")
	out, err := a.Placing["de"].Render(map[string]string{"Persona.Domain": "corp.example.com"})
	if err != nil || string(out) != "Dieser Honeytoken geh\u00f6rt auf die Freigabe von corp.example.com.\n" {
		t.Errorf("Render(placing) = %q, %v", out, err)
	}
}

// An artifact that no deception recommends is valid and offered on its own.
func TestLoad_AcceptsAnArtifactNoDeceptionRecommends(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	edit(t, sampleJSON, `"artifacts": ["config", "note"]`, `"artifacts": ["config"]`)(fsys)
	fsys[guideEnTmpl] = mapFile("{{.Honeytokens.Gateway.Host}} {{.Honeytokens.Link.URL}} {{.Persona.Company}} {{.Persona.Domain}}\n")
	edit(t, secondJSON, `"artifacts": ["config", "note"]`, `"artifacts": ["config"]`)(fsys)
	fsys["deceptions/second/guide.en.md.tmpl"] = mapFile("{{.Honeytokens.Gateway.Host}} {{.Honeytokens.Link.URL}} {{.Persona.Company}} {{.Persona.Domain}}\n")
	c, err := Load(fsys)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if _, ok := c.LookupArtifact("note"); !ok {
		t.Error("LookupArtifact(note) did not find the artifact")
	}
}

func moveArtifact(fsys fstest.MapFS, from, to string) {
	for name, f := range fsys {
		if rest, ok := strings.CutPrefix(name, "artifacts/"+from+"/"); ok {
			delete(fsys, name)
			fsys["artifacts/"+to+"/"+rest] = f
		}
	}
	if s := string(fsys["artifacts/"+to+"/artifact.json"].Data); s != "" {
		fsys["artifacts/"+to+"/artifact.json"] = mapFile(strings.Replace(s, `"id": "`+from+`"`, `"id": "`+to+`"`, 1))
	}
}

func manySlots(fsys fstest.MapFS) {
	var extra strings.Builder
	for i := range maxSlots {
		extra.WriteString(`{"key": "Extra` + string(rune('A'+i)) + `", "accepts": ["dns"], "optional": true},`)
	}
	s := strings.Replace(string(fsys[configJSON].Data), `"slots": [`, `"slots": [`+extra.String(), 1)
	fsys[configJSON] = mapFile(s)
}

func manySecrets(fsys fstest.MapFS) {
	var extra strings.Builder
	for i := range maxSecrets {
		extra.WriteString(`{"key": "Extra` + string(rune('A'+i)) + `", "length": 8},`)
	}
	s := strings.Replace(string(fsys[configJSON].Data), `"secrets": [`, `"secrets": [`+extra.String(), 1)
	fsys[configJSON] = mapFile(s)
}
