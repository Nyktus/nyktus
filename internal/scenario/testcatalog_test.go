// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenario_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"nyktus.org/nyktus/internal/catalog"
)

// The catalog of the tests that extend a scenario. The embedded catalog has no
// artifact with an optional slot and no two deceptions that disagree about the
// kind of a value of the persona, which these tests need.
//
//   - ssh and rdp are deceptions with a DNS and an image honeytoken, a value of
//     the persona (rdp asks for a company as well) and one artifact of the
//     same name, with a required slot, a value of the persona and a secret.
//   - pair recommends both artifacts.
//   - memo has an optional slot and nothing else: pocket litter without it.
//   - note asks for the company as text.
//   - ssh says where to place it.

const testDeception = `{
  "schema_version": 2,
  "id": "%ID%",
  "category": "network",
  "title": {"en": "Title %ID%", "de": "Titel %ID%"},
  "summary": {"en": "Summary.", "de": "Zusammenfassung."},
  "techniques": ["T1021.004"],
  "engage_activities": ["EAC0005"],
  "honeytokens": [
    {"key": "Gateway", "type": "dns", "label": {"en": "Gateway", "de": "Zugang"}, "techniques": ["T1021.004"]},
    {"key": "Image", "type": "web_image", "label": {"en": "Image", "de": "Bild"}, "techniques": []}
  ],
  "persona": [
    {"key": "Domain", "kind": "host", "label": {"en": "Domain", "de": "Domaene"}, "example": "corp.example.com"}%PERSONA%
  ],
  "artifacts": [%ARTIFACTS%],
  "guide": {"en": "guide.en.md.tmpl", "de": "guide.de.md.tmpl"}
}`

const company = `,
    {"key": "Company", "kind": "text", "label": {"en": "Company", "de": "Firma"}, "example": "Example Ltd"}`

const testArtifact = `{
  "schema_version": 1,
  "id": "%ID%",
  "category": "network",
  "title": {"en": "File %ID%", "de": "Datei %ID%"},
  "summary": {"en": "Artifact.", "de": "Artefakt."},
  "slots": [{"key": "Gateway", "accepts": ["dns"], "optional": false}],
  "persona": [
    {"key": "Domain", "kind": "host", "label": {"en": "Domain", "de": "Domaene"}, "example": "corp.example.com"}
  ],
  "secrets": [{"key": "Password", "length": 16}],
  "file_name": "%ID%.conf",
  "format": "config",
  "line_endings": "lf",
  "template": "config.tmpl"%PLACING%
}`

const placing = `,
  "placing": {"en": "placing.en.md.tmpl", "de": "placing.de.md.tmpl"}`

const testMemo = `{
  "schema_version": 1,
  "id": "memo",
  "category": "data",
  "title": {"en": "Memo", "de": "Notiz"},
  "summary": {"en": "Memo.", "de": "Notiz."},
  "slots": [{"key": "Image", "accepts": ["web_image", "web_url"], "optional": true}],
  "persona": [],
  "secrets": [],
  "file_name": "memo.txt",
  "format": "text",
  "line_endings": "lf",
  "template": "memo.txt.tmpl"
}`

const testPersonaArtifact = `{
  "schema_version": 1,
  "id": "%ID%",
  "category": "data",
  "title": {"en": "File %ID%", "de": "Datei %ID%"},
  "summary": {"en": "Artifact.", "de": "Artefakt."},
  "slots": [],
  "persona": [
    {"key": "Company", "kind": "%KIND%", "label": {"en": "Company", "de": "Firma"}, "example": "%EXAMPLE%"}
  ],
  "secrets": [],
  "file_name": "%ID%.txt",
  "format": "text",
  "line_endings": "lf",
  "template": "file.txt.tmpl"
}`

// testCatalog returns the catalog described above.
func testCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	file := func(content string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(content)} }
	fsys := fstest.MapFS{
		"artifacts/memo/artifact.json": file(testMemo),
		"artifacts/memo/memo.txt.tmpl": file("Reminder{{if .Honeytokens.Image.URL}}: {{.Honeytokens.Image.URL}}{{end}}\n"),
		"artifacts/note/artifact.json": file(personaArtifact("note", "text", "Example Ltd")),
		"artifacts/note/file.txt.tmpl": file("Company: {{.Persona.Company}}\n"),
	}
	for id, def := range map[string]struct{ persona, artifacts string }{
		"ssh":  {"", `"ssh"`},
		"rdp":  {company, `"rdp"`},
		"pair": {"", `"rdp", "ssh"`},
	} {
		d := strings.NewReplacer("%ID%", id, "%PERSONA%", def.persona, "%ARTIFACTS%", def.artifacts).Replace(testDeception)
		fsys["deceptions/"+id+"/deception.json"] = file(d)
		guide := "{{.Honeytokens.Image.URL}}"
		if def.persona != "" {
			guide += " {{.Persona.Company}}"
		}
		fsys["deceptions/"+id+"/guide.en.md.tmpl"] = file(guide)
		fsys["deceptions/"+id+"/guide.de.md.tmpl"] = file(guide)
	}
	for _, id := range []string{"ssh", "rdp"} {
		p := ""
		if id == "ssh" {
			p = placing
			fsys["artifacts/ssh/placing.en.md.tmpl"] = file("Place it on a host of {{.Persona.Domain}}.")
			fsys["artifacts/ssh/placing.de.md.tmpl"] = file("Lege es auf einen Host von {{.Persona.Domain}}.")
		}
		fsys["artifacts/"+id+"/artifact.json"] = file(strings.NewReplacer("%ID%", id, "%PLACING%", p).Replace(testArtifact))
		fsys["artifacts/"+id+"/config.tmpl"] = file("Host {{.Honeytokens.Gateway.Host}} {{.Persona.Domain}} {{.Secrets.Password}}\n")
	}
	c, err := catalog.Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func personaArtifact(id, kind, example string) string {
	return strings.NewReplacer("%ID%", id, "%KIND%", kind, "%EXAMPLE%", example).Replace(testPersonaArtifact)
}
