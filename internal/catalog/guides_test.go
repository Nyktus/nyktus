// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog_test

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/catalog"
)

// The outline that every guide follows, in the order of its sections, in each
// language. A section "Removing" stands between "Testing" and "Limits" where a
// deception leaves traces in the system that the administrator has to clean
// up. Both languages have the same sections in the same order, so that a
// reader, and a tool that reads a guide by section, finds the same thing in
// each.
var (
	outline  = map[string][]string{"en": {"Story", "Setup", "Testing", "Limits"}, "de": {"Geschichte", "Umsetzung", "Testen", "Grenzen"}}
	removing = map[string]string{"en": "Removing", "de": "Entfernen"}
)

// maxGuideLines is the length of a guide in lines, by group. The groups are
// recipes with many commands (the cloud and the directory) and everything else.
// A limit stands just above the longest guide of its group, so that a guide
// that grows has to say why.
var maxGuideLines = map[string]int{"other": 55, "directory": 125, "cloud": 155}

// guideGroup tells which limit holds for a deception.
func guideGroup(d catalog.Deception) string {
	switch {
	case d.Category == "cloud":
		return "cloud"
	case strings.HasPrefix(d.ID, "ad-"):
		return "directory"
	default:
		return "other"
	}
}

type heading struct {
	level int
	text  string
}

var (
	headingLine = regexp.MustCompile(`^(#{1,6})[ \t]+(.*?)[ \t]*$`)
	fenced      = regexp.MustCompile("(?s)```.*?```")
	inlineCode  = regexp.MustCompile("`[^`\n]+`")
)

// isFence tells whether a line opens or closes a code block, also one that is
// indented below an item of a list.
func isFence(line string) bool { return strings.HasPrefix(strings.TrimSpace(line), "```") }

// headings returns the headings of a Markdown text outside its code blocks.
func headings(md string) []heading {
	var hs []heading
	inFence := false
	for _, line := range strings.Split(md, "\n") {
		if isFence(line) {
			inFence = !inFence
			continue
		}
		if m := headingLine.FindStringSubmatch(line); !inFence && m != nil {
			hs = append(hs, heading{len(m[1]), m[2]})
		}
	}
	return hs
}

// prose returns the text of a guide without its code, which is not translated.
func prose(md string) string {
	return inlineCode.ReplaceAllString(fenced.ReplaceAllString(md, ""), "")
}

func lineCount(md string) int {
	return strings.Count(strings.TrimRight(md, "\n"), "\n") + 1
}

// outlineProblem returns what is wrong with the headings of a guide, or "".
func outlineProblem(md, lang string, allowSteps bool) string {
	want := slices.Clone(outline[lang])
	hs := headings(md)
	var h2 []string
	seen := map[string]bool{}
	section := ""
	for _, h := range hs {
		if seen[h.text] {
			return fmt.Sprintf("the heading %q stands twice", h.text)
		}
		seen[h.text] = true
		switch h.level {
		case 2:
			h2 = append(h2, h.text)
			section = h.text
		case 3:
			if !allowSteps || section != want[1] {
				return fmt.Sprintf("the heading %q is a step of a section other than %q, or of a guide that has no steps", h.text, want[1])
			}
		default:
			return fmt.Sprintf("the heading %q has level %d, want 2 or 3", h.text, h.level)
		}
	}
	// "Removing" is optional, between "Testing" and "Limits".
	if slices.Contains(h2, removing[lang]) {
		want = slices.Insert(want, 3, removing[lang])
	}
	if !slices.Equal(h2, want) {
		return fmt.Sprintf("the sections are %q, want %q", h2, want)
	}
	return ""
}

func headingLevels(md string) []int {
	var levels []int
	for _, h := range headings(md) {
		levels = append(levels, h.level)
	}
	return levels
}

func TestEmbeddedCatalog_GuidesFollowTheOutline(t *testing.T) {
	t.Parallel()

	for _, d := range load(t).Deceptions() {
		steps := guideGroup(d) != "other"
		for _, lang := range catalog.Languages {
			if p := outlineProblem(d.Guide[lang], lang, steps); p != "" {
				t.Errorf("%s: guide %s: %s", d.ID, lang, p)
			}
		}
		if !slices.Equal(headingLevels(d.Guide["en"]), headingLevels(d.Guide["de"])) {
			t.Errorf("%s: the guides have different headings: en %v, de %v", d.ID, headingLevels(d.Guide["en"]), headingLevels(d.Guide["de"]))
		}
	}
}

func TestOutlineProblem_RejectsWhatBreaksTheOutline(t *testing.T) {
	t.Parallel()

	const ok = "## Story\n\na\n\n## Setup\n\n1. b\n\n## Testing\n\nc\n\n## Limits\n\n- d\n"
	steps := strings.Replace(ok, "1. b", "### Step\n\n1. b", 1)
	tests := []struct {
		name  string
		md    string
		steps bool
		bad   bool
	}{
		{"the outline", ok, false, false},
		{"with a section Removing", strings.Replace(ok, "## Limits", "## Removing\n\ne\n\n## Limits", 1), false, false},
		{"a title of level 1", "# Title\n\n" + ok, false, true},
		{"a missing section", strings.Replace(ok, "## Testing\n\nc\n\n", "", 1), false, true},
		{"sections in another order", strings.Replace(strings.Replace(ok, "Limits", "X", 1), "Testing", "Limits", 1), false, true},
		{"a section for each file", strings.Replace(ok, "## Limits", "## Testing\n\nc\n\n## Limits", 1), false, true},
		{"a step where a guide has none", steps, false, true},
		{"a step in a recipe", steps, true, false},
		{"a step in the wrong section", strings.Replace(ok, "c\n", "### Step\n\nc\n", 1), true, true},
		{"a heading in a code block", ok + "\n```\n# comment\n```\n", false, false},
	}
	for _, tt := range tests {
		if got := outlineProblem(tt.md, "en", tt.steps); (got != "") != tt.bad {
			t.Errorf("%s: outlineProblem = %q, want a problem: %v", tt.name, got, tt.bad)
		}
	}
	if outlineProblem(ok, "de", false) == "" {
		t.Error("an English outline passes as German")
	}
}

func TestEmbeddedCatalog_GuidesStayShort(t *testing.T) {
	t.Parallel()

	for _, d := range load(t).Deceptions() {
		limit := maxGuideLines[guideGroup(d)]
		for _, lang := range catalog.Languages {
			if n := lineCount(d.Guide[lang]); n > limit {
				t.Errorf("%s: guide %s has %d lines, want at most %d for %s", d.ID, lang, n, limit, guideGroup(d))
			}
		}
	}
}

// placeholderWord finds a word that looks like a placeholder, to see one that
// is spelled in a way the catalog does not read.
var placeholderWord = regexp.MustCompile(`Honeytoken-[A-Za-z0-9-]*`)

// standardWord finds a placeholder of the catalog in prose, where it does not
// belong. A German compound such as "Honeytoken-Name" is no placeholder.
var standardWord = regexp.MustCompile(`Honeytoken-(?:Domain|URL)\b`)

// placeholderSlot is a placeholder that names a slot, such as
// Honeytoken-Domain-Server.
var placeholderSlot = regexp.MustCompile(`Honeytoken-(?:Domain|URL)-[A-Z][A-Za-z0-9]{0,31}`)

// standardPlaceholder is the whole word of a placeholder that the catalog reads.
var standardPlaceholder = regexp.MustCompile(`^Honeytoken-(?:Domain|URL)(?:-[A-Z][A-Za-z0-9]{0,31})?$`)

// placeholderProblem returns what is wrong with the placeholders in a guide, or
// "". A placeholder stands in code, so that it is read as one. The placeholders
// that the files of the deception hold, and the label of each of its
// honeytokens where it has several of a kind, stand in the guide: it is what
// says which honeytoken belongs to which placeholder.
func placeholderProblem(guide, lang string, d catalog.Deception) string {
	if w := standardWord.FindString(prose(guide)); w != "" {
		return fmt.Sprintf("the placeholder %s stands outside code", w)
	}
	for _, code := range append(fenced.FindAllString(guide, -1), inlineCode.FindAllString(guide, -1)...) {
		for _, w := range placeholderWord.FindAllString(code, -1) {
			if !standardPlaceholder.MatchString(w) {
				return w + " is no placeholder of the catalog"
			}
		}
	}
	for _, f := range d.Files {
		for _, w := range placeholderSlot.FindAllString(string(f.Content), -1) {
			if !strings.Contains(guide, w) {
				return fmt.Sprintf("the file %s holds %s, which the guide does not name", f.Name, w)
			}
		}
	}
	var dns, urls int
	for _, h := range d.Honeytokens {
		if h.Type == "dns" {
			dns++
		} else {
			urls++
		}
	}
	if dns > 1 || urls > 1 {
		open, closing := `"`, `"`
		if lang == "de" {
			open, closing = "„", "“"
		}
		for _, h := range d.Honeytokens {
			if !strings.Contains(guide, open+h.Label[lang]+closing) {
				return fmt.Sprintf("the guide does not name the honeytoken %s%s%s in quotation marks", open, h.Label[lang], closing)
			}
		}
	}
	return ""
}

func TestEmbeddedCatalog_GuidesTellWhichPlaceholderBelongsToWhichHoneytoken(t *testing.T) {
	t.Parallel()

	for _, d := range load(t).Deceptions() {
		for _, lang := range catalog.Languages {
			if p := placeholderProblem(d.Guide[lang], lang, d); p != "" {
				t.Errorf("%s: guide %s: %s", d.ID, lang, p)
			}
		}
	}
}

func TestPlaceholderProblem_RejectsWhatBreaksThePromise(t *testing.T) {
	t.Parallel()

	label := func(en string) catalog.Text { return catalog.Text{"en": en, "de": en} }
	one := catalog.Deception{Honeytokens: []catalog.HoneytokenSlot{{Label: label("Server"), Type: "dns"}}}
	two := catalog.Deception{
		Honeytokens: []catalog.HoneytokenSlot{{Label: label("Server"), Type: "dns"}, {Label: label("Gateway"), Type: "dns"}},
		Files:       []catalog.File{{Name: "a", Content: []byte("host Honeytoken-Domain-Gateway")}},
	}
	tests := []struct {
		name  string
		guide string
		d     catalog.Deception
		bad   bool
	}{
		{"a placeholder in code", "Replace `Honeytoken-Domain`.", one, false},
		{"a placeholder in prose", "Replace Honeytoken-Domain.", one, true},
		{"a German compound is no placeholder", "Der Honeytoken-Name und das Honeytoken-Typ.", one, false},
		{"a misspelled placeholder", "Replace `Honeytoken-domain`.", one, true},
		{"an unknown kind", "Replace `Honeytoken-Host`.", one, true},
		{"labels and placeholders named", "`Honeytoken-Domain-Gateway`: \"Gateway\", \"Server\"", two, false},
		{"a file placeholder that the guide leaves out", "\"Gateway\", \"Server\"", two, true},
		{"a label that the guide leaves out", "`Honeytoken-Domain-Gateway`: \"Gateway\"", two, true},
		{"a label that is no quotation", "`Honeytoken-Domain-Gateway`: Gateway, Server", two, true},
	}
	for _, tt := range tests {
		if got := placeholderProblem(tt.guide, "en", tt.d); (got != "") != tt.bad {
			t.Errorf("%s: placeholderProblem = %q, want a problem: %v", tt.name, got, tt.bad)
		}
	}
}

// codeProblem returns what differs in the code of two guides, or "". Commands,
// file names and values are the same in both languages; only the prose is
// translated, so a command cannot send the administrator of one language to
// something else than the other.
func codeProblem(en, de string) string {
	if a, b := fenced.FindAllString(en, -1), fenced.FindAllString(de, -1); !slices.Equal(a, b) {
		return "the code blocks differ"
	}
	a, b := inlineCode.FindAllString(withoutBlocks(en), -1), inlineCode.FindAllString(withoutBlocks(de), -1)
	slices.Sort(a)
	slices.Sort(b)
	if !slices.Equal(a, b) {
		return fmt.Sprintf("the code differs\nen: %q\nde: %q", a, b)
	}
	return ""
}

// withoutBlocks returns a text without its code blocks, but with its inline code.
func withoutBlocks(md string) string { return fenced.ReplaceAllString(md, "") }

func TestEmbeddedCatalog_GuidesNameTheSameCodeInBothLanguages(t *testing.T) {
	t.Parallel()

	for _, d := range load(t).Deceptions() {
		if p := codeProblem(d.Guide["en"], d.Guide["de"]); p != "" {
			t.Errorf("%s: %s", d.ID, p)
		}
	}
}

func TestCodeProblem_RejectsCodeThatDiffers(t *testing.T) {
	t.Parallel()

	const en = "Run `ls`.\n\n```sh\nls\n```\n"
	if p := codeProblem(en, "Führen Sie `ls` aus.\n\n```sh\nls\n```\n"); p != "" {
		t.Errorf("codeProblem(same code) = %q", p)
	}
	if codeProblem(en, "Führen Sie `dir` aus.\n\n```sh\nls\n```\n") == "" {
		t.Error("a differing code span passes")
	}
	if codeProblem(en, "Führen Sie `ls` aus.\n\n```sh\ndir\n```\n") == "" {
		t.Error("a differing code block passes")
	}
}

// germanSpellings are the spellings that a German guide does not use, with the
// word that it uses. The console says "Ereignis", so a guide does not say
// "Event"; the choice of the others is in the README of the catalog.
var germanSpellings = []struct {
	pattern *regexp.Regexp
	use     string
}{
	{regexp.MustCompile(`\bEvents?\b`), "Ereignis"},
	{regexp.MustCompile(`Host-Name`), "Hostname"},
	{regexp.MustCompile(`\bScenarios?\b`), "Szenario"},
	{regexp.MustCompile(`Eindringling`), "Angreifer"},
	{regexp.MustCompile(`(?i)canary`), "Honeytoken"},
	{regexp.MustCompile(`"[^"\n]+"`), "„…“ instead of straight quotation marks"},
	{regexp.MustCompile(`\b(?:[Dd]er|[Dd]en|[Ee]inen|[Dd]iesen|[Jj]eden) Honeytoken(?:[^-A-Za-z]|$)`), "das Honeytoken, which is neuter"},
	{regexp.MustCompile(`\d +(?:[KMGT]i?B|[Bb]ytes?)\b`), "a no-break space between a number and its unit"},
}

// germanProblem returns the first spelling of a German guide that it does not
// use, or "".
func germanProblem(md string) string {
	text := prose(md)
	for _, s := range germanSpellings {
		if m := s.pattern.FindString(text); m != "" {
			return fmt.Sprintf("%q: use %s", m, s.use)
		}
	}
	return ""
}

func TestEmbeddedCatalog_GermanGuidesUseTheTermsOfTheConsole(t *testing.T) {
	t.Parallel()

	for _, d := range load(t).Deceptions() {
		if p := germanProblem(d.Guide["de"]); p != "" {
			t.Errorf("%s: %s", d.ID, p)
		}
	}
}

// The titles, summaries and labels are shown in the lists of the console and
// follow the same terms as the guides.
func TestEmbeddedCatalog_GermanTextsUseTheTermsOfTheConsole(t *testing.T) {
	t.Parallel()

	for _, d := range load(t).Deceptions() {
		texts := map[string]string{"title": d.Title["de"], "summary": d.Summary["de"]}
		for i, h := range d.Honeytokens {
			texts[fmt.Sprintf("honeytokens[%d].label", i)] = h.Label["de"]
		}
		for i, h := range d.Honeypots {
			texts[fmt.Sprintf("honeypots[%d].label", i)] = h.Label["de"]
		}
		for field, text := range texts {
			if p := germanProblem(text); p != "" {
				t.Errorf("%s %s: %s", d.ID, field, p)
			}
		}
	}
}

func TestGermanProblem_RejectsOtherSpellings(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{
		"Das Event löst aus.", "Zwei Events.", "Der Host-Name", "Ein Scenario", "Ein Eindringling", "Ein Canary", "Das „Ereignis“ und \"Event\"",
		"bis zu 4 KiB", "bei 4096 Byte", "ein 1 TB Laufwerk", // an ordinary space
		"Der Honeytoken löst aus.", "Legen Sie einen Honeytoken an", "mit den Honeytoken",
	} {
		if germanProblem(bad) == "" {
			t.Errorf("germanProblem(%q) passes", bad)
		}
	}
	for _, good := range []string{
		"Das Ereignis löst aus.", "Der Hostname", "Ein Angreifer", "EventBridge", "bis zu 4 KiB",
		"`Event` und `Host-Name` stehen in Code", "```\nEvent\n```",
		"Das Honeytoken löst aus.", "dem Honeytoken", "der Honeytoken-Name", "die Namen der Honeytokens",
	} {
		if p := germanProblem(good); p != "" {
			t.Errorf("germanProblem(%q) = %q", good, p)
		}
	}
}

// section returns the text of the section with a heading of level 2, or "".
func section(md, title string) string {
	var out []string
	in, inFence := false, false
	for _, line := range strings.Split(md, "\n") {
		if isFence(line) {
			inFence = !inFence
		}
		if m := headingLine.FindStringSubmatch(line); !inFence && m != nil && len(m[1]) == 2 {
			in = m[2] == title
			continue
		}
		if in {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

var (
	lookupCommand  = regexp.MustCompile(`nslookup +Honeytoken-Domain`)
	requestCommand = regexp.MustCompile(`curl\b[^\n]*Honeytoken-URL`)
)

// testCommandProblem returns what is missing in the test of a guide, or "": a
// command for each kind of honeytoken, which the administrator runs with the
// placeholder replaced by the value of the honeytoken. The recipes of the cloud
// and of the directory test with a real call instead.
func testCommandProblem(text string, d catalog.Deception) string {
	for _, h := range d.Honeytokens {
		command, name := requestCommand, "curl"
		if h.Type == "dns" {
			command, name = lookupCommand, "nslookup"
		}
		if !command.MatchString(text) {
			return fmt.Sprintf("the test does not run %s with a placeholder for the honeytoken %q", name, h.Label["en"])
		}
	}
	return ""
}

func TestEmbeddedCatalog_GuidesTestEachKindOfHoneytokenWithACommand(t *testing.T) {
	t.Parallel()

	for _, d := range load(t).Deceptions() {
		if guideGroup(d) != "other" {
			continue
		}
		for _, lang := range catalog.Languages {
			if p := testCommandProblem(section(d.Guide[lang], outline[lang][2]), d); p != "" {
				t.Errorf("%s: guide %s: %s", d.ID, lang, p)
			}
		}
	}
}

func TestTestCommandProblem_RejectsATestWithoutACommand(t *testing.T) {
	t.Parallel()

	d := catalog.Deception{Honeytokens: []catalog.HoneytokenSlot{{Label: catalog.Text{"en": "A"}, Type: "dns"}, {Label: catalog.Text{"en": "B"}, Type: "web_image"}}}
	if p := testCommandProblem("Run `nslookup Honeytoken-Domain-A` and `curl https://Honeytoken-URL-B/`.", d); p != "" {
		t.Errorf("testCommandProblem(both commands) = %q", p)
	}
	for _, text := range []string{"Run `nslookup Honeytoken-Domain-A`.", "Run `curl Honeytoken-URL-B`.", "Open it.", "Do not run curl or nslookup.", "Run `nslookup X` and `curl Y`."} {
		if testCommandProblem(text, d) == "" {
			t.Errorf("testCommandProblem(%q) passes", text)
		}
	}
	md := "## Setup\n\ncurl\n\n## Testing\n\n1. Step\n\n   ```\n## not a heading\n   ```\nnslookup\n\n## Limits\n\nx\n"
	if got := section(md, "Testing"); !strings.Contains(got, "nslookup") || strings.Contains(got, "curl") || strings.Contains(got, "Limits") {
		t.Errorf("section(Testing) = %q", got)
	}
}

var (
	nestedItem = regexp.MustCompile(`^\s+(?:[-*+]|\d+[.)])\s`)
	tableRow   = regexp.MustCompile(`^\s*\|`)
)

// consoleProblem returns what the console would not show as written, or "":
// the reader of the console (web/src/markdown.ts) has no nested lists, which it
// runs into the text of the item, and no tables.
func consoleProblem(md string) string {
	inFence := false
	for _, line := range strings.Split(md, "\n") {
		if isFence(line) {
			inFence = !inFence
			continue
		}
		switch {
		case inFence:
		case nestedItem.MatchString(line):
			return "a list inside an item, which the console shows as running text: " + strings.TrimSpace(line)
		case tableRow.MatchString(line):
			return "a table, which the console does not show: " + strings.TrimSpace(line)
		}
	}
	return ""
}

func TestEmbeddedCatalog_GuidesUseOnlyWhatTheConsoleShows(t *testing.T) {
	t.Parallel()

	for _, d := range load(t).Deceptions() {
		for _, lang := range catalog.Languages {
			if p := consoleProblem(d.Guide[lang]); p != "" {
				t.Errorf("%s: guide %s: %s", d.ID, lang, p)
			}
		}
	}
}

func TestConsoleProblem_RejectsWhatTheConsoleDoesNotShow(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"1. Step\n   - nested\n", "- a\n  - b\n", "1. Step\n   1. nested\n", "| a | b |\n|---|---|\n"} {
		if consoleProblem(bad) == "" {
			t.Errorf("consoleProblem(%q) passes", bad)
		}
	}
	for _, good := range []string{"1. Step\n\n   ```sh\n   - not a list\n   | not a table\n   ```\n\n- a\n- b\n", "Run `a | b`.\n"} {
		if p := consoleProblem(good); p != "" {
			t.Errorf("consoleProblem(%q) = %q", good, p)
		}
	}
}
