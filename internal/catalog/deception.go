// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"nyktus.org/nyktus/internal/engage"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/severity"
)

// SchemaVersion is the version of the format of a deception that this build
// reads.
const SchemaVersion = 1

// Category groups deceptions by what they pretend to be.
type Category string

// Categories of deceptions.
const (
	// CategoryIdentity pretends to be credentials or accounts.
	CategoryIdentity Category = "identity"
	// CategoryNetwork pretends to be access to hosts or networks, such as VPN
	// or SSH configurations.
	CategoryNetwork Category = "network"
	// CategoryData pretends to be documents, exports or backups.
	CategoryData Category = "data"
	// CategoryEndpoint pretends to be files of a workstation, such as
	// shortcuts or scripts.
	CategoryEndpoint Category = "endpoint"
	// CategoryApplication pretends to be configuration or credentials of an
	// application.
	CategoryApplication Category = "application"
)

// Categories lists every category.
var Categories = []Category{CategoryIdentity, CategoryNetwork, CategoryData, CategoryEndpoint, CategoryApplication}

// Languages lists the languages of the texts and guides of every deception.
var Languages = []string{"en", "de"}

// Text is a text in every language of Languages.
type Text map[string]string

// Deception is a blueprint of a scenario: the honeytokens it creates, the
// values an administrator provides, the artifacts it renders and the guide
// that explains how to place them.
type Deception struct {
	// ID identifies the deception, such as "ssh-config". It is the name of
	// its directory.
	ID       string
	Category Category
	Title    Text
	Summary  Text
	// Techniques are the ATT&CK techniques that a trigger of the deception
	// suggests.
	Techniques []string
	// EngageActivities are the Engage activities that the deception carries
	// out, such as EAC0005 (Lures).
	EngageActivities []string
	Honeytokens      []Honeytoken
	Persona          []PersonaField
	Secrets          []Secret
	Artifacts        []Artifact
	// Guide explains to the administrator how to place the artifacts, by
	// language.
	Guide map[string]*Template
}

// Honeytoken is a honeytoken that applying a deception creates.
type Honeytoken struct {
	// Key names the honeytoken in the templates of the deception, such as
	// .Honeytokens.JumpHost.Host.
	Key        string
	Type       honeytoken.Type
	Label      Text
	Techniques []string
	// Severity is the severity of the honeytoken: the one that the deception
	// chooses, or the default of its type.
	Severity severity.Level
}

// PersonaField is a value that the administrator provides when applying a
// deception, such as the internal domain, so that artifacts fit the
// environment. Deceptions carry no default for it: a value in every
// installation would identify the artifacts.
type PersonaField struct {
	// Key names the value in the templates, such as .Persona.Domain.
	Key   string
	Kind  Kind
	Label Text
	// Example is shown to the administrator as an example. It never reaches
	// an artifact.
	Example string
}

// Secret is a random value that applying a deception generates, such as a
// password, of letters and digits.
type Secret struct {
	// Key names the value in the templates, such as .Secrets.Password.
	Key    string
	Length int
}

// Artifact is a file that applying a deception renders.
type Artifact struct {
	// Key identifies the artifact within its deception.
	Key string
	// FileName is the name under which the artifact is downloaded.
	FileName string
	Format   Format
	// LineEndings are the line endings of the file.
	LineEndings LineEndings
	Template    *Template
}

// LineEndings are the line endings of an artifact. Templates are written with
// line feeds; files that their tools expect with carriage returns, such as
// Windows shortcuts, declare CRLF.
type LineEndings string

// Line endings of artifacts.
const (
	LF   LineEndings = "lf"
	CRLF LineEndings = "crlf"
)

// Render renders the artifact with values, as Template.Render describes, with
// its line endings. No value contains a line break, so every line feed of the
// output comes from the template.
func (a Artifact) Render(values map[string]string) ([]byte, error) {
	out, err := a.Template.Render(values)
	if err != nil || a.LineEndings != CRLF {
		return out, err
	}
	return bytes.ReplaceAll(out, []byte("\n"), []byte("\r\n")), nil
}

// Limits of a deception.
const (
	maxTitleLength   = 100
	maxSummaryLength = 500
	maxLabelLength   = 60
	maxHoneytokens   = 10
	maxPersona       = 10
	maxSecrets       = 10
	maxArtifacts     = 20
	minSecretLength  = 8
	maxSecretLength  = 64
	// maxFileBytes bounds every file of a deception, above the largest
	// template.
	maxFileBytes = MaxTemplateBytes
	// MaxRenderedBytes bounds what applying a deception renders: its
	// artifacts and its guide in one language, with every value at its
	// longest. Applying a deception stores all of it in one transaction.
	MaxRenderedBytes = 4 << 20
	// definitionFile is the name of the file that describes a deception in
	// its directory.
	definitionFile = "deception.json"
)

var (
	deceptionID  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	valueKey     = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,31}$`)
	artifactKey  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	templateFile = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*\.tmpl$`)
	// A file name that every operating system accepts: no separators, no
	// leading dot or hyphen, no trailing dot or space.
	fileName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9 ._-]{0,98}[A-Za-z0-9_-])?$`)
)

// markers must not appear in an artifact, in any case: they name the product
// or what an artifact is, credit the catalog, or are what a template renders
// for a missing value, and whoever finds them knows that the file is a trap.
// Guides are read by administrators and may use them. Actions left over in a
// template cannot reach an artifact: the engine parses them.
var markers = []string{
	"nyktus", "honeytoken", "honeypot", "canary", "decoy", "deception", "creative commons", "generated by",
	"<no value>",
}

// licenseNotice finds the short form of a Creative Commons license, such as
// "CC BY 4.0" or "cc-by-sa", as a word of its own, so that words such as
// "gcc by default" do not match.
var licenseNotice = regexp.MustCompile(`(?i)\bcc[ -]by\b`)

// definition is the JSON of a deception.
type definition struct {
	SchemaVersion    int               `json:"schema_version"`
	ID               string            `json:"id"`
	Category         Category          `json:"category"`
	Title            Text              `json:"title"`
	Summary          Text              `json:"summary"`
	Techniques       []string          `json:"techniques"`
	EngageActivities []string          `json:"engage_activities"`
	Honeytokens      []honeytokenDef   `json:"honeytokens"`
	Persona          []personaFieldDef `json:"persona"`
	Secrets          []secretDef       `json:"secrets"`
	Artifacts        []artifactDef     `json:"artifacts"`
	Guide            map[string]string `json:"guide"`
}

type (
	honeytokenDef struct {
		Key        string          `json:"key"`
		Type       honeytoken.Type `json:"type"`
		Label      Text            `json:"label"`
		Techniques []string        `json:"techniques"`
		Severity   severity.Level  `json:"severity"`
	}
	personaFieldDef struct {
		Key     string `json:"key"`
		Kind    Kind   `json:"kind"`
		Label   Text   `json:"label"`
		Example string `json:"example"`
	}
	secretDef struct {
		Key    string `json:"key"`
		Length int    `json:"length"`
	}
	artifactDef struct {
		Key         string      `json:"key"`
		FileName    string      `json:"file_name"`
		Format      Format      `json:"format"`
		LineEndings LineEndings `json:"line_endings"`
		Template    string      `json:"template"`
	}
)

// ErrInvalidDeception means that a deception of the catalog is invalid.
var ErrInvalidDeception = errors.New("invalid deception")

// loadDeception reads, validates and compiles the deception in the directory
// dir of fsys.
func loadDeception(fsys fs.FS, dir string) (Deception, error) {
	fail := func(format string, args ...any) (Deception, error) {
		return Deception{}, fmt.Errorf("%w %s: %s", ErrInvalidDeception, dir, fmt.Sprintf(format, args...))
	}
	if !deceptionID.MatchString(dir) || len(dir) > 64 {
		return fail("the name of the directory is not a valid identifier")
	}
	files, err := readFiles(fsys, dir)
	if err != nil {
		return fail("%v", err)
	}
	raw, ok := files[definitionFile]
	if !ok {
		return fail("%s is missing", definitionFile)
	}
	var def definition
	if err := decodeStrict(raw, &def); err != nil {
		return fail("%s: %v", definitionFile, err)
	}
	if def.SchemaVersion != SchemaVersion {
		return fail("schema version %d is not supported, want %d", def.SchemaVersion, SchemaVersion)
	}
	if def.ID != dir {
		return fail("the identifier %q differs from the name of the directory", def.ID)
	}
	if err := def.validate(); err != nil {
		return fail("%v", err)
	}

	d := Deception{
		ID: def.ID, Category: def.Category, Title: def.Title, Summary: def.Summary,
		Techniques: def.Techniques, EngageActivities: def.EngageActivities,
		Guide: map[string]*Template{},
	}
	for _, h := range def.Honeytokens {
		level := h.Severity
		if level == "" {
			level = h.Type.DefaultSeverity()
		}
		d.Honeytokens = append(d.Honeytokens, Honeytoken{
			Key: h.Key, Type: h.Type, Label: h.Label, Techniques: h.Techniques, Severity: level,
		})
	}
	for _, p := range def.Persona {
		d.Persona = append(d.Persona, PersonaField(p))
	}
	for _, s := range def.Secrets {
		d.Secrets = append(d.Secrets, Secret(s))
	}
	fields := d.Fields()

	used := map[string]bool{definitionFile: true}
	for _, a := range def.Artifacts {
		src, ok := files[a.Template]
		if !ok {
			return fail("artifact %s: the template %s is missing", a.Key, a.Template)
		}
		used[a.Template] = true
		t, err := Compile(path.Join(dir, a.Template), a.Format, string(src), fields)
		if err != nil {
			return fail("artifact %s: %v", a.Key, err)
		}
		if marker := findMarker(t.static, d.ID); marker != "" {
			return fail("artifact %s: the template contains %q, which reveals the artifact", a.Key, marker)
		}
		d.Artifacts = append(d.Artifacts, Artifact{
			Key: a.Key, FileName: a.FileName, Format: a.Format, LineEndings: a.LineEndings, Template: t,
		})
	}
	for _, lang := range Languages {
		name := def.Guide[lang]
		src, ok := files[name]
		if !ok {
			return fail("guide %s: the template %s is missing", lang, name)
		}
		used[name] = true
		t, err := Compile(path.Join(dir, name), FormatMarkdown, string(src), fields)
		if err != nil {
			return fail("guide %s: %v", lang, err)
		}
		d.Guide[lang] = t
	}
	// Every file is stored as one value of at most MaxOutputBytes; the engine
	// bounds the output before the line endings are converted, so the
	// bound of each file is checked here.
	for _, a := range d.Artifacts {
		if n := a.maxBytes(); n > MaxOutputBytes {
			return fail("artifact %s can render %d bytes, more than %d", a.Key, n, MaxOutputBytes)
		}
	}
	for lang, t := range d.Guide {
		if t.bound > MaxOutputBytes {
			return fail("guide %s can render %d bytes, more than %d", lang, t.bound, MaxOutputBytes)
		}
	}
	if n := d.maxRenderedBytes(); n > MaxRenderedBytes {
		return fail("its artifacts and guide can render %d bytes, more than %d", n, MaxRenderedBytes)
	}
	// A value that no template references is a mistake: a honeytoken that
	// no file names is never placed, and a value of the persona is asked for
	// in vain.
	referenced := map[string]bool{}
	for _, a := range d.Artifacts {
		for path := range a.Template.fields {
			referenced[path] = true
		}
	}
	for _, t := range d.Guide {
		for path := range t.fields {
			referenced[path] = true
		}
	}
	for path := range fields {
		if !referenced[path] {
			return fail("no template references .%s", path)
		}
	}
	// A file that nothing references would be shipped without being
	// reviewed as part of a deception.
	for name := range files {
		if !used[name] {
			return fail("the file %s is not referenced", name)
		}
	}
	return d, nil
}

// Fields returns the values that the templates of d may reference: the URL
// or host name of each honeytoken, each value of the persona and each secret.
func (d Deception) Fields() Fields {
	fields := Fields{}
	for _, h := range d.Honeytokens {
		if h.Type == honeytoken.TypeDNS {
			fields["Honeytokens."+h.Key+".Host"] = KindHost
		} else {
			fields["Honeytokens."+h.Key+".URL"] = KindURL
		}
	}
	for _, p := range d.Persona {
		fields["Persona."+p.Key] = p.Kind
	}
	for _, s := range d.Secrets {
		fields["Secrets."+s.Key] = KindSecret
	}
	return fields
}

// readFiles reads every file in the directory dir of fsys. The directory may
// hold regular files only, with names of templates or the definition, each
// at most maxFileBytes.
func readFiles(fsys fs.FS, dir string) (map[string][]byte, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	files := make(map[string][]byte, len(entries))
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || (name != definitionFile && !templateFile.MatchString(name)) {
			return nil, fmt.Errorf("%s is not a template or %s", name, definitionFile)
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		if info.Size() > maxFileBytes {
			return nil, fmt.Errorf("%s is larger than %d bytes", name, maxFileBytes)
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, name))
		if err != nil {
			return nil, err
		}
		files[name] = b
	}
	return files, nil
}

// decodeStrict decodes JSON into v, rejecting unknown fields and anything
// after the value.
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after the deception")
	}
	return nil
}

func (def definition) validate() error {
	if !slices.Contains(Categories, def.Category) {
		return fmt.Errorf("unknown category %q", def.Category)
	}
	if err := validText(def.Title, maxTitleLength); err != nil {
		return fmt.Errorf("title: %w", err)
	}
	if err := validText(def.Summary, maxSummaryLength); err != nil {
		return fmt.Errorf("summary: %w", err)
	}
	if len(def.Techniques) == 0 || honeytoken.ValidateTechniques(def.Techniques) != nil {
		return errors.New("techniques: want at least one distinct technique of the bundled ATT&CK version")
	}
	if err := validActivities(def.EngageActivities); err != nil {
		return err
	}

	if len(def.Honeytokens) == 0 || len(def.Honeytokens) > maxHoneytokens {
		return fmt.Errorf("want 1 to %d honeytokens", maxHoneytokens)
	}
	if len(def.Persona) > maxPersona || len(def.Secrets) > maxSecrets {
		return fmt.Errorf("want at most %d values of the persona and %d secrets", maxPersona, maxSecrets)
	}
	keys := map[string]bool{}
	key := func(group, k string) error {
		if !valueKey.MatchString(k) || keys[group+"."+k] {
			return fmt.Errorf("%s: the key %q is malformed or used twice", group, k)
		}
		keys[group+"."+k] = true
		return nil
	}
	for _, h := range def.Honeytokens {
		if err := key("honeytokens", h.Key); err != nil {
			return err
		}
		if !h.Type.Valid() {
			return fmt.Errorf("honeytoken %s: unknown type %q", h.Key, h.Type)
		}
		if err := validText(h.Label, maxLabelLength); err != nil {
			return fmt.Errorf("honeytoken %s: label: %w", h.Key, err)
		}
		// Applying the deception names the honeytoken after its label.
		for _, lang := range Languages {
			if honeytoken.ValidateName(h.Label[lang]) != nil {
				return fmt.Errorf("honeytoken %s: label: %s is not a valid name of a honeytoken", h.Key, lang)
			}
		}
		if honeytoken.ValidateTechniques(h.Techniques) != nil {
			return fmt.Errorf("honeytoken %s: want up to %d distinct techniques of the bundled ATT&CK version", h.Key, honeytoken.MaxTechniques)
		}
		// Without a severity, the honeytoken has the default of its type;
		// info is only an analyst's judgment of an incident.
		if h.Severity != "" && !h.Severity.IsSuggested() {
			return fmt.Errorf("honeytoken %s: the severity %q is not one of %v", h.Key, h.Severity, severity.Suggested)
		}
	}
	for _, p := range def.Persona {
		if err := key("persona", p.Key); err != nil {
			return err
		}
		// URLs and secrets come from the server, never from the
		// administrator.
		if p.Kind != KindHost && p.Kind != KindName && p.Kind != KindText {
			return fmt.Errorf("persona %s: the kind %q is not host, name or text", p.Key, p.Kind)
		}
		if err := validText(p.Label, maxLabelLength); err != nil {
			return fmt.Errorf("persona %s: label: %w", p.Key, err)
		}
		if p.Example == "" || !validValue(p.Kind, p.Example) {
			return fmt.Errorf("persona %s: want an example of the kind %s", p.Key, p.Kind)
		}
	}
	for _, s := range def.Secrets {
		if err := key("secrets", s.Key); err != nil {
			return err
		}
		if s.Length < minSecretLength || s.Length > maxSecretLength {
			return fmt.Errorf("secret %s: want a length of %d to %d", s.Key, minSecretLength, maxSecretLength)
		}
	}

	if len(def.Artifacts) > maxArtifacts {
		return fmt.Errorf("want at most %d artifacts", maxArtifacts)
	}
	names := map[string]bool{}
	for _, a := range def.Artifacts {
		if !artifactKey.MatchString(a.Key) || len(a.Key) > 64 || keys["artifacts."+a.Key] {
			return fmt.Errorf("artifact %q: the key is malformed or used twice", a.Key)
		}
		keys["artifacts."+a.Key] = true
		// Two names that differ only in case are the same file on Windows
		// and macOS.
		if !fileName.MatchString(a.FileName) || names[strings.ToLower(a.FileName)] {
			return fmt.Errorf("artifact %s: the file name %q is malformed or used twice", a.Key, a.FileName)
		}
		names[strings.ToLower(a.FileName)] = true
		if !a.Format.Valid() {
			return fmt.Errorf("artifact %s: unknown format %q", a.Key, a.Format)
		}
		if a.LineEndings != LF && a.LineEndings != CRLF {
			return fmt.Errorf("artifact %s: the line endings %q are not lf or crlf", a.Key, a.LineEndings)
		}
		if !templateFile.MatchString(a.Template) {
			return fmt.Errorf("artifact %s: the template %q is not the name of a template", a.Key, a.Template)
		}
	}
	for lang, name := range def.Guide {
		if !slices.Contains(Languages, lang) || !templateFile.MatchString(name) {
			return fmt.Errorf("guide: %q is not a language or %q not the name of a template", lang, name)
		}
	}
	if len(def.Guide) != len(Languages) {
		return fmt.Errorf("guide: want a template for each of %v", Languages)
	}
	return nil
}

// validActivities accepts at least one distinct Engage activity of the
// bundled version.
func validActivities(ids []string) error {
	if len(ids) == 0 || len(ids) > 20 {
		return errors.New("engage_activities: want 1 to 20 activities")
	}
	for i, id := range ids {
		if _, ok := engage.Lookup(id); !ok || slices.Contains(ids[:i], id) {
			return fmt.Errorf("engage_activities: %q is unknown or listed twice", id)
		}
	}
	return nil
}

// validText accepts a text in every language of Languages, each of 1 to max
// printable characters on one line without surrounding spaces.
func validText(t Text, maxRunes int) error {
	if len(t) != len(Languages) {
		return fmt.Errorf("want a text in each of %v", Languages)
	}
	for _, lang := range Languages {
		s := t[lang]
		n := utf8.RuneCountInString(s)
		if n < 1 || n > maxRunes || strings.TrimSpace(s) != s || !utf8.ValidString(s) {
			return fmt.Errorf("%s: want 1 to %d characters without surrounding spaces", lang, maxRunes)
		}
		for _, r := range s {
			if !unicode.IsGraphic(r) {
				return fmt.Errorf("%s: contains the character %U", lang, r)
			}
		}
	}
	return nil
}

// maxBytes returns how many bytes the artifact can render at most.
func (a Artifact) maxBytes() int {
	if a.LineEndings == CRLF {
		// Every line feed becomes two bytes.
		return 2 * a.Template.bound
	}
	return a.Template.bound
}

// maxRenderedBytes returns how many bytes applying d can render at most: its
// artifacts and the longest of its guides.
func (d Deception) maxRenderedBytes() int {
	n := 0
	for _, a := range d.Artifacts {
		n += a.maxBytes()
	}
	guide := 0
	for _, t := range d.Guide {
		guide = max(guide, t.bound)
	}
	return n + guide
}

// Reveals returns the first marker that content, a rendered artifact of d,
// contains, or "" if it contains none. The templates of a deception are
// checked when it is loaded; the values that reach an artifact when it is
// applied, such as the persona, the address of the trigger or the zone of a
// DNS honeytoken, are not, so applying checks the result.
func (d Deception) Reveals(content []byte) string {
	return findMarker(string(content), d.ID)
}

// findMarker returns the first marker that the text contains, in any case, or
// "".
// The identifier of the deception is a marker as well: it is the same in
// every installation.
func findMarker(text, id string) string {
	if m := licenseNotice.FindString(text); m != "" {
		return strings.ToLower(m)
	}
	lower := strings.ToLower(text)
	for _, m := range append(slices.Clone(markers), id) {
		if strings.Contains(lower, m) {
			return m
		}
	}
	return ""
}
