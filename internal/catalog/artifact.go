// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"

	"nyktus.org/nyktus/internal/honeytoken"
)

// ArtifactSchemaVersion is the version of the format of an artifact that this
// build reads.
const ArtifactSchemaVersion = 1

// Artifact is a template of a file that a person places to make a scenario
// believable. It exists without a deception: it asks for the values of the
// persona, may generate secrets, and may carry honeytokens in its slots. A
// slot that is bound to a honeytoken makes the file a lure; without one the
// file is pocket litter. An artifact never raises an event itself.
type Artifact struct {
	// ID identifies the artifact, such as "ssh-config". It is the name of its
	// directory.
	ID       string
	Category Category
	Title    Text
	Summary  Text
	// EngageActivities are the Engage activities that placing the artifact
	// carries out.
	EngageActivities []string
	Slots            []Slot
	Persona          []PersonaField
	Secrets          []Secret
	// FileName is the name under which the artifact is downloaded.
	FileName    string
	Format      Format
	LineEndings LineEndings
	Template    *Template
	// Placing tells the administrator where to place the artifact, by
	// language, or is nil.
	Placing map[string]*Template
}

// Slot is a place in an artifact for the trigger of a honeytoken.
type Slot struct {
	// Key names the slot in the template, such as .Honeytokens.JumpHost.Host.
	// A deception that recommends the artifact binds the slot to its
	// honeytoken of the same key.
	Key string
	// Accepts are the types of honeytokens that the slot takes. All of them
	// give the same value: a host name for dns, a URL for web_url and
	// web_image.
	Accepts []honeytoken.Type
	// Optional says that the artifact is valid with the slot empty, as pocket
	// litter. The template references an optional slot only inside {{if}}.
	Optional bool
}

// field returns the name and the kind of the value that the slot gives.
func (s Slot) field() (string, Kind) {
	if s.Accepts[0] == honeytoken.TypeDNS {
		return "Honeytokens." + s.Key + ".Host", KindHost
	}
	return "Honeytokens." + s.Key + ".URL", KindURL
}

// Fields returns the values that the template of the artifact may reference:
// the URL or host name of each slot, each value of the persona and each
// secret.
func (a Artifact) Fields() Fields {
	fields := Fields{}
	for _, s := range a.Slots {
		path, kind := s.field()
		fields[path] = kind
	}
	for _, p := range a.Persona {
		fields["Persona."+p.Key] = p.Kind
	}
	for _, s := range a.Secrets {
		fields["Secrets."+s.Key] = KindSecret
	}
	return fields
}

// optionalFields returns the names of the values of the optional slots.
func (a Artifact) optionalFields() map[string]bool {
	optional := map[string]bool{}
	for _, s := range a.Slots {
		if s.Optional {
			path, _ := s.field()
			optional[path] = true
		}
	}
	return optional
}

// accepts reports whether the slot takes honeytokens of type t.
func (s Slot) accepts(t honeytoken.Type) bool {
	return slices.Contains(s.Accepts, t)
}

// artifactDefinitionFile is the name of the file that describes an artifact in
// its directory.
const artifactDefinitionFile = "artifact.json"

// artifactDefinition is the JSON of an artifact.
type artifactDefinition struct {
	SchemaVersion    int               `json:"schema_version"`
	ID               string            `json:"id"`
	Category         Category          `json:"category"`
	Title            Text              `json:"title"`
	Summary          Text              `json:"summary"`
	EngageActivities []string          `json:"engage_activities"`
	Slots            []slotDef         `json:"slots"`
	Persona          []personaFieldDef `json:"persona"`
	Secrets          []secretDef       `json:"secrets"`
	FileName         string            `json:"file_name"`
	Format           Format            `json:"format"`
	LineEndings      LineEndings       `json:"line_endings"`
	Template         string            `json:"template"`
	Placing          map[string]string `json:"placing"`
}

type slotDef struct {
	Key      string            `json:"key"`
	Accepts  []honeytoken.Type `json:"accepts"`
	Optional bool              `json:"optional"`
}

// ErrInvalidArtifact means that an artifact of the catalog is invalid.
var ErrInvalidArtifact = errors.New("invalid artifact")

// loadArtifact reads, validates and compiles the artifact in the directory dir
// of fsys.
func loadArtifact(fsys fs.FS, dir string) (Artifact, error) {
	fail := func(format string, args ...any) (Artifact, error) {
		return Artifact{}, fmt.Errorf("%w %s: %s", ErrInvalidArtifact, dir, fmt.Sprintf(format, args...))
	}
	if !entryID.MatchString(dir) || len(dir) > maxIDLength {
		return fail("the name of the directory is not a valid identifier")
	}
	files, err := readFiles(fsys, dir, artifactDefinitionFile)
	if err != nil {
		return fail("%v", err)
	}
	raw, ok := files[artifactDefinitionFile]
	if !ok {
		return fail("%s is missing", artifactDefinitionFile)
	}
	var def artifactDefinition
	if err := decodeStrict(raw, &def); err != nil {
		return fail("%s: %v", artifactDefinitionFile, err)
	}
	if def.SchemaVersion != ArtifactSchemaVersion {
		return fail("schema version %d is not supported, want %d", def.SchemaVersion, ArtifactSchemaVersion)
	}
	if def.ID != dir {
		return fail("the identifier %q differs from the name of the directory", def.ID)
	}
	if err := def.validate(); err != nil {
		return fail("%v", err)
	}

	a := Artifact{
		ID: def.ID, Category: def.Category, Title: def.Title, Summary: def.Summary,
		EngageActivities: def.EngageActivities,
		FileName:         def.FileName, Format: def.Format, LineEndings: def.LineEndings,
	}
	for _, s := range def.Slots {
		a.Slots = append(a.Slots, Slot(s))
	}
	for _, p := range def.Persona {
		a.Persona = append(a.Persona, PersonaField(p))
	}
	for _, s := range def.Secrets {
		a.Secrets = append(a.Secrets, Secret(s))
	}
	fields := a.Fields()

	used := map[string]bool{artifactDefinitionFile: true}
	src, ok := files[def.Template]
	if !ok {
		return fail("the template %s is missing", def.Template)
	}
	used[def.Template] = true
	if a.Template, err = compile(path.Join(dir, def.Template), def.Format, string(src), fields, a.optionalFields()); err != nil {
		return fail("%v", err)
	}
	if marker := findMarker(a.Template.static, a.ID); marker != "" {
		return fail("the template contains %q, which reveals the artifact", marker)
	}
	if n := a.maxBytes(); n > MaxOutputBytes {
		return fail("it can render %d bytes, more than %d", n, MaxOutputBytes)
	}

	referenced := map[string]bool{}
	for p := range a.Template.fields {
		referenced[p] = true
	}
	if len(def.Placing) > 0 {
		a.Placing = map[string]*Template{}
		for _, lang := range Languages {
			name := def.Placing[lang]
			src, ok := files[name]
			if !ok {
				return fail("placing %s: the template %s is missing", lang, name)
			}
			used[name] = true
			t, err := Compile(path.Join(dir, name), FormatMarkdown, string(src), fields)
			if err != nil {
				return fail("placing %s: %v", lang, err)
			}
			if t.bound > MaxOutputBytes {
				return fail("placing %s can render %d bytes, more than %d", lang, t.bound, MaxOutputBytes)
			}
			for p := range t.fields {
				referenced[p] = true
			}
			a.Placing[lang] = t
		}
	}
	// A value that nothing references is a mistake: a slot that the file does
	// not name is never placed, and a value of the persona is asked for in
	// vain.
	for _, p := range slices.Sorted(maps.Keys(fields)) {
		if !referenced[p] {
			return fail("no template references .%s", p)
		}
	}
	if err := checkFiles(files, used); err != nil {
		return fail("%v", err)
	}
	return a, nil
}

func (def artifactDefinition) validate() error {
	if !slices.Contains(Categories, def.Category) {
		return fmt.Errorf("unknown category %q", def.Category)
	}
	if err := validText(def.Title, maxTitleLength); err != nil {
		return fmt.Errorf("title: %w", err)
	}
	if err := validText(def.Summary, maxSummaryLength); err != nil {
		return fmt.Errorf("summary: %w", err)
	}
	if err := validActivities(def.EngageActivities); err != nil {
		return err
	}
	if err := def.validateSlots(); err != nil {
		return err
	}
	if err := validPersonaDefs(def.Persona); err != nil {
		return err
	}
	if err := validSecretDefs(def.Secrets); err != nil {
		return err
	}
	if !fileName.MatchString(def.FileName) {
		return fmt.Errorf("the file name %q is malformed", def.FileName)
	}
	if !def.Format.Valid() {
		return fmt.Errorf("unknown format %q", def.Format)
	}
	if def.LineEndings != LF && def.LineEndings != CRLF {
		return fmt.Errorf("the line endings %q are not lf or crlf", def.LineEndings)
	}
	if !templateFile.MatchString(def.Template) {
		return fmt.Errorf("the template %q is not the name of a template", def.Template)
	}
	// Placing comes in both languages or not at all.
	if len(def.Placing) > 0 {
		for lang, name := range def.Placing {
			if !slices.Contains(Languages, lang) || !templateFile.MatchString(name) {
				return fmt.Errorf("placing: %q is not a language or %q not the name of a template", lang, name)
			}
		}
		if len(def.Placing) != len(Languages) {
			return fmt.Errorf("placing: want a template for each of %v", Languages)
		}
	}
	return nil
}

func (def artifactDefinition) validateSlots() error {
	if len(def.Slots) > maxSlots {
		return fmt.Errorf("want at most %d slots", maxSlots)
	}
	seen := map[string]bool{}
	for _, s := range def.Slots {
		if !valueKey.MatchString(s.Key) || seen[s.Key] {
			return fmt.Errorf("slots: the key %q is malformed or used twice", s.Key)
		}
		seen[s.Key] = true
		if len(s.Accepts) == 0 {
			return fmt.Errorf("slot %s: accepts no type of honeytoken", s.Key)
		}
		for i, t := range s.Accepts {
			if !t.Valid() || slices.Contains(s.Accepts[:i], t) {
				return fmt.Errorf("slot %s: the type %q is unknown or listed twice", s.Key, t)
			}
			// A template reads one value of the slot, so every type that the
			// slot takes must give that value.
			if (t == honeytoken.TypeDNS) != (s.Accepts[0] == honeytoken.TypeDNS) {
				return fmt.Errorf("slot %s: dns gives a host name and web_url a URL, so one slot cannot take both", s.Key)
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

// Values returns the values that the template of the artifact references: the
// URL or host name of every slot, taken from the honeytoken that is placed
// under the key of the slot, the values of its persona and its secrets. A
// slot without a placed honeytoken is empty if it is optional; a required one
// fails with ErrInvalidValue, as does a value of the persona or a secret that
// is missing or empty.
func (a Artifact) Values(placed map[string]Placed, persona, secrets map[string]string) (map[string]string, error) {
	values := map[string]string{}
	for _, s := range a.Slots {
		path, _ := s.field()
		p, ok := placed[s.Key]
		v := p.URL
		if s.Accepts[0] == honeytoken.TypeDNS {
			v = p.Host
		}
		if (!ok || v == "") && !s.Optional {
			return nil, fmt.Errorf("%w: the slot %s needs a honeytoken", ErrInvalidValue, s.Key)
		}
		values[path] = v
	}
	// The persona and the secrets are never optional: an empty value would
	// render as an empty password or domain.
	for _, p := range a.Persona {
		v := persona[p.Key]
		if v == "" {
			return nil, fmt.Errorf("%w: the persona %s needs a value", ErrInvalidValue, p.Key)
		}
		values["Persona."+p.Key] = v
	}
	for _, s := range a.Secrets {
		v := secrets[s.Key]
		if v == "" {
			return nil, fmt.Errorf("%w: the secret %s needs a value", ErrInvalidValue, s.Key)
		}
		values["Secrets."+s.Key] = v
	}
	return values, nil
}

// Render renders the artifact with values, as Template.Render describes, with
// its line endings. No value contains a line break, so every line feed of the
// output comes from the template. It fails with a RevealError if the result
// contains a marker, also the identifier of the artifact and the identifiers
// deceptionIDs of the deceptions that it is rendered for: the templates are
// checked when the catalog is loaded, but the values that reach the file when
// it is applied, such as the persona, the address of the trigger and the zone
// of a DNS honeytoken, are not.
func (a Artifact) Render(values map[string]string, deceptionIDs ...string) ([]byte, error) {
	out, err := a.Template.Render(values)
	if err != nil {
		return nil, err
	}
	if a.LineEndings == CRLF {
		out = bytes.ReplaceAll(out, []byte("\n"), []byte("\r\n"))
	}
	if marker := a.Reveals(out, deceptionIDs...); marker != "" {
		return nil, &RevealError{Artifact: a.ID, Marker: marker}
	}
	return out, nil
}

// Reveals returns the first marker that content, a rendered artifact, contains,
// or "" if it contains none, as Render checks it: the identifier of the
// artifact and the identifiers deceptionIDs are markers as well.
func (a Artifact) Reveals(content []byte, deceptionIDs ...string) string {
	return findMarker(string(content), append([]string{a.ID}, deceptionIDs...)...)
}

// bindsTo returns the first reason why a deception with honeytokens cannot
// recommend the artifact, or "": a required slot without a honeytoken of its
// key, or a honeytoken of another type than the slot takes.
func (a Artifact) bindsTo(honeytokens []Honeytoken) string {
	for _, s := range a.Slots {
		i := slices.IndexFunc(honeytokens, func(h Honeytoken) bool { return h.Key == s.Key })
		switch {
		case i < 0 && !s.Optional:
			return fmt.Sprintf("the slot %s has no honeytoken of that key", s.Key)
		case i >= 0 && !s.accepts(honeytokens[i].Type):
			return fmt.Sprintf("the slot %s does not take honeytokens of the type %s", s.Key, honeytokens[i].Type)
		}
	}
	return ""
}
