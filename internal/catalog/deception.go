// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"

	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/severity"
)

// DeceptionSchemaVersion is the version of the format of a deception that this
// build reads.
const DeceptionSchemaVersion = 2

// Deception is a story of a scenario: the honeytokens it creates, the values
// an administrator provides, the artifacts that it recommends and the guide
// that explains the story and what limits its trigger has.
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
	// EngageActivities are the Engage activities of the scenario that applying
	// the deception creates, such as EAC0005 (Lures).
	EngageActivities []string
	Honeytokens      []Honeytoken
	// Persona holds the values that the administrator provides. It includes
	// those of the recommended artifacts.
	Persona []PersonaField
	// Artifacts are the artifacts that applying the deception renders, in
	// order.
	Artifacts []Artifact
	// Guide explains the story to the administrator, by language.
	Guide map[string]*Template
}

// Honeytoken is a honeytoken that applying a deception creates.
type Honeytoken struct {
	// Key names the honeytoken in the guide, such as .Honeytokens.JumpHost.Host,
	// and binds it to the slots of the recommended artifacts that have the
	// same key.
	Key        string
	Type       honeytoken.Type
	Label      Text
	Techniques []string
	// Severity is the severity of the honeytoken: the one that the deception
	// chooses, or the default of its type.
	Severity severity.Level
}

// MaxRenderedBytes bounds what applying a deception renders: its artifacts and
// its guide in one language, with every value at its longest. Applying a
// deception stores all of it in one transaction.
const MaxRenderedBytes = 4 << 20

// deceptionDefinitionFile is the name of the file that describes a deception
// in its directory.
const deceptionDefinitionFile = "deception.json"

// deceptionDefinition is the JSON of a deception.
type deceptionDefinition struct {
	SchemaVersion    int               `json:"schema_version"`
	ID               string            `json:"id"`
	Category         Category          `json:"category"`
	Title            Text              `json:"title"`
	Summary          Text              `json:"summary"`
	Techniques       []string          `json:"techniques"`
	EngageActivities []string          `json:"engage_activities"`
	Honeytokens      []honeytokenDef   `json:"honeytokens"`
	Persona          []personaFieldDef `json:"persona"`
	Artifacts        []string          `json:"artifacts"`
	Guide            map[string]string `json:"guide"`
}

type honeytokenDef struct {
	Key        string          `json:"key"`
	Type       honeytoken.Type `json:"type"`
	Label      Text            `json:"label"`
	Techniques []string        `json:"techniques"`
	Severity   severity.Level  `json:"severity"`
}

// ErrInvalidDeception means that a deception of the catalog is invalid.
var ErrInvalidDeception = errors.New("invalid deception")

// loadDeception reads, validates and compiles the deception in the directory
// dir of fsys. artifacts are the artifacts of the catalog by identifier, from
// which the deception takes the ones it recommends.
func loadDeception(fsys fs.FS, dir string, artifacts map[string]Artifact) (Deception, error) {
	fail := func(format string, args ...any) (Deception, error) {
		return Deception{}, fmt.Errorf("%w %s: %s", ErrInvalidDeception, dir, fmt.Sprintf(format, args...))
	}
	if !entryID.MatchString(dir) || len(dir) > maxIDLength {
		return fail("the name of the directory is not a valid identifier")
	}
	files, err := readFiles(fsys, dir, deceptionDefinitionFile)
	if err != nil {
		return fail("%v", err)
	}
	raw, ok := files[deceptionDefinitionFile]
	if !ok {
		return fail("%s is missing", deceptionDefinitionFile)
	}
	var def deceptionDefinition
	if err := decodeStrict(raw, &def); err != nil {
		return fail("%s: %v", deceptionDefinitionFile, err)
	}
	if def.SchemaVersion != DeceptionSchemaVersion {
		return fail("schema version %d is not supported, want %d", def.SchemaVersion, DeceptionSchemaVersion)
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

	// The honeytokens and the persona that a recommended artifact uses are
	// referenced by it, so the guide need not name them.
	referenced := map[string]bool{}
	fileNames := map[string]string{}
	for _, id := range def.Artifacts {
		a, ok := artifacts[id]
		if !ok {
			return fail("artifact %s: not in the catalog", id)
		}
		// Two names that differ only in case are the same file on Windows
		// and macOS, so the downloads of the scenario would replace each
		// other.
		lower := strings.ToLower(a.FileName)
		if other, dup := fileNames[lower]; dup {
			return fail("artifact %s: the file name %q is also that of artifact %s", id, a.FileName, other)
		}
		fileNames[lower] = id
		if reason := a.bindsTo(d.Honeytokens); reason != "" {
			return fail("artifact %s: %s", id, reason)
		}
		for _, p := range a.Persona {
			i := slices.IndexFunc(d.Persona, func(q PersonaField) bool { return q.Key == p.Key })
			if i < 0 || d.Persona[i].Kind != p.Kind {
				return fail("artifact %s: the persona %s of kind %s is not a value of the deception", id, p.Key, p.Kind)
			}
			referenced["Persona."+p.Key] = true
		}
		for _, s := range a.Slots {
			if slices.ContainsFunc(d.Honeytokens, func(h Honeytoken) bool { return h.Key == s.Key }) {
				p, _ := s.field()
				referenced[p] = true
			}
		}
		if marker := findMarker(a.Template.static, d.ID); marker != "" {
			return fail("artifact %s: the template contains %q, which reveals the artifact", id, marker)
		}
		d.Artifacts = append(d.Artifacts, a)
	}

	used := map[string]bool{deceptionDefinitionFile: true}
	fields := d.Fields()
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
		for p := range t.fields {
			referenced[p] = true
		}
	}
	// Every file is stored as one value of at most MaxOutputBytes; the guide
	// is bounded here, the artifacts when they are loaded.
	for lang, t := range d.Guide {
		if t.bound > MaxOutputBytes {
			return fail("guide %s can render %d bytes, more than %d", lang, t.bound, MaxOutputBytes)
		}
	}
	if n := d.maxRenderedBytes(); n > MaxRenderedBytes {
		return fail("its artifacts and guide can render %d bytes, more than %d", n, MaxRenderedBytes)
	}
	// A value that nothing references is a mistake: a honeytoken that no file
	// names is never placed, and a value of the persona is asked for in vain.
	for _, p := range slices.Sorted(maps.Keys(fields)) {
		if !referenced[p] {
			return fail("no template references .%s", p)
		}
	}
	if err := checkFiles(files, used); err != nil {
		return fail("%v", err)
	}
	return d, nil
}

// Fields returns the values that the guide of d may reference: the URL or host
// name of each honeytoken and each value of the persona. The artifacts have
// fields of their own.
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
	return fields
}

func (def deceptionDefinition) validate() error {
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
	seen := map[string]bool{}
	for _, h := range def.Honeytokens {
		if !valueKey.MatchString(h.Key) || seen[h.Key] {
			return fmt.Errorf("honeytokens: the key %q is malformed or used twice", h.Key)
		}
		seen[h.Key] = true
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
	if err := validPersonaDefs(def.Persona); err != nil {
		return err
	}

	if len(def.Artifacts) > maxArtifacts {
		return fmt.Errorf("want at most %d artifacts", maxArtifacts)
	}
	for i, id := range def.Artifacts {
		if !entryID.MatchString(id) || len(id) > maxIDLength || slices.Contains(def.Artifacts[:i], id) {
			return fmt.Errorf("artifacts: %q is malformed or listed twice", id)
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
