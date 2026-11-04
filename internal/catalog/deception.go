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

	"nyktus.org/nyktus/internal/honeypot"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/severity"
)

// SchemaVersion is the version of the format of a deception that this build
// reads.
const SchemaVersion = 3

// Deception is a guide for an administrator: the story that it tells and what
// it detects, the instructions to carry it out, the honeytokens and honeypots
// that it asks for and example files. Nothing of it is rendered, created or
// stored when it is applied, except what the administrator chooses to create.
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
	// EngageActivities are the Engage activities that the story carries out,
	// such as EAC0005 (Lures) or, for files without a honeytoken, EAC0011
	// (Pocket Litter).
	EngageActivities []string
	// Honeytokens and Honeypots are the slots of the story: what the guide
	// asks the administrator to create.
	Honeytokens []HoneytokenSlot
	Honeypots   []HoneypotSlot
	Files       []File
	// Guide is the instruction in Markdown, by language.
	Guide map[string]string
}

// HoneytokenSlot is a honeytoken that the guide asks for. Its label names the
// honeytoken when it is created.
type HoneytokenSlot struct {
	Label      Text
	Type       honeytoken.Type
	Techniques []string
	// Severity is the severity of the honeytoken: the one that the deception
	// chooses, or the default of its type.
	Severity severity.Level
}

// HoneypotSlot is a honeypot that the guide asks for. Its label names the
// honeypot when it is created.
type HoneypotSlot struct {
	Label   Text
	Service honeypot.Service
}

// File is an example file of a deception, static text that the administrator
// adapts and places.
type File struct {
	// Name is the name under which the file is downloaded.
	Name    string
	Format  Format
	Content []byte
}

// File returns the file name of the deception.
func (d Deception) File(name string) (File, bool) {
	i := slices.IndexFunc(d.Files, func(f File) bool { return f.Name == name })
	if i < 0 {
		return File{}, false
	}
	return d.Files[i], true
}

// deceptionDefinitionFile is the name of the file that describes a deception
// in its directory, and filesDir the directory of its example files.
const (
	deceptionDefinitionFile = "deception.json"
	filesDir                = "files"
)

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
	Honeypots        []honeypotDef     `json:"honeypots"`
	Files            []fileDef         `json:"files"`
	Guide            map[string]string `json:"guide"`
}

type (
	honeytokenDef struct {
		Label      Text            `json:"label"`
		Type       honeytoken.Type `json:"type"`
		Techniques []string        `json:"techniques"`
		Severity   severity.Level  `json:"severity"`
	}
	honeypotDef struct {
		Label   Text             `json:"label"`
		Service honeypot.Service `json:"service"`
	}
	fileDef struct {
		Name   string `json:"name"`
		Format Format `json:"format"`
		File   string `json:"file"`
	}
)

// ErrInvalidDeception means that a deception of the catalog is invalid.
var ErrInvalidDeception = errors.New("invalid deception")

// loadDeception reads and validates the deception in the directory dir of
// fsys.
func loadDeception(fsys fs.FS, dir string) (Deception, error) {
	fail := func(format string, args ...any) (Deception, error) {
		return Deception{}, fmt.Errorf("%w %s: %s", ErrInvalidDeception, dir, fmt.Sprintf(format, args...))
	}
	if !entryID.MatchString(dir) || len(dir) > maxIDLength {
		return fail("the name of the directory is not a valid identifier")
	}
	top, err := readDir(fsys, dir, true, func(name string) bool { return name == deceptionDefinitionFile || guideFile.MatchString(name) })
	if err != nil {
		return fail("%v", err)
	}
	raw, ok := top[deceptionDefinitionFile]
	if !ok {
		return fail("%s is missing", deceptionDefinitionFile)
	}
	var def deceptionDefinition
	if err := decodeStrict(raw, &def); err != nil {
		return fail("%s: %v", deceptionDefinitionFile, err)
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
		Guide: map[string]string{},
	}
	for _, h := range def.Honeytokens {
		level := h.Severity
		if level == "" {
			level = h.Type.DefaultSeverity()
		}
		d.Honeytokens = append(d.Honeytokens, HoneytokenSlot{Label: h.Label, Type: h.Type, Techniques: h.Techniques, Severity: level})
	}
	for _, h := range def.Honeypots {
		d.Honeypots = append(d.Honeypots, HoneypotSlot(h))
	}

	used := map[string]bool{deceptionDefinitionFile: true}
	for _, lang := range Languages {
		name := def.Guide[lang]
		src, ok := top[name]
		if !ok {
			return fail("guide %s: the file %s is missing", lang, name)
		}
		used[name] = true
		if err := validContent(src); err != nil {
			return fail("guide %s: %v", lang, err)
		}
		if reason := placeholdersFit(string(src), d.Honeytokens); reason != "" {
			return fail("guide %s: %s", lang, reason)
		}
		d.Guide[lang] = string(src)
	}
	for _, name := range slices.Sorted(maps.Keys(top)) {
		if !used[name] {
			return fail("the file %s is not referenced", name)
		}
	}

	// The directory of the files may be missing: Git keeps no empty directory.
	// What it holds must be listed, and what is listed must be in it.
	var examples map[string][]byte
	if _, statErr := fs.Stat(fsys, path.Join(dir, filesDir)); !errors.Is(statErr, fs.ErrNotExist) {
		if examples, err = readDir(mustSub(fsys, dir), filesDir, false, fileName.MatchString); err != nil {
			return fail("%v", err)
		}
	}
	// Two names that differ only in case are the same file on Windows and
	// macOS, so downloads would replace each other.
	names := map[string]bool{}
	usedFiles := map[string]bool{}
	for _, f := range def.Files {
		if names[strings.ToLower(f.Name)] {
			return fail("file %s: the name is used twice", f.Name)
		}
		names[strings.ToLower(f.Name)] = true
		content, ok := examples[f.File]
		if !ok || usedFiles[f.File] {
			return fail("file %s: %s is missing in %s or used twice", f.Name, f.File, filesDir)
		}
		usedFiles[f.File] = true
		if err := validContent(content); err != nil {
			return fail("file %s: %v", f.Name, err)
		}
		if marker := findMarker(f.Name+"\n"+string(content), d.ID); marker != "" {
			return fail("file %s contains %q, which reveals what it is", f.Name, marker)
		}
		if reason := placeholdersFit(string(content), d.Honeytokens); reason != "" {
			return fail("file %s: %s", f.Name, reason)
		}
		d.Files = append(d.Files, File{Name: f.Name, Format: f.Format, Content: content})
	}
	for _, name := range slices.Sorted(maps.Keys(examples)) {
		if !usedFiles[name] {
			return fail("the file %s/%s is not referenced", filesDir, name)
		}
	}
	return d, nil
}

// placeholdersFit returns what is wrong if a text names a placeholder that does
// not fit the honeytokens of the deception, or "": one for a kind of honeytoken
// that the deception does not have, one that names a slot where the deception
// has one honeytoken of the kind, or one that does not where it has several.
// Slots have no keys, so which slot a name means is not checked: the guide says
// it.
func placeholdersFit(text string, slots []HoneytokenSlot) string {
	var dns, urls int
	for _, s := range slots {
		if s.Type == honeytoken.TypeDNS {
			dns++
		} else {
			urls++
		}
	}
	for _, m := range placeholder.FindAllStringSubmatch(text, -1) {
		word, kind, suffix := m[0], m[1], m[2]
		count := dns
		if kind == "URL" {
			count = urls
		}
		switch {
		case count == 0:
			return word + " stands for a kind of honeytoken that the deception does not have"
		case count == 1 && suffix != "":
			return word + " names a slot, but the deception has one honeytoken of that kind"
		case count > 1 && suffix == "":
			return fmt.Sprintf("%s does not say which of the %d honeytokens of that kind it stands for", word, count)
		}
	}
	return ""
}

// readDir reads the regular files of the directory dir of fsys, each at most
// MaxFileBytes. The directory holds nothing else but the entries that the
// function ok accepts by name, and the directory filesDir if skipFiles says
// that it is the directory of a deception.
func readDir(fsys fs.FS, dir string, skipFiles bool, ok func(name string) bool) (map[string][]byte, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	files := make(map[string][]byte, len(entries))
	for _, e := range entries {
		name := e.Name()
		if skipFiles && e.IsDir() && name == filesDir {
			continue
		}
		if !e.Type().IsRegular() || !ok(name) {
			return nil, fmt.Errorf("%s/%s is not a file that a deception may hold", dir, name)
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		if info.Size() > MaxFileBytes {
			return nil, fmt.Errorf("%s is larger than %d bytes", name, MaxFileBytes)
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, name))
		if err != nil {
			return nil, err
		}
		files[name] = b
	}
	return files, nil
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
	if len(def.Honeytokens) > maxHoneytokens || len(def.Honeypots) > maxHoneypots {
		return fmt.Errorf("want up to %d honeytokens and %d honeypots", maxHoneytokens, maxHoneypots)
	}
	if len(def.Honeytokens)+len(def.Honeypots) == 0 {
		return errors.New("want a honeytoken or a honeypot: a deception without one detects nothing")
	}
	for i, h := range def.Honeytokens {
		if !h.Type.Valid() {
			return fmt.Errorf("honeytoken %d: unknown type %q", i+1, h.Type)
		}
		if err := validText(h.Label, maxLabelLength); err != nil {
			return fmt.Errorf("honeytoken %d: label: %w", i+1, err)
		}
		// Creating the honeytoken names it after its label.
		for _, lang := range Languages {
			if honeytoken.ValidateName(h.Label[lang]) != nil {
				return fmt.Errorf("honeytoken %d: label: %s is not a valid name of a honeytoken", i+1, lang)
			}
		}
		if honeytoken.ValidateTechniques(h.Techniques) != nil {
			return fmt.Errorf("honeytoken %d: want up to %d distinct techniques of the bundled ATT&CK version", i+1, honeytoken.MaxTechniques)
		}
		// Without a severity, the honeytoken has the default of its type;
		// info is only an analyst's judgment of an incident.
		if h.Severity != "" && !h.Severity.IsSuggested() {
			return fmt.Errorf("honeytoken %d: the severity %q is not one of %v", i+1, h.Severity, severity.Suggested)
		}
	}
	for i, h := range def.Honeypots {
		if !h.Service.Valid() {
			return fmt.Errorf("honeypot %d: unknown service %q", i+1, h.Service)
		}
		if err := validText(h.Label, maxLabelLength); err != nil {
			return fmt.Errorf("honeypot %d: label: %w", i+1, err)
		}
		for _, lang := range Languages {
			if honeypot.ValidateName(h.Label[lang]) != nil {
				return fmt.Errorf("honeypot %d: label: %s is not a valid name of a honeypot", i+1, lang)
			}
		}
	}
	for _, lang := range Languages {
		if dup := duplicateLabel(def, lang); dup != "" {
			return fmt.Errorf("two slots have the label %q in %s, which would give the resources one name", dup, lang)
		}
	}
	if len(def.Files) > maxFiles {
		return fmt.Errorf("want at most %d files", maxFiles)
	}
	for _, f := range def.Files {
		if !fileName.MatchString(f.Name) || !fileName.MatchString(f.File) || reservedName.MatchString(f.Name) || !f.Format.Valid() {
			return fmt.Errorf("file %q: want a name that every system accepts, a file in %s and a known format", f.Name, filesDir)
		}
	}
	for lang, name := range def.Guide {
		if !slices.Contains(Languages, lang) || !guideFile.MatchString(name) {
			return fmt.Errorf("guide: %q is not a language or %q not the name of a file", lang, name)
		}
	}
	if len(def.Guide) != len(Languages) {
		return fmt.Errorf("guide: want a file for each of %v", Languages)
	}
	if def.Guide["en"] == def.Guide["de"] {
		return errors.New("guide: both languages name the same file")
	}
	return nil
}

// duplicateLabel returns a label in the language that two honeytokens or two
// honeypots of the definition share, or "". A honeytoken and a honeypot may
// share one: they are different kinds of resources.
func duplicateLabel(def deceptionDefinition, lang string) string {
	seen := map[string]bool{}
	for _, h := range def.Honeytokens {
		if seen[h.Label[lang]] {
			return h.Label[lang]
		}
		seen[h.Label[lang]] = true
	}
	seen = map[string]bool{}
	for _, h := range def.Honeypots {
		if seen[h.Label[lang]] {
			return h.Label[lang]
		}
		seen[h.Label[lang]] = true
	}
	return ""
}
