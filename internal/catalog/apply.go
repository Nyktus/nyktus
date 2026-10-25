// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"nyktus.org/nyktus/internal/honeytoken"
)

// Errors of applying a deception.
var (
	// ErrInvalidPersona means that the values of the persona do not match
	// those that the deception asks for.
	ErrInvalidPersona = errors.New("invalid persona")
	// ErrArtifactReveals means that a rendered artifact contains a marker.
	ErrArtifactReveals = errors.New("artifact reveals what it is")
	// ErrUnknownLanguage means that the deception has no guide in a
	// language.
	ErrUnknownLanguage = errors.New("unknown language")
)

// PersonaError says which value of the persona is wrong. Its message names
// the key and the kind only, never the value, and can be shown to the
// administrator.
type PersonaError struct {
	Key    string
	Reason string
}

func (e *PersonaError) Error() string {
	return fmt.Sprintf("persona %s: %s", e.Key, e.Reason)
}

// Is makes the error match ErrInvalidPersona.
func (e *PersonaError) Is(target error) bool {
	return target == ErrInvalidPersona
}

// RevealError says which artifact contains which marker.
type RevealError struct {
	Artifact string
	Marker   string
}

func (e *RevealError) Error() string {
	return fmt.Sprintf("artifact %s contains %q", e.Artifact, e.Marker)
}

// Is makes the error match ErrArtifactReveals.
func (e *RevealError) Is(target error) bool {
	return target == ErrArtifactReveals
}

// kindRules describe the kinds of values of the persona, for the messages of
// PersonaError.
var kindRules = map[Kind]string{
	KindHost: "must be a host name of lowercase letters, digits, hyphens and dots",
	KindName: "must be an account name of letters, digits, dots, hyphens and underscores, up to 64 characters, " +
		"starting with a letter or digit",
	KindText: fmt.Sprintf("must be text on one line of up to %d printable characters", MaxTextLength),
}

// ValidatePersona accepts persona if it holds a value for every value of the
// persona of d and nothing else, each not empty and of its kind. A deception
// has no defaults, so every value is required.
func (d Deception) ValidatePersona(persona map[string]string) error {
	return validatePersona(d.Persona, persona, "deception")
}

// ValidatePersona accepts persona if it holds a value for every value of the
// persona of a and nothing else, as Deception.ValidatePersona does.
func (a Artifact) ValidatePersona(persona map[string]string) error {
	return validatePersona(a.Persona, persona, "artifact")
}

func validatePersona(fields []PersonaField, persona map[string]string, owner string) error {
	for _, p := range fields {
		v, ok := persona[p.Key]
		switch {
		case !ok || v == "":
			return &PersonaError{Key: p.Key, Reason: "is required"}
		case !validValue(p.Kind, v):
			return &PersonaError{Key: p.Key, Reason: kindRules[p.Kind]}
		}
	}
	return validatePersonaKeys(fields, owner, persona)
}

// validatePersonaKeys accepts persona if it names no key that is not in
// fields.
func validatePersonaKeys(fields []PersonaField, owner string, persona map[string]string) error {
	keys := make([]string, 0, len(persona))
	for k := range persona {
		keys = append(keys, k)
	}
	// The first unknown key in order, so that the message does not change
	// between requests.
	slices.Sort(keys)
	for _, k := range keys {
		if !slices.ContainsFunc(fields, func(p PersonaField) bool { return p.Key == k }) {
			// The key comes from the request; it is named only if it has
			// the form of a key, so that the error does not echo any text.
			if !valueKey.MatchString(k) {
				k = "with a malformed key"
			}
			return &PersonaError{Key: k, Reason: "is not a value of the persona of this " + owner}
		}
	}
	return nil
}

// secretAlphabet are the characters of a secret: letters and digits, which no
// supported format treats specially.
const secretAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// NewSecrets returns a new random value for every secret of a, of its length,
// from crypto/rand.
func (a Artifact) NewSecrets() map[string]string {
	secrets := make(map[string]string, len(a.Secrets))
	for _, s := range a.Secrets {
		secrets[s.Key] = newSecret(s.Length)
	}
	return secrets
}

// NewSecrets returns new secrets for the artifacts of d that have any, by the
// identifier of the artifact. Every artifact generates its own, so a password
// that two files of a deception name is not the same in both.
func (d Deception) NewSecrets() map[string]map[string]string {
	secrets := map[string]map[string]string{}
	for _, a := range d.Artifacts {
		if len(a.Secrets) > 0 {
			secrets[a.ID] = a.NewSecrets()
		}
	}
	return secrets
}

func newSecret(length int) string {
	out := make([]byte, 0, length)
	var b [1]byte
	for len(out) < length {
		// crypto/rand.Read never fails; it crashes the program instead.
		_, _ = rand.Read(b[:])
		// Bytes beyond the largest multiple of the alphabet would favor its
		// first characters.
		if int(b[0]) >= 256-256%len(secretAlphabet) {
			continue
		}
		out = append(out, secretAlphabet[int(b[0])%len(secretAlphabet)])
	}
	return string(out)
}

// Placed is what a honeytoken of a deception is placed as: the URL of a
// honeytoken of the type web_url or web_image, or a host name of one of the
// type dns.
type Placed struct {
	URL  string
	Host string
}

// Values returns the values that the guide of d references: the URL or host
// name of every honeytoken, keyed by its key, and the persona.
func (d Deception) Values(placed map[string]Placed, persona map[string]string) map[string]string {
	values := map[string]string{}
	for _, h := range d.Honeytokens {
		if h.Type == honeytoken.TypeDNS {
			values["Honeytokens."+h.Key+".Host"] = placed[h.Key].Host
		} else {
			values["Honeytokens."+h.Key+".URL"] = placed[h.Key].URL
		}
	}
	for _, p := range d.Persona {
		values["Persona."+p.Key] = persona[p.Key]
	}
	return values
}

// RenderedArtifact is an artifact of the catalog with its content and the text
// that says where to place it.
type RenderedArtifact struct {
	Artifact
	Content []byte
	// Placing is empty if the artifact has no text for the language.
	Placing string
}

// RenderArtifact renders the artifact a in lang, with the honeytokens placed,
// the persona and the secrets of the artifact, and the text that says where to
// place it. The identifiers deceptionIDs of the deceptions of the scenario are
// markers like the one of the artifact, see Artifact.Render. It fails with a
// RevealError if the file contains a marker.
func RenderArtifact(a Artifact, placed map[string]Placed, persona, secrets map[string]string, lang string, deceptionIDs ...string) (RenderedArtifact, error) {
	values, err := a.Values(placed, persona, secrets)
	if err != nil {
		return RenderedArtifact{}, fmt.Errorf("render artifact %s: %w", a.ID, err)
	}
	content, err := a.Render(values, deceptionIDs...)
	if err != nil {
		var re *RevealError
		if errors.As(err, &re) {
			return RenderedArtifact{}, err
		}
		return RenderedArtifact{}, fmt.Errorf("render artifact %s: %w", a.ID, err)
	}
	r := RenderedArtifact{Artifact: a, Content: content}
	if t := a.Placing[lang]; t != nil {
		placing, err := t.Render(values)
		if err != nil {
			return RenderedArtifact{}, fmt.Errorf("render placing %s of %s: %w", lang, a.ID, err)
		}
		r.Placing = string(placing)
	}
	return r, nil
}

// Rendered is what applying a deception renders.
type Rendered struct {
	Artifacts []RenderedArtifact
	// Guide is the guide in the language of the application.
	Guide []byte
}

// Render renders the artifacts of d and its guide in lang. placed holds the
// honeytokens by key, persona the values of the persona and secrets those of
// each artifact by its identifier, as NewSecrets returns them. It fails with a
// RevealError if an artifact contains a marker, and with ErrUnknownLanguage if
// d has no guide in lang.
func (d Deception) Render(placed map[string]Placed, persona map[string]string, secrets map[string]map[string]string, lang string) (Rendered, error) {
	return d.RenderSelected(d.Artifacts, placed, persona, secrets, lang)
}

// RenderSelected renders the guide of d in lang, and of its artifacts only
// those in artifacts, as Render does.
func (d Deception) RenderSelected(artifacts []Artifact, placed map[string]Placed, persona map[string]string, secrets map[string]map[string]string, lang string) (Rendered, error) {
	guide, ok := d.Guide[lang]
	if !ok {
		return Rendered{}, fmt.Errorf("%w: %q", ErrUnknownLanguage, lang)
	}
	var r Rendered
	for _, a := range artifacts {
		rendered, err := RenderArtifact(a, placed, persona, secrets[a.ID], lang, d.ID)
		if err != nil {
			return Rendered{}, fmt.Errorf("render artifacts of %s: %w", d.ID, err)
		}
		r.Artifacts = append(r.Artifacts, rendered)
	}
	var err error
	if r.Guide, err = guide.Render(d.Values(placed, persona)); err != nil {
		return Rendered{}, fmt.Errorf("render guide %s of %s: %w", lang, d.ID, err)
	}
	return r, nil
}

// Engage activities that follow from what a scenario holds. A deception names
// the activities of its story in its entry; these depend on how it is applied.
const (
	ActivityLures             = "EAC0005"
	ActivityPocketLitter      = "EAC0011"
	ActivityPersonas          = "EAC0012"
	ActivityArtifactDiversity = "EAC0022"
)

// Lure reports whether a bound slot makes the artifact the carrier of a lure,
// placed with the honeytokens placed. Engage tells a lure from pocket litter
// by intent, not by kind of file: a file that carries a trigger expects an
// action, one that does not only supports the story.
func (a Artifact) Lure(placed map[string]Placed) bool {
	return slices.ContainsFunc(a.Slots, func(s Slot) bool { return s.placedValue(placed) != "" })
}

// Activities returns the Engage activities that a scenario carries out when it
// holds the artifacts placed with the honeytokens placed and a persona: base,
// the activities of the story, then lures for every artifact that carries a
// honeytoken, pocket litter for every one that does not, artifact diversity
// for files of more than one format, and personas for a persona that is not
// empty. Each appears once.
func Activities(base []string, artifacts []Artifact, placed map[string]Placed, persona map[string]string) []string {
	out := slices.Clone(base)
	add := func(id string) {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	formats := map[Format]bool{}
	for _, a := range artifacts {
		formats[a.Format] = true
		if a.Lure(placed) {
			add(ActivityLures)
		} else {
			add(ActivityPocketLitter)
		}
	}
	if len(formats) > 1 {
		add(ActivityArtifactDiversity)
	}
	if len(persona) > 0 {
		add(ActivityPersonas)
	}
	return out
}

// ErrPersonaConflict means that a value of the persona differs from the one
// the scenario already has.
var ErrPersonaConflict = errors.New("persona value conflicts with the scenario")

// PersonaConflictError says which key of the persona has another value in the
// scenario. Its message names the key only, never either value: the stored one
// is inventory, and the given one is not echoed.
type PersonaConflictError struct {
	Key string
}

func (e *PersonaConflictError) Error() string {
	return fmt.Sprintf("persona %s: the scenario already has another value", e.Key)
}

// Is makes the error match ErrPersonaConflict.
func (e *PersonaConflictError) Is(target error) bool {
	return target == ErrPersonaConflict
}

// MaxPersonaBytes is the largest persona of a scenario, as its JSON, as the
// database enforces it.
const MaxPersonaBytes = 16384

// MergePersona returns the persona of a scenario that holds stored after the
// deception d joins it with the values given. The persona only grows: a key
// that is new is added, a value that is there stays, and a value that is left
// out is the stored one. It fails with a PersonaError for a key that d does not
// ask for, a value that is missing or not of the kind d gives the key, or a
// persona that gets too large, and with a PersonaConflictError for a given
// value that differs from the stored one. added lists the new keys in order.
func (d Deception) MergePersona(stored, given map[string]string) (merged map[string]string, added []string, err error) {
	return mergePersona(d.Persona, "deception", stored, given)
}

// MergePersona merges the persona of the artifact a into that of a scenario,
// as Deception.MergePersona does.
func (a Artifact) MergePersona(stored, given map[string]string) (merged map[string]string, added []string, err error) {
	return mergePersona(a.Persona, "artifact", stored, given)
}

func mergePersona(fields []PersonaField, owner string, stored, given map[string]string) (map[string]string, []string, error) {
	// An unknown key is named in the same way as in validatePersona.
	if err := validatePersonaKeys(fields, owner, given); err != nil {
		return nil, nil, err
	}
	merged := make(map[string]string, len(stored)+len(fields))
	for k, v := range stored {
		merged[k] = v
	}
	var added []string
	for _, f := range fields {
		g, hasGiven := given[f.Key]
		s, hasStored := stored[f.Key]
		v := s
		switch {
		case hasGiven && hasStored && g != s:
			return nil, nil, &PersonaConflictError{Key: f.Key}
		case hasGiven:
			v = g
		case !hasStored:
			return nil, nil, &PersonaError{Key: f.Key, Reason: "is required"}
		}
		if v == "" {
			return nil, nil, &PersonaError{Key: f.Key, Reason: "is required"}
		}
		if !validValue(f.Kind, v) {
			return nil, nil, &PersonaError{Key: f.Key, Reason: kindRules[f.Kind]}
		}
		if !hasStored {
			added = append(added, f.Key)
		}
		merged[f.Key] = v
	}
	if b, err := json.Marshal(merged); err != nil || len(b) > MaxPersonaBytes {
		return nil, nil, &PersonaError{Key: "", Reason: "the persona of the scenario would be too large"}
	}
	return merged, added, nil
}
