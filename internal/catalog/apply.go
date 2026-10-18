// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"crypto/rand"
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
	for _, p := range d.Persona {
		v, ok := persona[p.Key]
		switch {
		case !ok || v == "":
			return &PersonaError{Key: p.Key, Reason: "is required"}
		case !validValue(p.Kind, v):
			return &PersonaError{Key: p.Key, Reason: kindRules[p.Kind]}
		}
	}
	keys := make([]string, 0, len(persona))
	for k := range persona {
		keys = append(keys, k)
	}
	// The first unknown key in order, so that the message does not change
	// between requests.
	slices.Sort(keys)
	for _, k := range keys {
		if !slices.ContainsFunc(d.Persona, func(p PersonaField) bool { return p.Key == k }) {
			// The key comes from the request; it is named only if it has
			// the form of a key, so that the error does not echo any text.
			if !valueKey.MatchString(k) {
				k = "with a malformed key"
			}
			return &PersonaError{Key: k, Reason: "is not a value of the persona of this deception"}
		}
	}
	return nil
}

// secretAlphabet are the characters of a secret: letters and digits, which no
// supported format treats specially.
const secretAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// NewSecrets returns a new random value for every secret of d, of its length,
// from crypto/rand.
func (d Deception) NewSecrets() map[string]string {
	secrets := make(map[string]string, len(d.Secrets))
	for _, s := range d.Secrets {
		secrets[s.Key] = newSecret(s.Length)
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

// Values returns the values that the templates of d reference: the URL or
// host name of every honeytoken, keyed by the key of its slot, the persona
// and the secrets.
func (d Deception) Values(honeytokens map[string]Placed, persona, secrets map[string]string) map[string]string {
	values := map[string]string{}
	for _, h := range d.Honeytokens {
		if h.Type == honeytoken.TypeDNS {
			values["Honeytokens."+h.Key+".Host"] = honeytokens[h.Key].Host
		} else {
			values["Honeytokens."+h.Key+".URL"] = honeytokens[h.Key].URL
		}
	}
	for k, v := range persona {
		values["Persona."+k] = v
	}
	for k, v := range secrets {
		values["Secrets."+k] = v
	}
	return values
}

// RenderedArtifact is an artifact of a deception with its content.
type RenderedArtifact struct {
	Artifact
	Content []byte
}

// Rendered is what applying a deception renders.
type Rendered struct {
	Artifacts []RenderedArtifact
	// Guide is the guide in the language of the application.
	Guide []byte
}

// Render renders the artifacts of d and its guide in lang with values. It
// fails with a RevealError if an artifact contains a marker, and with
// ErrUnknownLanguage if d has no guide in lang.
func (d Deception) Render(values map[string]string, lang string) (Rendered, error) {
	guide, ok := d.Guide[lang]
	if !ok {
		return Rendered{}, fmt.Errorf("%w: %q", ErrUnknownLanguage, lang)
	}
	var r Rendered
	for _, a := range d.Artifacts {
		content, err := a.Render(values)
		if err != nil {
			return Rendered{}, fmt.Errorf("render artifact %s of %s: %w", a.Key, d.ID, err)
		}
		if marker := d.Reveals(content); marker != "" {
			return Rendered{}, &RevealError{Artifact: a.Key, Marker: marker}
		}
		r.Artifacts = append(r.Artifacts, RenderedArtifact{Artifact: a, Content: content})
	}
	var err error
	if r.Guide, err = guide.Render(values); err != nil {
		return Rendered{}, fmt.Errorf("render guide %s of %s: %w", lang, d.ID, err)
	}
	return r, nil
}
