// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
)

// The persona of a scenario only grows: a key is added, a value that is there
// stays, and an error never names a value.
func TestMergePersona(t *testing.T) {
	t.Parallel()
	fields := []PersonaField{
		{Key: "Domain", Kind: KindHost},
		{Key: "Account", Kind: KindName},
		{Key: "Company", Kind: KindText},
	}
	d := Deception{Persona: fields}
	long := strings.Repeat("a", MaxTextLength+1)

	for name, tt := range map[string]struct {
		stored, given map[string]string
		want          map[string]string
		added         []string
		err           error
		key           string
	}{
		"everything is new": {
			nil,
			map[string]string{"Domain": "corp.example.com", "Account": "j.doe", "Company": "Example Ltd"},
			map[string]string{"Domain": "corp.example.com", "Account": "j.doe", "Company": "Example Ltd"},
			[]string{"Domain", "Account", "Company"},
			nil, "",
		},
		"a new key beside stored ones": {
			map[string]string{"Domain": "corp.example.com", "Account": "j.doe"},
			map[string]string{"Company": "Example Ltd"},
			map[string]string{"Domain": "corp.example.com", "Account": "j.doe", "Company": "Example Ltd"},
			[]string{"Company"},
			nil, "",
		},
		"the same values": {
			map[string]string{"Domain": "corp.example.com", "Account": "j.doe", "Company": "Example Ltd"},
			map[string]string{"Domain": "corp.example.com", "Account": "j.doe", "Company": "Example Ltd"},
			map[string]string{"Domain": "corp.example.com", "Account": "j.doe", "Company": "Example Ltd"},
			nil, nil, "",
		},
		"values that are left out": {
			map[string]string{"Domain": "corp.example.com", "Account": "j.doe", "Company": "Example Ltd"},
			nil,
			map[string]string{"Domain": "corp.example.com", "Account": "j.doe", "Company": "Example Ltd"},
			nil, nil, "",
		},
		"a key of the scenario that the deception does not ask for stays": {
			map[string]string{"Port": "22", "Domain": "corp.example.com", "Account": "j.doe", "Company": "Example Ltd"},
			nil,
			map[string]string{"Port": "22", "Domain": "corp.example.com", "Account": "j.doe", "Company": "Example Ltd"},
			nil, nil, "",
		},
		"another value": {
			map[string]string{"Domain": "corp.example.com"},
			map[string]string{"Domain": "other.example.com", "Account": "j.doe", "Company": "Example Ltd"},
			nil, nil, ErrPersonaConflict, "Domain",
		},
		"another value in another case": {
			map[string]string{"Account": "j.doe"},
			map[string]string{"Domain": "corp.example.com", "Account": "J.Doe", "Company": "Example Ltd"},
			nil, nil, ErrPersonaConflict, "Account",
		},
		"a key the scenario lacks and nobody gives": {
			map[string]string{"Domain": "corp.example.com"},
			map[string]string{"Account": "j.doe"},
			nil, nil, ErrInvalidPersona, "Company",
		},
		"an empty value": {
			nil,
			map[string]string{"Domain": "", "Account": "j.doe", "Company": "Example Ltd"},
			nil, nil, ErrInvalidPersona, "Domain",
		},
		"an empty value beside a stored one": {
			map[string]string{"Domain": "corp.example.com"},
			map[string]string{"Domain": "", "Account": "j.doe", "Company": "Example Ltd"},
			nil, nil, ErrPersonaConflict, "Domain",
		},
		"a key that is not asked for": {
			map[string]string{"Domain": "corp.example.com"},
			map[string]string{"Account": "j.doe", "Company": "Example Ltd", "Zone": "x"},
			nil, nil, ErrInvalidPersona, "Zone",
		},
		"a key with the form of nothing": {
			map[string]string{"Domain": "corp.example.com"},
			map[string]string{"Account": "j.doe", "Company": "Example Ltd", "z z": "x"},
			nil, nil, ErrInvalidPersona, "with a malformed key",
		},
		"a host name of the wrong kind": {
			nil,
			map[string]string{"Domain": "Corp Example", "Account": "j.doe", "Company": "Example Ltd"},
			nil, nil, ErrInvalidPersona, "Domain",
		},
		"a name of the wrong kind": {
			nil,
			map[string]string{"Domain": "corp.example.com", "Account": "-j", "Company": "Example Ltd"},
			nil, nil, ErrInvalidPersona, "Account",
		},
		"a text that is too long": {
			nil,
			map[string]string{"Domain": "corp.example.com", "Account": "j.doe", "Company": long},
			nil, nil, ErrInvalidPersona, "Company",
		},
		"a text with a line break": {
			nil,
			map[string]string{"Domain": "corp.example.com", "Account": "j.doe", "Company": "a\nb"},
			nil, nil, ErrInvalidPersona, "Company",
		},
		// The kind comes from what joins now: a value the scenario has must fit it.
		"a stored value of another kind": {
			map[string]string{"Domain": "Example Ltd"},
			map[string]string{"Account": "j.doe", "Company": "Example Ltd"},
			nil, nil, ErrInvalidPersona, "Domain",
		},
		"a persona that gets too large": {
			func() map[string]string {
				m := map[string]string{}
				for i := range 200 {
					m["K"+strings.Repeat("x", i%20)+string(rune('a'+i/20))+string(rune('a'+i%20))] = strings.Repeat("v", 150)
				}
				return m
			}(),
			map[string]string{"Domain": "corp.example.com", "Account": "j.doe", "Company": "Example Ltd"},
			nil, nil, ErrInvalidPersona, "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			stored, given := maps.Clone(tt.stored), maps.Clone(tt.given)
			got, added, err := d.MergePersona(tt.stored, tt.given)
			if !errors.Is(err, tt.err) {
				t.Fatalf("MergePersona() error = %v, want %v", err, tt.err)
			}
			if !maps.Equal(tt.stored, stored) || !maps.Equal(tt.given, given) {
				t.Errorf("MergePersona() changed its arguments: %v, %v", tt.stored, tt.given)
			}
			if err != nil {
				if tt.key != "" && !strings.Contains(err.Error(), tt.key) {
					t.Errorf("error = %q, want it to name %q", err, tt.key)
				}
				// Not a value of the request and not a stored one.
				for _, v := range append(slices.Collect(maps.Values(tt.stored)), slices.Collect(maps.Values(tt.given))...) {
					if len(v) > 2 && len(v) < 100 && strings.Contains(err.Error(), v) {
						t.Errorf("error = %q, want it without the value %q", err, v)
					}
				}
				if got != nil || added != nil {
					t.Errorf("MergePersona() = %v, %v with an error, want nothing", got, added)
				}
				return
			}
			if !maps.Equal(got, tt.want) || !slices.Equal(added, tt.added) {
				t.Errorf("MergePersona() = %v, %v; want %v, %v", got, added, tt.want, tt.added)
			}
		})
	}
}

// An artifact merges its persona as a deception does, and names itself in the
// message for a key it does not ask for.
func TestArtifactMergePersona(t *testing.T) {
	t.Parallel()
	a := Artifact{Persona: []PersonaField{{Key: "Company", Kind: KindText}}}

	got, added, err := a.MergePersona(map[string]string{"Domain": "corp.example.com"}, map[string]string{"Company": "Example Ltd"})
	if err != nil || !maps.Equal(got, map[string]string{"Domain": "corp.example.com", "Company": "Example Ltd"}) || !slices.Equal(added, []string{"Company"}) {
		t.Errorf("MergePersona() = %v, %v, %v", got, added, err)
	}
	_, _, err = a.MergePersona(nil, map[string]string{"Company": "Example Ltd", "Zone": "x"})
	if !errors.Is(err, ErrInvalidPersona) || !strings.Contains(err.Error(), "of this artifact") {
		t.Errorf("MergePersona(unknown key) error = %v, want one that names the artifact", err)
	}
}

// The conflict is an error of its own that names the key.
func TestPersonaConflictError(t *testing.T) {
	t.Parallel()
	err := error(&PersonaConflictError{Key: "Domain"})
	if !errors.Is(err, ErrPersonaConflict) || errors.Is(err, ErrInvalidPersona) || !strings.Contains(err.Error(), "Domain") {
		t.Errorf("error = %v", err)
	}
}
