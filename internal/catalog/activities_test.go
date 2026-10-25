// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"slices"
	"testing"

	"nyktus.org/nyktus/internal/engage"
	"nyktus.org/nyktus/internal/honeytoken"
)

// The activities that follow from a scenario are those of Engage by the name
// the guidelines use for them.
func TestActivities_AreActivitiesOfEngage(t *testing.T) {
	t.Parallel()
	for id, name := range map[string]string{
		ActivityLures: "Lures", ActivityPocketLitter: "Pocket Litter",
		ActivityPersonas: "Personas", ActivityArtifactDiversity: "Artifact Diversity",
	} {
		if a, ok := engage.Lookup(id); !ok || a.Name != name {
			t.Errorf("Lookup(%s) = %+v, %v; want %q", id, a, ok, name)
		}
	}
}

func TestArtifactLure_FollowsTheBindingOfASlot(t *testing.T) {
	t.Parallel()
	dns := Slot{Key: "Host", Accepts: []honeytoken.Type{honeytoken.TypeDNS}}
	link := Slot{Key: "Link", Accepts: []honeytoken.Type{honeytoken.TypeWebURL}, Optional: true}
	for name, tt := range map[string]struct {
		a      Artifact
		placed map[string]Placed
		want   bool
	}{
		"required slot bound":                                  {Artifact{Slots: []Slot{dns}}, map[string]Placed{"Host": {Host: "a.example.org"}}, true},
		"optional slot bound":                                  {Artifact{Slots: []Slot{link}}, map[string]Placed{"Link": {URL: "https://t.example.org/x"}}, true},
		"optional slot left empty":                             {Artifact{Slots: []Slot{link}}, nil, false},
		"honeytoken of the key but of the other kind of value": {Artifact{Slots: []Slot{dns}}, map[string]Placed{"Host": {URL: "https://t.example.org/x"}}, false},
		"honeytoken under another key":                         {Artifact{Slots: []Slot{link}}, map[string]Placed{"Other": {URL: "https://t.example.org/x"}}, false},
		"no slot":                                              {Artifact{}, map[string]Placed{"Host": {Host: "a.example.org"}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := tt.a.Lure(tt.placed); got != tt.want {
				t.Errorf("Lure() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestActivities(t *testing.T) {
	t.Parallel()
	dns := Slot{Key: "Host", Accepts: []honeytoken.Type{honeytoken.TypeDNS}}
	link := Slot{Key: "Link", Accepts: []honeytoken.Type{honeytoken.TypeWebURL}, Optional: true}
	bound := map[string]Placed{"Host": {Host: "a.example.org"}, "Link": {URL: "https://t.example.org/x"}}
	persona := map[string]string{"Domain": "corp.example.com"}
	for name, tt := range map[string]struct {
		base      []string
		artifacts []Artifact
		placed    map[string]Placed
		persona   map[string]string
		want      []string
	}{
		"story only":              {[]string{"EAC0005"}, nil, nil, nil, []string{"EAC0005"}},
		"no base":                 {nil, []Artifact{{Slots: []Slot{dns}}}, bound, nil, []string{"EAC0005"}},
		"lure carrier":            {[]string{"EAC0005"}, []Artifact{{Slots: []Slot{dns}, Format: FormatConfig}}, bound, nil, []string{"EAC0005"}},
		"pocket litter":           {[]string{"EAC0005"}, []Artifact{{Slots: []Slot{link}, Format: FormatText}}, nil, nil, []string{"EAC0005", "EAC0011"}},
		"file without slot":       {[]string{"EAC0005"}, []Artifact{{Format: FormatText}}, bound, nil, []string{"EAC0005", "EAC0011"}},
		"lure and litter":         {nil, []Artifact{{Slots: []Slot{dns}, Format: FormatText}, {Format: FormatText}}, bound, nil, []string{"EAC0005", "EAC0011"}},
		"one format twice":        {nil, []Artifact{{Format: FormatText}, {Format: FormatText}}, nil, nil, []string{"EAC0011"}},
		"two formats":             {nil, []Artifact{{Format: FormatText}, {Format: FormatHTML}}, nil, nil, []string{"EAC0011", "EAC0022"}},
		"persona":                 {[]string{"EAC0005"}, nil, nil, persona, []string{"EAC0005", "EAC0012"}},
		"empty persona":           {[]string{"EAC0005"}, nil, nil, map[string]string{}, []string{"EAC0005"}},
		"named by the story":      {[]string{"EAC0005", "EAC0022"}, []Artifact{{Format: FormatText}, {Format: FormatHTML}}, nil, persona, []string{"EAC0005", "EAC0022", "EAC0011", "EAC0012"}},
		"base that repeats lures": {[]string{"EAC0011"}, []Artifact{{Format: FormatText}}, nil, nil, []string{"EAC0011"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			base := slices.Clone(tt.base)
			got := Activities(tt.base, tt.artifacts, tt.placed, tt.persona)
			if !slices.Equal(got, tt.want) {
				t.Errorf("Activities() = %v, want %v", got, tt.want)
			}
			if !slices.Equal(tt.base, base) {
				t.Errorf("Activities() changed its base to %v", tt.base)
			}
		})
	}
}
