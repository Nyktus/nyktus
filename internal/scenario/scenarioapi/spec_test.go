// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenarioapi

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/scenario"
)

type parameter struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Schema      struct {
		Enum    []string `yaml:"enum"`
		Maximum int      `yaml:"maximum"`
		Default int      `yaml:"default"`
	} `yaml:"schema"`
}

type property struct {
	MaxLength int `yaml:"maxLength"`
	MaxItems  int `yaml:"maxItems"`
}

// Limits, page sizes, the fields of a change and the removals of a deletion
// live in code and in the specification; both must agree.
func TestSpecification_MatchesCode(t *testing.T) {
	t.Parallel()

	var spec struct {
		Paths map[string]struct {
			Get struct {
				Parameters []parameter `yaml:"parameters"`
			} `yaml:"get"`
			Delete struct {
				Parameters []parameter `yaml:"parameters"`
			} `yaml:"delete"`
		} `yaml:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required   []string            `yaml:"required"`
				Properties map[string]property `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(api.OpenAPI(), &spec); err != nil {
		t.Fatalf("parse specification: %v", err)
	}
	schemas := spec.Components.Schemas

	for _, s := range []string{"CreateScenarioRequest", "UpdateScenarioRequest"} {
		p := schemas[s].Properties
		if p["name"].MaxLength != scenario.MaxNameLength || p["notes"].MaxLength != scenario.MaxNotesLength ||
			p["engage_activities"].MaxItems != scenario.MaxEngageActivities {
			t.Errorf("%s: limits %+v differ from the code", s, p)
		}
	}
	if got := schemas["CreateScenarioRequest"].Required; !slices.Equal(got, []string{"name"}) {
		t.Errorf("CreateScenarioRequest.required = %v", got)
	}
	fields := []string{scenario.FieldName, scenario.FieldNotes, scenario.FieldEngageActivities}
	for _, s := range []string{"CreateScenarioRequest", "UpdateScenarioRequest"} {
		if got := slices.Sorted(maps.Keys(schemas[s].Properties)); !slices.Equal(got, slices.Sorted(slices.Values(fields))) {
			t.Errorf("%s properties = %v, want %v", s, got, fields)
		}
	}

	params := spec.Paths["/api/v1/scenarios"].Get.Parameters
	if len(params) != 2 || params[0].Name != "limit" || params[1].Name != "cursor" ||
		params[0].Schema.Maximum != scenario.MaxPageSize || params[0].Schema.Default != defaultPageSize {
		t.Errorf("parameters of the list = %+v, want limit up to %d, %d by default, and cursor", params, scenario.MaxPageSize, defaultPageSize)
	}

	var removals []string
	for _, r := range scenario.Removals {
		removals = append(removals, string(r))
	}
	params = spec.Paths["/api/v1/scenarios/{id}"].Delete.Parameters
	// Other specification tests read every default of a query parameter as a
	// number, so the default removal is part of the description.
	if len(params) != 1 || params[0].Name != paramHoneytokens ||
		!slices.Equal(slices.Sorted(slices.Values(params[0].Schema.Enum)), slices.Sorted(slices.Values(removals))) ||
		!strings.Contains(params[0].Description, "`"+string(scenario.RemovalKeep)+"` (the\ndefault)") {
		t.Errorf("parameters of the deletion = %+v, want only %s with %v, keep by default", params, paramHoneytokens, removals)
	}
}
