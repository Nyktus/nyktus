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
	"nyktus.org/nyktus/internal/catalog"
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
	names := []string{paramHoneytokens, paramHoneypots}
	if len(params) != len(names) {
		t.Fatalf("parameters of the deletion = %+v, want %v", params, names)
	}
	for i, name := range names {
		// Other specification tests read every default of a query parameter
		// as a number, so the default removal is part of the description.
		if p := params[i]; p.Name != name ||
			!slices.Equal(slices.Sorted(slices.Values(p.Schema.Enum)), slices.Sorted(slices.Values(removals))) ||
			!strings.Contains(p.Description, "`"+string(scenario.RemovalKeep)+"` (the\ndefault)") {
			t.Errorf("parameter %d of the deletion = %+v, want %s with %v, keep by default", i, p, name, removals)
		}
	}

	var apply struct {
		Required   []string `yaml:"required"`
		Properties map[string]struct {
			Enum      []string `yaml:"enum"`
			MaxLength int      `yaml:"maxLength"`
		} `yaml:"properties"`
	}
	var doc struct {
		Components struct {
			Schemas map[string]yaml.Node `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(api.OpenAPI(), &doc); err != nil {
		t.Fatal(err)
	}
	node := doc.Components.Schemas["ApplyDeceptionRequest"]
	if err := node.Decode(&apply); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(apply.Required, []string{"name"}) ||
		!slices.Equal(slices.Sorted(maps.Keys(apply.Properties)), []string{"create_resources", "language", "name", "notes"}) ||
		apply.Properties["name"].MaxLength != scenario.MaxNameLength || apply.Properties["notes"].MaxLength != scenario.MaxNotesLength ||
		!slices.Equal(slices.Sorted(slices.Values(apply.Properties["language"].Enum)), slices.Sorted(slices.Values(catalog.Languages))) ||
		defaultLanguage != "en" {
		t.Errorf("ApplyDeceptionRequest = %+v, want name, notes, language of %v, English by default, and create_resources", apply, catalog.Languages)
	}
	// The request that extends a scenario, as the code names it.
	var schema struct {
		Required   []string       `yaml:"required"`
		Properties map[string]any `yaml:"properties"`
	}
	node = doc.Components.Schemas["AddDeceptionRequest"]
	if err := node.Decode(&schema); err != nil {
		t.Fatal(err)
	}
	if got, want := slices.Sorted(maps.Keys(schema.Properties)), []string{"create_resources", "deception_id", "language"}; !slices.Equal(got, want) ||
		!slices.Equal(schema.Required, []string{"deception_id"}) {
		t.Errorf("AddDeceptionRequest properties = %v, required %v; want %v and deception_id required", got, schema.Required, want)
	}
}
