// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeytokenapi

import (
	"maps"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/severity"
)

type schemaProperty struct {
	Enum      []string `yaml:"enum"`
	MaxLength int      `yaml:"maxLength"`
	MaxItems  int      `yaml:"maxItems"`
}

type schema struct {
	Required   []string                  `yaml:"required"`
	Properties map[string]schemaProperty `yaml:"properties"`
}

func specSchemas(t *testing.T) map[string]schema {
	t.Helper()
	var spec struct {
		Components struct {
			Schemas map[string]schema `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(api.OpenAPI(), &spec); err != nil {
		t.Fatalf("parse specification: %v", err)
	}
	return spec.Components.Schemas
}

// Types, limits, page sizes and the fields of a change live in code and in the
// specification; both must agree.
func TestSpecification_MatchesCode(t *testing.T) {
	t.Parallel()

	var spec struct {
		Paths map[string]struct {
			Get struct {
				Parameters []struct {
					Name   string `yaml:"name"`
					Schema struct {
						Enum    []string `yaml:"enum"`
						Maximum int      `yaml:"maximum"`
						Default int      `yaml:"default"`
					} `yaml:"schema"`
				} `yaml:"parameters"`
			} `yaml:"get"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(api.OpenAPI(), &spec); err != nil {
		t.Fatalf("parse specification: %v", err)
	}
	types := make([]string, 0, len(honeytoken.Types))
	for _, typ := range honeytoken.Types {
		types = append(types, string(typ))
	}

	params := map[string][]string{}
	for _, p := range spec.Paths["/api/v1/honeytokens"].Get.Parameters {
		params[p.Name] = p.Schema.Enum
		if p.Name == "limit" && (p.Schema.Maximum != honeytoken.MaxPageSize || p.Schema.Default != defaultPageSize) {
			t.Errorf("limit: specification maximum %d, default %d; code %d, %d", p.Schema.Maximum, p.Schema.Default, honeytoken.MaxPageSize, defaultPageSize)
		}
	}
	if got := slices.Sorted(maps.Keys(params)); !slices.Equal(got, []string{"cursor", filterEnabled, "limit", filterScenarioID, filterType}) {
		t.Errorf("parameters of the list = %v", got)
	}
	if !sameSet(params[filterType], types) || !sameSet(params[filterEnabled], []string{"true", "false"}) {
		t.Errorf("filters: type %v, enabled %v; want %v and true, false", params[filterType], params[filterEnabled], types)
	}

	schemas := specSchemas(t)
	for _, s := range []string{"Honeytoken", "CreateHoneytokenRequest"} {
		if got := schemas[s].Properties["type"].Enum; !sameSet(got, types) {
			t.Errorf("%s.type = %v, want %v", s, got, types)
		}
	}
	for _, s := range []string{"CreateHoneytokenRequest", "UpdateHoneytokenRequest"} {
		p := schemas[s].Properties
		if p["name"].MaxLength != honeytoken.MaxNameLength || p["notes"].MaxLength != honeytoken.MaxNotesLength ||
			p["redirect_url"].MaxLength != honeytoken.MaxRedirectURLLength || p["techniques"].MaxItems != honeytoken.MaxTechniques {
			t.Errorf("%s: limits %+v differ from the code", s, p)
		}
	}
	if got := schemas["CreateHoneytokenRequest"].Required; !sameSet(got, []string{"type", "name"}) {
		t.Errorf("CreateHoneytokenRequest.required = %v", got)
	}
	levels := make([]string, 0, len(severity.Suggested))
	for _, l := range severity.Suggested {
		levels = append(levels, string(l))
	}
	for _, s := range []string{"Honeytoken", "CreateHoneytokenRequest", "UpdateHoneytokenRequest"} {
		if got := schemas[s].Properties["severity"].Enum; !sameSet(got, levels) {
			t.Errorf("%s.severity = %v, want %v", s, got, levels)
		}
	}
	fields := []string{
		honeytoken.FieldName, honeytoken.FieldNotes, honeytoken.FieldEnabled, honeytoken.FieldRedirectURL,
		honeytoken.FieldTechniques, honeytoken.FieldSeverity,
	}
	if got := slices.Collect(maps.Keys(schemas["UpdateHoneytokenRequest"].Properties)); !sameSet(got, fields) {
		t.Errorf("UpdateHoneytokenRequest properties = %v, want the fields of a change %v", got, fields)
	}
}

func sameSet(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}
