// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeypotapi

import (
	"maps"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/honeypot"
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

// Services, severities, states, limits, page sizes and the fields of a change
// live in code and in the specification; both must agree. The schema of the
// database agrees with the code through the store tests, which write every
// value that the code produces.
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
	services := make([]string, 0, len(honeypot.Services))
	for _, s := range honeypot.Services {
		services = append(services, string(s))
	}

	params := map[string][]string{}
	for _, p := range spec.Paths["/api/v1/honeypots"].Get.Parameters {
		params[p.Name] = p.Schema.Enum
		if p.Name == "limit" && (p.Schema.Maximum != honeypot.MaxPageSize || p.Schema.Default != defaultPageSize) {
			t.Errorf("limit: specification maximum %d, default %d; code %d, %d", p.Schema.Maximum, p.Schema.Default, honeypot.MaxPageSize, defaultPageSize)
		}
	}
	if got := slices.Sorted(maps.Keys(params)); !slices.Equal(got, []string{"cursor", filterEnabled, "limit", filterScenarioID, filterService}) {
		t.Errorf("parameters of the list = %v", got)
	}
	if !sameSet(params[filterService], services) || !sameSet(params[filterEnabled], []string{"true", "false"}) {
		t.Errorf("filters: service %v, enabled %v; want %v and true, false", params[filterService], params[filterEnabled], services)
	}

	schemas := specSchemas(t)
	for _, s := range []string{"Honeypot", "CreatedHoneypot", "CreateHoneypotRequest"} {
		if got := schemas[s].Properties["service"].Enum; !sameSet(got, services) {
			t.Errorf("%s.service = %v, want %v", s, got, services)
		}
	}
	statuses := make([]string, 0, len(honeypot.Statuses))
	for _, s := range honeypot.Statuses {
		statuses = append(statuses, string(s))
	}
	if got := schemas["Honeypot"].Properties["status"].Enum; !sameSet(got, statuses) {
		t.Errorf("Honeypot.status = %v, want %v", got, statuses)
	}
	if got := schemas["CreatedHoneypot"].Properties["status"].Enum; !sameSet(got, []string{string(honeypot.StatusNever)}) {
		t.Errorf("CreatedHoneypot.status = %v, want only never", got)
	}
	for _, s := range []string{"CreateHoneypotRequest", "UpdateHoneypotRequest"} {
		p := schemas[s].Properties
		if p["name"].MaxLength != honeypot.MaxNameLength || p["notes"].MaxLength != honeypot.MaxNotesLength ||
			p["techniques"].MaxItems != honeypot.MaxTechniques {
			t.Errorf("%s: limits %+v differ from the code", s, p)
		}
	}
	if got := schemas["CreateHoneypotRequest"].Required; !sameSet(got, []string{"service", "name"}) {
		t.Errorf("CreateHoneypotRequest.required = %v", got)
	}
	levels := make([]string, 0, len(severity.Suggested))
	for _, l := range severity.Suggested {
		levels = append(levels, string(l))
	}
	for _, s := range []string{"Honeypot", "CreatedHoneypot", "CreateHoneypotRequest", "UpdateHoneypotRequest"} {
		if got := schemas[s].Properties["severity"].Enum; !sameSet(got, levels) {
			t.Errorf("%s.severity = %v, want %v", s, got, levels)
		}
	}
	fields := []string{
		honeypot.FieldName, honeypot.FieldNotes, honeypot.FieldEnabled, honeypot.FieldTechniques, honeypot.FieldSeverity,
	}
	if got := slices.Collect(maps.Keys(schemas["UpdateHoneypotRequest"].Properties)); !sameSet(got, fields) {
		t.Errorf("UpdateHoneypotRequest properties = %v, want the fields of a change %v", got, fields)
	}
	// The created honeypot is the honeypot with its secret and the entry for the
	// sensor that holds it.
	want := append(slices.Clone(schemas["Honeypot"].Required), "secret", "sensor_config")
	if got := schemas["CreatedHoneypot"].Required; !sameSet(got, want) {
		t.Errorf("CreatedHoneypot.required = %v, want %v", got, want)
	}
}

func sameSet(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}
