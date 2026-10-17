// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package incidentapi

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/incident"
)

type schemaProperty struct {
	Enum      []any `yaml:"enum"`
	MaxLength int   `yaml:"maxLength"`
	MaxItems  int   `yaml:"maxItems"`
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

// enum returns the values of an enumeration other than null.
func enum(p schemaProperty) []string {
	var out []string
	for _, v := range p.Enum {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return slices.Sorted(slices.Values(out))
}

func names[T ~string](values []T, except ...T) []string {
	var out []string
	for _, v := range values {
		if !slices.Contains(except, v) {
			out = append(out, string(v))
		}
	}
	return slices.Sorted(slices.Values(out))
}

// Statuses, severities, limits, page sizes, filters and the fields of the
// triage live in code and in the specification; both must agree.
func TestSpecification_MatchesCode(t *testing.T) {
	t.Parallel()

	var spec struct {
		Paths map[string]struct {
			Get struct {
				Parameters []struct {
					Name   string `yaml:"name"`
					Schema struct {
						Pattern string `yaml:"pattern"`
						Maximum int    `yaml:"maximum"`
						Default int    `yaml:"default"`
					} `yaml:"schema"`
				} `yaml:"parameters"`
			} `yaml:"get"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(api.OpenAPI(), &spec); err != nil {
		t.Fatalf("parse specification: %v", err)
	}
	for path, want := range map[string][]string{
		"/api/v1/incidents": {"cursor", "limit", filterResourceID, filterStatus},
		"/api/v1/events":    {"cursor", filterIncidentID, "limit"},
	} {
		var got []string
		for _, p := range spec.Paths[path].Get.Parameters {
			got = append(got, p.Name)
			if p.Name == "limit" && (p.Schema.Maximum != incident.MaxPageSize || p.Schema.Default != defaultPageSize) {
				t.Errorf("%s limit: specification maximum %d, default %d; code %d, %d", path, p.Schema.Maximum, p.Schema.Default, incident.MaxPageSize, defaultPageSize)
			}
			if p.Name == filterStatus {
				for _, s := range incident.Statuses {
					if !strings.Contains(p.Schema.Pattern, string(s)) {
						t.Errorf("the pattern of the status filter misses %s", s)
					}
				}
			}
		}
		if slices.Sort(got); !slices.Equal(got, want) {
			t.Errorf("parameters of %s = %v, want %v", path, got, want)
		}
	}

	schemas := specSchemas(t)
	statuses := names(incident.Statuses)
	severities := names(incident.Severities)
	eventSeverities := names(incident.Severities, incident.SeverityInfo)
	for _, check := range []struct {
		schema, property string
		want             []string
	}{
		{"Incident", "status", statuses},
		{"TriageIncidentRequest", "status", statuses},
		{"Incident", "severity", severities},
		{"Incident", "severity_override", severities},
		{"TriageIncidentRequest", "severity_override", severities},
		{"Incident", "event_severity", eventSeverities},
		{"Event", "channel", []string{incident.ChannelDNS, incident.ChannelHTTP}},
		{"Incident", "resource_type", slices.Sorted(slices.Values(incident.ResourceTypes))},
		{"Event", "resource_type", []string{honeytoken.ResourceType}},
	} {
		if got := enum(schemas[check.schema].Properties[check.property]); !slices.Equal(got, check.want) {
			t.Errorf("%s.%s = %v, want %v", check.schema, check.property, got, check.want)
		}
	}
	triage := schemas["TriageIncidentRequest"].Properties
	if triage["notes"].MaxLength != incident.MaxNotesLength || triage["techniques_override"].MaxItems != honeytoken.MaxTechniques {
		t.Errorf("TriageIncidentRequest limits %+v differ from the code", triage)
	}
	fields := []string{incident.FieldStatus, incident.FieldNotes, incident.FieldSeverityOverride, incident.FieldTechniquesOverride}
	if got := slices.Sorted(maps.Keys(triage)); !slices.Equal(got, slices.Sorted(slices.Values(fields))) {
		t.Errorf("TriageIncidentRequest properties = %v, want the fields of the triage %v", got, fields)
	}
}
