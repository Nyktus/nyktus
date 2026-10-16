// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalogapi

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/honeytoken"
)

// schemaNode is the part of a schema of the specification that the responses
// of the catalog use.
type schemaNode struct {
	Ref string `yaml:"$ref"`
	// Type is a string or, in schemas of other packages, a list of types.
	Type                 any                    `yaml:"type"`
	Required             []string               `yaml:"required"`
	Properties           map[string]*schemaNode `yaml:"properties"`
	AdditionalProperties *bool                  `yaml:"additionalProperties"`
	Items                *schemaNode            `yaml:"items"`
	Enum                 []string               `yaml:"enum"`
	Pattern              string                 `yaml:"pattern"`
	Minimum              *float64               `yaml:"minimum"`
	Maximum              *float64               `yaml:"maximum"`
}

type specDocument struct {
	Paths map[string]struct {
		Get struct {
			Parameters []struct {
				Name        string `yaml:"name"`
				Description string `yaml:"description"`
				Schema      struct {
					Enum []string `yaml:"enum"`
				} `yaml:"schema"`
			} `yaml:"parameters"`
		} `yaml:"get"`
	} `yaml:"paths"`
	Components struct {
		Schemas map[string]*schemaNode `yaml:"schemas"`
	} `yaml:"components"`
}

func loadSpec(t *testing.T) specDocument {
	t.Helper()
	var spec specDocument
	if err := yaml.Unmarshal(api.OpenAPI(), &spec); err != nil {
		t.Fatalf("parse specification: %v", err)
	}
	return spec
}

// check reports where v does not match the schema s: its type, its required
// and undocumented members, enums, patterns and bounds. It is a small
// validator for the schemas of this package, not of OpenAPI in general.
func check(schemas map[string]*schemaNode, s *schemaNode, v any, at string) []string {
	if s.Ref != "" {
		return check(schemas, schemas[strings.TrimPrefix(s.Ref, "#/components/schemas/")], v, at)
	}
	var problems []string
	typ, _ := s.Type.(string)
	switch typ {
	case "object":
		m, ok := v.(map[string]any)
		if !ok {
			return []string{at + ": not an object"}
		}
		for _, name := range s.Required {
			if _, ok := m[name]; !ok {
				problems = append(problems, at+"."+name+": missing")
			}
		}
		for name, value := range m {
			prop, ok := s.Properties[name]
			if !ok {
				if s.AdditionalProperties == nil || !*s.AdditionalProperties {
					problems = append(problems, at+"."+name+": not documented")
				}
				continue
			}
			problems = append(problems, check(schemas, prop, value, at+"."+name)...)
		}
		if s.AdditionalProperties == nil || *s.AdditionalProperties {
			problems = append(problems, at+": the schema allows undocumented members")
		}
	case "array":
		list, ok := v.([]any)
		if !ok {
			return []string{at + ": not an array"}
		}
		for i, item := range list {
			problems = append(problems, check(schemas, s.Items, item, fmt.Sprintf("%s[%d]", at, i))...)
		}
	case "string":
		str, ok := v.(string)
		if !ok {
			return []string{at + ": not a string"}
		}
		if len(s.Enum) > 0 && !slices.Contains(s.Enum, str) {
			problems = append(problems, fmt.Sprintf("%s: %q not in %v", at, str, s.Enum))
		}
		if s.Pattern != "" && !regexp.MustCompile(s.Pattern).MatchString(str) {
			problems = append(problems, fmt.Sprintf("%s: %q does not match %s", at, str, s.Pattern))
		}
	case "integer":
		n, ok := v.(float64)
		if !ok || n != float64(int64(n)) {
			return []string{at + ": not an integer"}
		}
		if (s.Minimum != nil && n < *s.Minimum) || (s.Maximum != nil && n > *s.Maximum) {
			problems = append(problems, fmt.Sprintf("%s: %v out of bounds", at, n))
		}
	default:
		problems = append(problems, fmt.Sprintf("%s: unsupported schema type %v", at, s.Type))
	}
	return problems
}

// Every response matches its schema in the specification, which forbids
// undocumented members, so that a field added to the code fails until it is
// documented.
func TestResponses_MatchTheSpecification(t *testing.T) {
	t.Parallel()
	spec := loadSpec(t)
	h := NewHandler(testCatalog(t))

	for _, tt := range []struct {
		schema string
		body   []byte
	}{
		{"CatalogDeceptionList", serve(t, h.List, "/api/v1/catalog/deceptions", "").Body.Bytes()},
		{"CatalogDeception", serve(t, h.Get, "/api/v1/catalog/deceptions/ssh?lang=de", "ssh").Body.Bytes()},
		{"CatalogDeception", serve(t, h.Get, "/api/v1/catalog/deceptions/guide-only", "guide-only").Body.Bytes()},
	} {
		var v any
		if err := json.Unmarshal(tt.body, &v); err != nil {
			t.Fatal(err)
		}
		s, ok := spec.Components.Schemas[tt.schema]
		if !ok {
			t.Fatalf("the specification has no schema %s", tt.schema)
		}
		for _, p := range check(spec.Components.Schemas, s, v, tt.schema) {
			t.Error(p)
		}
	}
}

// Categories, kinds, formats, types and languages live in code and in the
// specification; both must agree.
func TestSpecification_MatchesCode(t *testing.T) {
	t.Parallel()
	spec := loadSpec(t)
	schemas := spec.Components.Schemas
	detailProps := schemas["CatalogDeception"].Properties

	names := func(values any) []string {
		var out []string
		switch vs := values.(type) {
		case []catalog.Category:
			for _, v := range vs {
				out = append(out, string(v))
			}
		case []catalog.Format:
			for _, v := range vs {
				out = append(out, string(v))
			}
		case []honeytoken.Type:
			for _, v := range vs {
				out = append(out, string(v))
			}
		case []string:
			out = vs
		}
		slices.Sort(out)
		return out
	}
	sorted := func(s []string) []string { s = slices.Clone(s); slices.Sort(s); return s }

	for name, tt := range map[string]struct{ spec, code []string }{
		"category":        {schemas["CatalogDeceptionSummary"].Properties["category"].Enum, names(catalog.Categories)},
		"detail category": {detailProps["category"].Enum, names(catalog.Categories)},
		"artifact format": {detailProps["artifacts"].Items.Properties["format"].Enum, names(catalog.Formats)},
		"honeytoken type": {detailProps["honeytokens"].Items.Properties["type"].Enum, names(honeytoken.Types)},
		"persona kinds":   {detailProps["persona"].Items.Properties["kind"].Enum, []string{"host", "name", "text"}},
	} {
		if !slices.Equal(sorted(tt.spec), tt.code) {
			t.Errorf("%s: specification %v, code %v", name, tt.spec, tt.code)
		}
	}

	for _, path := range []string{"/api/v1/catalog/deceptions", "/api/v1/catalog/deceptions/{id}"} {
		params := spec.Paths[path].Get.Parameters
		// Other specification tests read every default of a query parameter
		// as a number, so the default language is part of the description.
		if len(params) != 1 || params[0].Name != paramLang || defaultLang != "en" ||
			!strings.Contains(params[0].Description, "Without it, they are English") ||
			!slices.Equal(sorted(params[0].Schema.Enum), names(catalog.Languages)) {
			t.Errorf("%s: parameters %+v, want only %s with %v, English by default", path, params, paramLang, catalog.Languages)
		}
	}
}
