// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalogapi

import (
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/honeypot"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/platform/apispec"
	"nyktus.org/nyktus/internal/severity"
)

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
}

func loadSpec(t *testing.T) specDocument {
	t.Helper()
	var spec specDocument
	if err := yaml.Unmarshal(api.OpenAPI(), &spec); err != nil {
		t.Fatalf("parse specification: %v", err)
	}
	return spec
}

// Every response matches its schema in the specification, which forbids
// undocumented members, so that a field added to the code fails until it is
// documented.
func TestResponses_MatchTheSpecification(t *testing.T) {
	t.Parallel()
	schemas, err := apispec.ParseSchemas(api.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(testCatalog(t))

	for _, tt := range []struct {
		schema string
		body   []byte
	}{
		{"CatalogDeceptionList", serve(t, h.List, "/api/v1/catalog/deceptions").Body.Bytes()},
		{"CatalogDeception", serve(t, h.Get, "/api/v1/catalog/deceptions/ssh?lang=de", "id", "ssh").Body.Bytes()},
		{"CatalogDeception", serve(t, h.Get, "/api/v1/catalog/deceptions/notes", "id", "notes").Body.Bytes()},
	} {
		for _, p := range schemas.Check(tt.schema, tt.body) {
			t.Error(p)
		}
	}
}

// Categories, kinds, formats, types and languages live in code and in the
// specification; both must agree.
func TestSpecification_MatchesCode(t *testing.T) {
	t.Parallel()
	spec := loadSpec(t)
	schemas, err := apispec.ParseSchemas(api.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
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
		case []honeypot.Service:
			for _, v := range vs {
				out = append(out, string(v))
			}
		case []honeytoken.Type:
			for _, v := range vs {
				out = append(out, string(v))
			}
		case []severity.Level:
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
		"category":         {schemas["CatalogDeceptionSummary"].Properties["category"].EnumStrings(), names(catalog.Categories)},
		"detail category":  {detailProps["category"].EnumStrings(), names(catalog.Categories)},
		"file format":      {detailProps["files"].Items.Properties["format"].EnumStrings(), names(catalog.Formats)},
		"honeytoken type":  {detailProps["honeytokens"].Items.Properties["type"].EnumStrings(), names(honeytoken.Types)},
		"severity":         {detailProps["honeytokens"].Items.Properties["severity"].EnumStrings(), names(severity.Suggested)},
		"honeypot service": {detailProps["honeypots"].Items.Properties["service"].EnumStrings(), names(honeypot.Services)},
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
