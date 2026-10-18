// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package artifactapi

import (
	"maps"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/artifact"
	"nyktus.org/nyktus/internal/catalog"
)

// Limits, page sizes, filters, formats and the fields of a change live in
// code and in the specification; both must agree.
func TestSpecification_MatchesCode(t *testing.T) {
	t.Parallel()

	var spec struct {
		Paths map[string]struct {
			Get struct {
				Parameters []struct {
					Name   string `yaml:"name"`
					Schema struct {
						Maximum int `yaml:"maximum"`
						Default int `yaml:"default"`
					} `yaml:"schema"`
				} `yaml:"parameters"`
			} `yaml:"get"`
		} `yaml:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required   []string `yaml:"required"`
				Properties map[string]struct {
					Enum      []string `yaml:"enum"`
					MaxLength int      `yaml:"maxLength"`
					Maximum   int      `yaml:"maximum"`
				} `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(api.OpenAPI(), &spec); err != nil {
		t.Fatalf("parse specification: %v", err)
	}

	var names []string
	for _, p := range spec.Paths["/api/v1/artifacts"].Get.Parameters {
		names = append(names, p.Name)
		if p.Name == "limit" && (p.Schema.Maximum != artifact.MaxPageSize || p.Schema.Default != defaultPageSize) {
			t.Errorf("limit: specification maximum %d, default %d; code %d, %d", p.Schema.Maximum, p.Schema.Default, artifact.MaxPageSize, defaultPageSize)
		}
	}
	if !slices.Equal(names, []string{"limit", "cursor", filterScenarioID}) {
		t.Errorf("parameters of the list = %v", names)
	}

	update := spec.Components.Schemas["UpdateArtifactRequest"]
	if got := slices.Sorted(maps.Keys(update.Properties)); !slices.Equal(got, []string{artifact.FieldPlacementNotes}) ||
		update.Properties[artifact.FieldPlacementNotes].MaxLength != artifact.MaxPlacementNotesLength {
		t.Errorf("UpdateArtifactRequest = %+v, want only placement_notes of up to %d characters", update, artifact.MaxPlacementNotesLength)
	}
	var formats []string
	for _, f := range catalog.Formats {
		formats = append(formats, string(f))
	}
	schema := spec.Components.Schemas["Artifact"]
	if got := schema.Properties["format"].Enum; !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(formats))) ||
		schema.Properties["size"].Maximum != artifact.MaxContentBytes {
		t.Errorf("Artifact: formats %v, size up to %d; want %v and %d", got, schema.Properties["size"].Maximum, formats, artifact.MaxContentBytes)
	}
}
