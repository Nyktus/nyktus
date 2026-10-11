// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

import (
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/user"
)

type schema struct {
	Properties map[string]struct {
		Enum []string `yaml:"enum"`
	} `yaml:"properties"`
}

// Page sizes, error codes and allowed values live in code and in the
// specification; both must agree.
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
			Schemas   map[string]schema `yaml:"schemas"`
			Responses map[string]struct {
				Description string `yaml:"description"`
			} `yaml:"responses"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(api.OpenAPI(), &spec); err != nil {
		t.Fatalf("parse specification: %v", err)
	}

	var found bool
	for _, p := range spec.Paths["/api/v1/users"].Get.Parameters {
		if p.Name == "limit" {
			found = true
			if p.Schema.Maximum != user.MaxPageSize || p.Schema.Default != defaultPageSize {
				t.Errorf("limit: specification maximum %d, default %d; code %d, %d", p.Schema.Maximum, p.Schema.Default, user.MaxPageSize, defaultPageSize)
			}
		}
	}
	if !found {
		t.Error("the specification does not document the parameter limit of GET /api/v1/users")
	}

	conflict := spec.Components.Responses["Conflict"].Description
	for _, code := range []string{CodeEmailTaken, CodeLastActiveAdmin, CodeOwnAccount, CodeInvalidState} {
		if !strings.Contains(conflict, "`"+code+"`") {
			t.Errorf("the response Conflict does not name the code %s", code)
		}
	}

	roles := []string{string(user.RoleAdmin), string(user.RoleEditor), string(user.RoleViewer)}
	for _, s := range []string{"CreateUserRequest", "UpdateUserRequest", "User"} {
		if got := spec.Components.Schemas[s].Properties["role"].Enum; !sameSet(got, roles) {
			t.Errorf("%s.role = %v, want %v", s, got, roles)
		}
	}
	statuses := []string{string(user.StatusActive), string(user.StatusDeactivated)}
	if got := spec.Components.Schemas["UpdateUserRequest"].Properties["status"].Enum; !sameSet(got, statuses) {
		t.Errorf("UpdateUserRequest.status = %v, want %v", got, statuses)
	}
	fields := []string{user.FieldDisplayName, user.FieldRole, user.FieldStatus}
	var props []string
	for name := range spec.Components.Schemas["UpdateUserRequest"].Properties {
		props = append(props, name)
	}
	if !sameSet(props, fields) {
		t.Errorf("UpdateUserRequest properties = %v, want the fields of a change %v", props, fields)
	}
}

func sameSet(a, b []string) bool {
	a, b = slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b))
	return slices.Equal(a, b)
}
