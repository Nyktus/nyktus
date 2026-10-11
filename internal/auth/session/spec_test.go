// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/api"
)

// The error codes of the second factor live in code and in the specification;
// both must agree.
func TestSpecification_NamesTheErrorCodes(t *testing.T) {
	t.Parallel()

	var spec struct {
		Components struct {
			Responses map[string]struct {
				Description string `yaml:"description"`
			} `yaml:"responses"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(api.OpenAPI(), &spec); err != nil {
		t.Fatalf("parse specification: %v", err)
	}
	for response, codes := range map[string][]string{
		"Conflict":              {codeTOTPEnabled, codeTOTPNotEnabled, codeNoTOTPSetup},
		"SecondFactorForbidden": {codeWrongPassword, codeWrongCode, codeAccountLocked},
	} {
		description := spec.Components.Responses[response].Description
		for _, code := range codes {
			if !strings.Contains(description, "`"+code+"`") {
				t.Errorf("the response %s does not name the code %s", response, code)
			}
		}
	}
}
