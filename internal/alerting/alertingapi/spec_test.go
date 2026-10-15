// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package alertingapi

import (
	"maps"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/alerting"
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

// Types, limits and the fields of a change live in code and in the
// specification; both must agree.
func TestSpecification_MatchesCode(t *testing.T) {
	t.Parallel()

	types := make([]string, 0, len(alerting.Types))
	for _, typ := range alerting.Types {
		types = append(types, string(typ))
	}
	schemas := specSchemas(t)
	for _, s := range []string{"AlertChannel", "CreateAlertChannelRequest"} {
		if got := schemas[s].Properties["type"].Enum; !sameSet(got, types) {
			t.Errorf("%s.type = %v, want %v", s, got, types)
		}
	}
	for _, s := range []string{"CreateAlertChannelRequest", "UpdateAlertChannelRequest"} {
		p := schemas[s].Properties
		if p["name"].MaxLength != alerting.MaxNameLength || p["url"].MaxLength != alerting.MaxURLLength {
			t.Errorf("%s: limits %+v differ from the code", s, p)
		}
	}
	h := schemas["AlertChannelHeader"].Properties
	if h["name"].MaxLength != alerting.MaxHeaderNameLength || h["value"].MaxLength != alerting.MaxHeaderValueLength {
		t.Errorf("AlertChannelHeader: limits %+v differ from the code", h)
	}
	if got := schemas["AlertChannelList"].Properties["alert_channels"].MaxItems; got != alerting.MaxChannels {
		t.Errorf("AlertChannelList.alert_channels.maxItems = %d, want %d", got, alerting.MaxChannels)
	}
	if got := schemas["CreateAlertChannelRequest"].Required; !sameSet(got, []string{"name", "type", "url"}) {
		t.Errorf("CreateAlertChannelRequest.required = %v", got)
	}
	fields := []string{alerting.FieldName, alerting.FieldEnabled, alerting.FieldURL, alerting.FieldHeader, "password"}
	if got := slices.Collect(maps.Keys(schemas["UpdateAlertChannelRequest"].Properties)); !sameSet(got, fields) {
		t.Errorf("UpdateAlertChannelRequest properties = %v, want the fields of a change and the password %v", got, fields)
	}
}

func sameSet(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}
