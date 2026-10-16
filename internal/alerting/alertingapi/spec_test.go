// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package alertingapi

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/alerting"
	"nyktus.org/nyktus/internal/platform/smtp"
)

type schemaProperty struct {
	Enum      []string `yaml:"enum"`
	MaxLength int      `yaml:"maxLength"`
	MaxItems  int      `yaml:"maxItems"`
}

type schema struct {
	Required   []string                  `yaml:"required"`
	Properties map[string]schemaProperty `yaml:"properties"`
	MaxLength  int                       `yaml:"maxLength"`
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
	// The URL is required for every type but email, which has recipients
	// instead; the code checks which one a type needs.
	if got := schemas["CreateAlertChannelRequest"].Required; !sameSet(got, []string{"name", "type"}) {
		t.Errorf("CreateAlertChannelRequest.required = %v", got)
	}
	for _, s := range []string{"AlertChannel", "CreateAlertChannelRequest", "UpdateAlertChannelRequest"} {
		if got := schemas[s].Properties["recipients"].MaxItems; got != alerting.MaxRecipients {
			t.Errorf("%s.recipients.maxItems = %d, want %d", s, got, alerting.MaxRecipients)
		}
	}
	if got := schemas["EmailAddress"].MaxLength; got != smtp.MaxAddressLength {
		t.Errorf("EmailAddress.maxLength = %d, want %d", got, smtp.MaxAddressLength)
	}
	fields := []string{
		alerting.FieldName, alerting.FieldEnabled, alerting.FieldURL, alerting.FieldHeader, alerting.FieldRecipients,
		"password",
	}
	if got := slices.Collect(maps.Keys(schemas["UpdateAlertChannelRequest"].Properties)); !sameSet(got, fields) {
		t.Errorf("UpdateAlertChannelRequest properties = %v, want the fields of a change and the password %v", got, fields)
	}
}

// The states and classes of failure of a delivery live in code, in the schema
// and in the specification.
func TestSpecification_MatchesTheDeliveries(t *testing.T) {
	t.Parallel()

	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Enum    []any `yaml:"enum"`
					Maximum int   `yaml:"maximum"`
				} `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(api.OpenAPI(), &spec); err != nil {
		t.Fatal(err)
	}
	p := spec.Components.Schemas["AlertDelivery"].Properties
	strs := func(values []any) []string {
		var out []string
		for _, v := range values {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	var statuses, failures, types []string
	for _, s := range alerting.Statuses {
		statuses = append(statuses, string(s))
	}
	for _, f := range alerting.Failures {
		failures = append(failures, string(f))
	}
	for _, typ := range alerting.Types {
		types = append(types, string(typ))
	}
	if got := strs(p["status"].Enum); !sameSet(got, statuses) {
		t.Errorf("status = %v, want %v", got, statuses)
	}
	if got := strs(p["last_error"].Enum); !sameSet(got, failures) {
		t.Errorf("last_error = %v, want %v", got, failures)
	}
	if got := strs(p["channel_type"].Enum); !sameSet(got, types) {
		t.Errorf("channel_type = %v, want %v", got, types)
	}
	if p["attempts"].Maximum != alerting.MaxAttempts {
		t.Errorf("attempts.maximum = %d, want %d", p["attempts"].Maximum, alerting.MaxAttempts)
	}
}

func sameSet(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

// The responses for every kind of channel hold exactly the members of the
// schema, each of a type that the schema allows: target and recipients are
// null where the type has none.
func TestResponses_MatchTheSchemaOfAChannel(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Required   []string `yaml:"required"`
				Properties map[string]struct {
					Type any `yaml:"type"`
				} `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(api.OpenAPI(), &spec); err != nil {
		t.Fatal(err)
	}
	schema := spec.Components.Schemas["AlertChannel"]
	allowed := func(name string) []string {
		switch typ := schema.Properties[name].Type.(type) {
		case string:
			return []string{typ}
		case []any:
			var out []string
			for _, v := range typ {
				out = append(out, fmt.Sprint(v))
			}
			return out
		}
		return nil
	}
	jsonType := func(v any) string {
		switch v.(type) {
		case nil:
			return "null"
		case string:
			return "string"
		case bool:
			return "boolean"
		case []any:
			return "array"
		case map[string]any:
			return "object"
		default:
			return "number"
		}
	}

	bodies := map[string]string{
		"webhook": webhookBody("SOAR"),
		"email":   `{"name":"SOC","type":"email","recipients":["soc@example.com"],"password":"` + password + `"}`,
	}
	for typ, body := range bodies {
		rec := f.serve(t, f.h.Create, http.MethodPost, "", body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("%s: status %d, body %s", typ, rec.Code, rec.Body)
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if keys := slices.Collect(maps.Keys(got)); !sameSet(keys, slices.Collect(maps.Keys(schema.Properties))) {
			t.Errorf("%s: members %v, want those of the schema", typ, keys)
		}
		for _, name := range schema.Required {
			if _, ok := got[name]; !ok {
				t.Errorf("%s: required member %s missing", typ, name)
			}
		}
		for name, v := range got {
			if !slices.Contains(allowed(name), jsonType(v)) {
				t.Errorf("%s: %s is %s, want one of %v", typ, name, jsonType(v), allowed(name))
			}
		}
		if (got["target"] == nil) != (typ == "email") || (got["recipients"] == nil) != (typ != "email") {
			t.Errorf("%s: target %v, recipients %v", typ, got["target"], got["recipients"])
		}
	}
}
