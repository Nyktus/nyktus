// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package apispec

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Schema is the part of a JSON schema of the specification that the
// responses of the API use.
type Schema struct {
	Ref string `yaml:"$ref"`
	// Type is a type or a list of types, such as [string, "null"].
	Type                 any                `yaml:"type"`
	Required             []string           `yaml:"required"`
	Properties           map[string]*Schema `yaml:"properties"`
	AdditionalProperties *bool              `yaml:"additionalProperties"`
	Items                *Schema            `yaml:"items"`
	OneOf                []*Schema          `yaml:"oneOf"`
	Enum                 []any              `yaml:"enum"`
	Pattern              string             `yaml:"pattern"`
	Format               string             `yaml:"format"`
	Minimum              *float64           `yaml:"minimum"`
	Maximum              *float64           `yaml:"maximum"`
}

// Types returns the types that s allows.
func (s *Schema) Types() []string {
	switch t := s.Type.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, v := range t {
			out = append(out, fmt.Sprint(v))
		}
		return out
	}
	return nil
}

// EnumStrings returns the values of the enum of s that are strings, such as
// to compare them with the constants of the code.
func (s *Schema) EnumStrings() []string {
	var out []string
	for _, v := range s.Enum {
		if str, ok := v.(string); ok {
			out = append(out, str)
		}
	}
	return out
}

// Schemas are the schemas of the components of a specification, by name.
type Schemas map[string]*Schema

// ParseSchemas reads the schemas of the components of an OpenAPI document.
func ParseSchemas(data []byte) (Schemas, error) {
	var doc struct {
		Components struct {
			Schemas Schemas `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse specification: %w", err)
	}
	return doc.Components.Schemas, nil
}

// Check reports where the JSON body does not match the schema name: its
// types, required and undocumented members, enums, patterns, formats and
// bounds. A schema of an object must forbid undocumented members, so that a
// member added to the code fails until it is documented. It is a small
// validator for the schemas of this specification, not of JSON Schema in
// general: a construct it does not know is reported as a problem.
func (s Schemas) Check(name string, body []byte) []string {
	schema, ok := s[name]
	if !ok {
		return []string{"the specification has no schema " + name}
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return []string{fmt.Sprintf("%s: not JSON: %v", name, err)}
	}
	return s.check(schema, v, name)
}

func (s Schemas) check(schema *Schema, v any, at string) []string {
	if schema.Ref != "" {
		ref, ok := s[strings.TrimPrefix(schema.Ref, "#/components/schemas/")]
		if !ok {
			return []string{fmt.Sprintf("%s: unknown reference %s", at, schema.Ref)}
		}
		return s.check(ref, v, at)
	}
	if len(schema.OneOf) > 0 {
		matches := 0
		for _, alt := range schema.OneOf {
			if len(s.check(alt, v, at)) == 0 {
				matches++
			}
		}
		if matches != 1 {
			return []string{fmt.Sprintf("%s: matches %d schemas of oneOf, want 1", at, matches)}
		}
		return nil
	}

	types := schema.Types()
	typ := jsonType(v)
	if !slices.Contains(types, typ) && (typ != "integer" || !slices.Contains(types, "number")) {
		return []string{fmt.Sprintf("%s: %s, want %v", at, typ, types)}
	}
	if len(schema.Enum) > 0 && !slices.Contains(schema.Enum, v) {
		return []string{fmt.Sprintf("%s: %v not in %v", at, v, schema.Enum)}
	}

	var problems []string
	switch v := v.(type) {
	case map[string]any:
		for _, name := range schema.Required {
			if _, ok := v[name]; !ok {
				problems = append(problems, at+"."+name+": missing")
			}
		}
		for name, value := range v {
			prop, ok := schema.Properties[name]
			if !ok {
				problems = append(problems, at+"."+name+": not documented")
				continue
			}
			problems = append(problems, s.check(prop, value, at+"."+name)...)
		}
		if schema.AdditionalProperties == nil || *schema.AdditionalProperties {
			problems = append(problems, at+": the schema allows undocumented members")
		}
	case []any:
		if schema.Items == nil {
			return []string{at + ": the schema of the items is missing"}
		}
		for i, item := range v {
			problems = append(problems, s.check(schema.Items, item, fmt.Sprintf("%s[%d]", at, i))...)
		}
	case string:
		if schema.Pattern != "" && !regexp.MustCompile(schema.Pattern).MatchString(v) {
			problems = append(problems, fmt.Sprintf("%s: %q does not match %s", at, v, schema.Pattern))
		}
		if !validFormat(schema.Format, v) {
			problems = append(problems, fmt.Sprintf("%s: %q is not a %s", at, v, schema.Format))
		}
	case float64:
		if (schema.Minimum != nil && v < *schema.Minimum) || (schema.Maximum != nil && v > *schema.Maximum) {
			problems = append(problems, fmt.Sprintf("%s: %v out of bounds", at, v))
		}
	}
	return problems
}

// jsonType names the type of a value decoded from JSON as JSON Schema does.
// A number without a fraction is an integer.
func jsonType(v any) string {
	switch v := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case float64:
		if v == float64(int64(v)) {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	default:
		return "object"
	}
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// validFormat checks the formats whose form the API promises. Other formats,
// such as uri, are descriptions only.
func validFormat(format, v string) bool {
	switch format {
	case "uuid":
		return uuidPattern.MatchString(v)
	case "date-time":
		_, err := time.Parse(time.RFC3339Nano, v)
		return err == nil
	}
	return true
}
