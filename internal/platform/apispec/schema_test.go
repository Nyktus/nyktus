// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package apispec

import (
	"strings"
	"testing"
)

const schemaSpec = `
openapi: 3.1.0
components:
  schemas:
    Thing:
      type: object
      additionalProperties: false
      required: [id, kind]
      properties:
        id: {type: string, format: uuid}
        kind: {type: string, enum: [a, b]}
        code: {type: string, pattern: "^[A-Z]{2}$"}
        at: {type: string, format: date-time}
        count: {type: integer, minimum: 1, maximum: 9}
        ratio: {type: number}
        on: {type: boolean}
        note: {type: [string, "null"]}
        tags: {type: array, items: {type: string}}
        part: {$ref: "#/components/schemas/Part"}
        either:
          oneOf:
            - {type: string}
            - {type: integer}
    Part:
      type: object
      additionalProperties: false
      properties:
        n: {type: integer}
    Open:
      type: object
      properties:
        n: {type: integer}
    Overlap:
      oneOf:
        - {type: integer}
        - {type: number}
    Broken:
      $ref: "#/components/schemas/Missing"
    ArrayWithoutItems:
      type: array
`

const thingID = `"id":"0b0c3a60-6c55-4b4b-8a2c-2d0c1e7f9a10"`

func TestSchemas_Check(t *testing.T) {
	t.Parallel()
	schemas, err := ParseSchemas([]byte(schemaSpec))
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name   string
		schema string
		body   string
		// problem is part of the only problem reported, or empty for none.
		problem string
	}{
		{"complete", "Thing", `{` + thingID + `,"kind":"a","code":"DE","at":"2026-10-17T10:00:00.5Z","count":9,` +
			`"ratio":0.5,"on":true,"note":null,"tags":["x"],"part":{"n":1},"either":"x"}`, ""},
		{"number accepts an integer", "Thing", `{` + thingID + `,"kind":"a","ratio":1}`, ""},
		{"nullable type accepts a string", "Thing", `{` + thingID + `,"kind":"a","note":"x"}`, ""},
		{"unknown schema", "Nothing", `{}`, "has no schema Nothing"},
		{"not JSON", "Thing", `{`, "not JSON"},
		{"missing member", "Thing", `{` + thingID + `}`, "Thing.kind: missing"},
		{"undocumented member", "Thing", `{` + thingID + `,"kind":"a","extra":1}`, "Thing.extra: not documented"},
		{"wrong type", "Thing", `{` + thingID + `,"kind":"a","on":"yes"}`, "Thing.on: string"},
		{"null where not allowed", "Thing", `{` + thingID + `,"kind":"a","code":null}`, "Thing.code: null"},
		{"fraction for an integer", "Thing", `{` + thingID + `,"kind":"a","count":1.5}`, "Thing.count: number"},
		{"not in enum", "Thing", `{` + thingID + `,"kind":"c"}`, "Thing.kind: c not in"},
		{"pattern", "Thing", `{` + thingID + `,"kind":"a","code":"de"}`, "does not match"},
		{"uuid", "Thing", `{"id":"0B0C3A60-6C55-4B4B-8A2C-2D0C1E7F9A10","kind":"a"}`, "is not a uuid"},
		{"date-time", "Thing", `{` + thingID + `,"kind":"a","at":"2026-10-17"}`, "is not a date-time"},
		{"below minimum", "Thing", `{` + thingID + `,"kind":"a","count":0}`, "out of bounds"},
		{"above maximum", "Thing", `{` + thingID + `,"kind":"a","count":10}`, "out of bounds"},
		{"item", "Thing", `{` + thingID + `,"kind":"a","tags":[1]}`, "Thing.tags[0]: integer"},
		{"reference", "Thing", `{` + thingID + `,"kind":"a","part":{"m":1}}`, "Thing.part.m: not documented"},
		{"no alternative of oneOf", "Thing", `{` + thingID + `,"kind":"a","either":true}`, "matches 0 schemas"},
		{"several alternatives of oneOf", "Overlap", `1`, "matches 2 schemas"},
		{"schema allows undocumented members", "Open", `{"n":1}`, "allows undocumented members"},
		{"unknown reference", "Broken", `{}`, "unknown reference"},
		{"array without items", "ArrayWithoutItems", `[]`, "schema of the items is missing"},
	} {
		got := schemas.Check(tt.schema, []byte(tt.body))
		switch {
		case tt.problem == "" && len(got) != 0:
			t.Errorf("%s: problems %q, want none", tt.name, got)
		case tt.problem != "" && (len(got) != 1 || !strings.Contains(got[0], tt.problem)):
			t.Errorf("%s: problems %q, want only one with %q", tt.name, got, tt.problem)
		}
	}
}

func TestParseSchemas_RejectsInvalidYAML(t *testing.T) {
	t.Parallel()
	if _, err := ParseSchemas([]byte("components: [")); err == nil {
		t.Error("ParseSchemas accepted invalid YAML")
	}
}
