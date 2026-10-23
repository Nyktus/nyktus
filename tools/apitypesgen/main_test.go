// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"nyktus.org/nyktus/api"
)

var update = flag.Bool("update", false, "rewrite the golden file and the committed types")

func compareOrUpdate(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil { //nolint:gosec // A source file of the repository.
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) //nolint:gosec // A fixed path of the repository.
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s is out of date; regenerate it with go test ./tools/apitypesgen -update\n\ngot:\n%s", path, got)
	}
}

// A small specification covers what the generator maps: references, enums,
// nullable types, constants, maps, unions, optional members, parameters,
// bodies, responses of every kind and redirects. Regenerate the golden file
// with go test ./tools/apitypesgen -update.
func TestGenerate_MatchesGoldenFile(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("testdata", "spec.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := generate(spec, grants{{"admin", []string{"things:read", "things:write"}}, {"viewer", []string{"things:read"}}},
		keyScopes{scopes: []string{"things:read", "things:write", "other:read"}, requires: map[string]string{"things:write": "things:read"}})
	if err != nil {
		t.Fatalf("generate() error = %v", err)
	}
	compareOrUpdate(t, filepath.Join("testdata", "types.golden.ts"), got)
}

// The types of the web console are committed, so that a change of the
// specification shows in review. They must be the ones the specification yields.
func TestCommittedTypes_MatchTheSpecification(t *testing.T) {
	got, err := generate(api.OpenAPI(), roleGrants(), serverKeyScopes())
	if err != nil {
		t.Fatalf("generate() error = %v", err)
	}
	compareOrUpdate(t, filepath.Join("..", "..", "web", "src", "api", "generated.ts"), got)
}

func TestGenerate_RejectsWhatItCannotMap(t *testing.T) {
	t.Parallel()

	const head = "openapi: 3.1.0\npaths: {}\ncomponents:\n  schemas:\n    X:\n"
	tests := []struct {
		name string
		spec string
		want string
	}{
		{"no type", head + "      description: untyped\n", "without type"},
		{"unknown type", head + "      type: tuple\n", `unsupported type "tuple"`},
		{"array without items", head + "      type: array\n", "without items"},
		{"external reference", head + "      $ref: other.yaml#/X\n", "unsupported reference"},
		{"all of", head + "      allOf: [{type: string}]\n", `keyword "allOf" is not supported`},
		{"any of", head + "      type: string\n      anyOf: [{enum: [a]}, {enum: [b]}]\n", `keyword "anyOf" is not supported`},
		{"pattern properties", head + "      type: object\n      patternProperties: {'^a': {type: string}}\n", `keyword "patternProperties" is not supported`},
		{"nested keyword", head + "      type: object\n      properties: {a: {type: array, items: {not: {type: string}}}}\n", `keyword "not" is not supported`},
		{
			"range of statuses",
			"openapi: 3.1.0\npaths:\n  /a:\n    get: {operationId: a, x-access: public, responses: {'2XX': {description: ok}}}\ncomponents: {schemas: {}}\n",
			"no status code",
		},
		{
			"status below the first class",
			"openapi: 3.1.0\npaths:\n  /a:\n    get: {operationId: a, x-access: public, responses: {'099': {description: ok}}}\ncomponents: {schemas: {}}\n",
			"no status code",
		},
		{
			"status above the last class",
			"openapi: 3.1.0\npaths:\n  /a:\n    get: {operationId: a, x-access: public, responses: {'600': {description: ok}}}\ncomponents: {schemas: {}}\n",
			"no status code",
		},
		{"members and map", head + "      type: object\n      properties: {a: {type: string}}\n      additionalProperties: {type: string}\n", "further members"},
		{
			"repeated operation id",
			"openapi: 3.1.0\npaths:\n  /a:\n    get: {operationId: a, x-access: public, responses: {'200': {description: ok}}}\n  /b:\n    get: {operationId: a, x-access: public, responses: {'200': {description: ok}}}\ncomponents: {schemas: {}}\n",
			"repeated",
		},
		{
			"wildcard without parameter",
			"openapi: 3.1.0\npaths:\n  /a/{id}:\n    get: {operationId: a, x-access: public, responses: {'200': {description: ok}}}\ncomponents: {schemas: {}}\n",
			"path parameters",
		},
		{
			"cookie parameter",
			"openapi: 3.1.0\npaths:\n  /a:\n    get:\n      operationId: a\n      x-access: public\n      parameters: [{name: c, in: cookie, schema: {type: string}}]\n      responses: {'200': {description: ok}}\ncomponents: {schemas: {}}\n",
			"not supported",
		},
		{
			"form body",
			"openapi: 3.1.0\npaths:\n  /a:\n    post:\n      operationId: a\n      x-access: public\n      requestBody: {content: {application/x-www-form-urlencoded: {schema: {type: object}}}}\n      responses: {'200': {description: ok}}\ncomponents: {schemas: {}}\n",
			"application/json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := generate([]byte(tt.spec), nil, keyScopes{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("generate() error = %v, want one that contains %q", err, tt.want)
			}
		})
	}
}

// The scopes that the console offers are the ones that the server accepts, every
// requirement is itself a scope, and keys never carry the permissions that would
// let a leaked key take over accounts, keys or the alerts.
func TestServerKeyScopes_MatchTheServer(t *testing.T) {
	t.Parallel()

	keys := serverKeyScopes()
	if len(keys.scopes) == 0 {
		t.Fatal("no scopes")
	}
	for scope, required := range keys.requires {
		if !slices.Contains(keys.scopes, scope) || !slices.Contains(keys.scopes, required) {
			t.Errorf("%s requires %s, and one of them is no scope", scope, required)
		}
	}
	if keys.requires["incidents:write"] != "incidents:read" {
		t.Errorf("incidents:write requires %q, want incidents:read", keys.requires["incidents:write"])
	}
	for _, never := range []string{"users:write", "api_keys:write", "alert_channels:write"} {
		if slices.Contains(keys.scopes, never) {
			t.Errorf("a key may carry %s", never)
		}
	}
}

func TestScopes_ListsTheScopesAndWhatTheyRequire(t *testing.T) {
	t.Parallel()

	got := scopes(keyScopes{scopes: []string{"a:read", "a:write", "b:read"}, requires: map[string]string{"a:write": "a:read", "b:read": "a:read"}})
	for _, want := range []string{
		"export const keyScopes = ['a:read', 'a:write', 'b:read'] as const;",
		"export type KeyScope = (typeof keyScopes)[number];",
		"  'a:write': 'a:read',\n  'b:read': 'a:read',\n};",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("scopes() lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "'a:read': ") {
		t.Errorf("a scope that requires nothing is listed as requiring something:\n%s", got)
	}
}
