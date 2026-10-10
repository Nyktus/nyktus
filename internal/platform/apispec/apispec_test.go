// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package apispec

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/platform/httpx"
)

const validSpec = `
openapi: 3.1.0
paths:
  /livez:
    get:
      operationId: getLiveness
      x-access: public
      responses:
        "200": {description: ok}
  /api/v1/users/{id}:
    parameters:
      - {name: id, in: path, required: true, schema: {type: string}}
    get:
      operationId: getUser
      x-access: users:read
      responses:
        "200": {description: ok}
    delete:
      operationId: deleteUser
      x-access: users:write
      responses:
        "204": {description: deleted}
  /api/v1/me:
    get:
      operationId: getMe
      x-access: authenticated
      responses:
        "200": {description: ok}
`

func TestParse_ReadsOperations(t *testing.T) {
	t.Parallel()

	spec, err := Parse([]byte(validSpec))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	want := []Operation{
		{Method: http.MethodGet, Path: "/api/v1/me", OperationID: "getMe", Access: "authenticated"},
		{Method: http.MethodDelete, Path: "/api/v1/users/{id}", OperationID: "deleteUser", Access: "users:write"},
		{Method: http.MethodGet, Path: "/api/v1/users/{id}", OperationID: "getUser", Access: "users:read"},
		{Method: http.MethodGet, Path: "/livez", OperationID: "getLiveness", Access: "public"},
	}
	if !slices.Equal(spec.Operations, want) {
		t.Errorf("Operations = %+v, want %+v", spec.Operations, want)
	}
}

func TestParse_RejectsInvalidSpecifications(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec string
		want []string
	}{
		{
			name: "unsupported version",
			spec: "openapi: 3.0.3\npaths: {}\n",
			want: []string{`openapi version "3.0.3" is not supported`},
		},
		{
			name: "missing declarations",
			spec: `
openapi: 3.1.0
paths:
  /a:
    get:
      responses: {}
`,
			want: []string{"GET /a: operationId is missing", `GET /a: x-access "" must be`, "GET /a: no responses are documented"},
		},
		{
			name: "duplicate operationId and invalid access",
			spec: `
openapi: 3.1.0
paths:
  /a:
    get: {operationId: same, x-access: admin, responses: {"200": {description: ok}}}
  /b:
    get: {operationId: same, x-access: public, responses: {"200": {description: ok}}}
`,
			want: []string{`GET /a: x-access "admin" must be`, `GET /b: operationId "same" is already used by GET /a`},
		},
		{
			name: "misspelled method",
			spec: `
openapi: 3.1.0
paths:
  /a:
    gte: {operationId: a, x-access: public, responses: {"200": {description: ok}}}
`,
			want: []string{`/a: unknown field "gte"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte(tt.spec))
			if err == nil {
				t.Fatal("Parse() accepted an invalid specification")
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not contain %q:\n%v", want, err)
				}
			}
		})
	}
}

func TestCompare(t *testing.T) {
	t.Parallel()

	spec, err := Parse([]byte(validSpec))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	matching := []httpx.Route{
		{Method: http.MethodGet, Path: "/livez", Access: httpx.Public},
		{Method: http.MethodGet, Path: "/api/v1/users/{id}", Access: httpx.Require("users:read")},
		{Method: http.MethodDelete, Path: "/api/v1/users/{id}", Access: httpx.Require("users:write")},
		{Method: http.MethodGet, Path: "/api/v1/me", Access: httpx.Authenticated},
	}

	tests := []struct {
		name   string
		routes []httpx.Route
		want   []string
	}{
		{name: "matching", routes: matching},
		{
			name:   "undocumented route",
			routes: append(slices.Clone(matching), httpx.Route{Method: http.MethodPost, Path: "/api/v1/users", Access: httpx.Require("users:write")}),
			want:   []string{"route POST /api/v1/users is not documented"},
		},
		{
			name:   "unrouted operation",
			routes: matching[:3],
			want:   []string{"operation GET /api/v1/me (getMe) is documented but not routed"},
		},
		{
			name: "different access",
			routes: []httpx.Route{
				matching[0],
				{Method: http.MethodGet, Path: "/api/v1/users/{id}", Access: httpx.Authenticated},
				{Method: http.MethodDelete, Path: "/api/v1/users/{id}", Access: httpx.Require("users:read")},
				matching[3],
			},
			want: []string{
				`route GET /api/v1/users/{id} has access "authenticated", but the specification declares "users:read"`,
				`route DELETE /api/v1/users/{id} has access "users:read", but the specification declares "users:write"`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := spec.Compare(tt.routes)
			if len(got) != len(tt.want) {
				t.Fatalf("Compare() = %q, want %d problems", got, len(tt.want))
			}
			for i, want := range tt.want {
				if !strings.Contains(got[i], want) {
					t.Errorf("problem %d = %q, want it to contain %q", i, got[i], want)
				}
			}
		})
	}
}
