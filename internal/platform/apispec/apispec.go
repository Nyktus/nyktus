// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package apispec reads the OpenAPI specification and compares it with the routes
// of a router. Tests use it to keep the contract and the implementation in sync,
// including the access requirement of every operation.
package apispec

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/internal/platform/httpx"
)

// Operation is a method and path of the specification with its declared access.
type Operation struct {
	Method      string
	Path        string
	OperationID string
	Access      string
}

func (o Operation) key() string { return o.Method + " " + o.Path }

// Spec holds the operations of a specification.
type Spec struct {
	Operations []Operation
}

var (
	methods = map[string]string{
		"get": http.MethodGet, "put": http.MethodPut, "post": http.MethodPost, "delete": http.MethodDelete,
		"patch": http.MethodPatch, "head": http.MethodHead, "options": http.MethodOptions, "trace": http.MethodTrace,
	}
	// pathItemFields are the fields of an OpenAPI path item that are not operations.
	pathItemFields = []string{"summary", "description", "servers", "parameters"}
)

type document struct {
	OpenAPI string                          `yaml:"openapi"`
	Paths   map[string]map[string]yaml.Node `yaml:"paths"`
}

type operation struct {
	OperationID string         `yaml:"operationId"`
	Access      string         `yaml:"x-access"`
	Responses   map[string]any `yaml:"responses"`
}

// Parse reads an OpenAPI 3.1 document and validates the properties the project
// relies on: every operation has a unique operationId, at least one response and a
// valid x-access declaration. All problems are reported together.
func Parse(data []byte) (*Spec, error) {
	var doc document
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse specification: %w", err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.1.") {
		return nil, fmt.Errorf("openapi version %q is not supported; use 3.1.x", doc.OpenAPI)
	}

	var (
		spec Spec
		errs []error
		ids  = make(map[string]string)
	)
	// Sorted, so that problems are reported in a stable order.
	for _, path := range slices.Sorted(maps.Keys(doc.Paths)) {
		item := doc.Paths[path]
		if _, ok := item["$ref"]; ok {
			errs = append(errs, fmt.Errorf("%s: $ref path items are not supported; define the operations inline", path))
			continue
		}
		operations := 0
		for _, field := range slices.Sorted(maps.Keys(item)) {
			method, ok := methods[field]
			if !ok {
				if !slices.Contains(pathItemFields, field) && !strings.HasPrefix(field, "x-") {
					errs = append(errs, fmt.Errorf("%s: unknown field %q", path, field))
				}
				continue
			}
			operations++
			node := item[field]
			var op operation
			if err := node.Decode(&op); err != nil {
				errs = append(errs, fmt.Errorf("%s %s: %w", method, path, err))
				continue
			}
			o := Operation{Method: method, Path: path, OperationID: op.OperationID, Access: op.Access}
			errs = append(errs, validate(o.key(), op, ids)...)
			spec.Operations = append(spec.Operations, o)
		}
		if operations == 0 {
			errs = append(errs, fmt.Errorf("%s: path has no operations", path))
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &spec, nil
}

func validate(key string, op operation, ids map[string]string) []error {
	var errs []error
	switch other, seen := ids[op.OperationID]; {
	case op.OperationID == "":
		errs = append(errs, fmt.Errorf("%s: operationId is missing", key))
	case seen:
		errs = append(errs, fmt.Errorf("%s: operationId %q is already used by %s", key, op.OperationID, other))
	default:
		ids[op.OperationID] = key
	}

	if len(op.Responses) == 0 {
		errs = append(errs, fmt.Errorf("%s: no responses are documented", key))
	}
	// Protected operations document how they are denied, so that clients and the
	// published documentation see the authentication surface the router enforces.
	switch {
	case !validAccess(op.Access):
		errs = append(errs, fmt.Errorf("%s: x-access %q must be public, authenticated or resource:action", key, op.Access))
	case op.Access == httpx.Public.String():
	default:
		if _, ok := op.Responses["401"]; !ok {
			errs = append(errs, fmt.Errorf("%s: protected operation does not document response 401", key))
		}
		if _, ok := op.Responses["403"]; !ok && op.Access != httpx.Authenticated.String() {
			errs = append(errs, fmt.Errorf("%s: operation that requires %s does not document response 403", key, op.Access))
		}
	}
	return errs
}

// validAccess accepts the values that httpx.Access.String produces for a declared
// access, so that the specification and the router share one permission format.
func validAccess(access string) bool {
	return access == httpx.Public.String() || access == httpx.Authenticated.String() || httpx.Permission(access).Valid()
}

// Compare reports every difference between the specification and routes: routes
// that are not documented, documented operations that are not routed, and
// operations whose access requirement differs.
func (s *Spec) Compare(routes []httpx.Route) []string {
	documented := make(map[string]Operation, len(s.Operations))
	for _, o := range s.Operations {
		documented[o.key()] = o
	}

	var problems []string
	routed := make(map[string]bool, len(routes))
	for _, r := range routes {
		key := Operation{Method: r.Method, Path: r.Path}.key()
		routed[key] = true
		o, ok := documented[key]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("route %s is not documented in the specification", key))
		case o.Access != r.Access.String():
			problems = append(problems, fmt.Sprintf("route %s has access %q, but the specification declares %q", key, r.Access, o.Access))
		}
	}
	for _, o := range s.Operations {
		if !routed[o.key()] {
			problems = append(problems, fmt.Sprintf("operation %s (%s) is documented but not routed", o.key(), o.OperationID))
		}
	}
	return problems
}
