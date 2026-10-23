// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command apitypesgen writes the TypeScript types of the web console from the
// OpenAPI specification: one type for every schema, and for every operation its
// method, path, access, parameters, body and successful responses.
//
// The web console is written by hand against these types, so a change of the
// specification that the console does not follow fails its type check. The
// output is committed, and a test compares it with the specification. After
// changing api/openapi.yaml, run
//
//	go run ./tools/apitypesgen
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/user"
)

func main() {
	out := flag.String("out", "web/src/api/generated.ts", "write the types to this file")
	flag.Parse()

	b, err := generate(api.OpenAPI(), roleGrants())
	if err == nil {
		err = os.WriteFile(*out, b, 0o644) //nolint:gosec // A source file of the repository, readable by everyone.
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "apitypesgen:", err)
		os.Exit(1)
	}
}

// ordered is a mapping of YAML that keeps the order of its keys, so that the
// types follow the order of the specification.
type ordered[V any] struct {
	keys   []string
	values map[string]V
}

func (o *ordered[V]) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: want a mapping", n.Line)
	}
	o.values = make(map[string]V, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		var v V
		if err := n.Content[i+1].Decode(&v); err != nil {
			return err
		}
		key := n.Content[i].Value
		o.keys = append(o.keys, key)
		o.values[key] = v
	}
	return nil
}

// schema is the part of a JSON schema that the specification uses.
//
// Keywords that change what a value may be, such as allOf, anyOf or
// patternProperties, would make a generated type wider or narrower than the
// specification without a sign, so a schema that uses one is refused.
type schema struct {
	Ref                  string                `yaml:"$ref"`
	Type                 any                   `yaml:"type"`
	Properties           ordered[*schema]      `yaml:"properties"`
	Required             []string              `yaml:"required"`
	AdditionalProperties *additionalProperties `yaml:"additionalProperties"`
	Items                *schema               `yaml:"items"`
	OneOf                []*schema             `yaml:"oneOf"`
	Enum                 []any                 `yaml:"enum"`
	Const                any                   `yaml:"const"`
}

// mapped are the keywords that decide the type of a schema.
var mapped = map[string]bool{
	"$ref": true, "type": true, "properties": true, "required": true, "additionalProperties": true,
	"items": true, "oneOf": true, "enum": true, "const": true,
}

// annotations are keywords that narrow or describe a value without changing its
// TypeScript type, which a check at run time or a reader of the specification uses.
var annotations = map[string]bool{
	"description": true, "title": true, "examples": true, "example": true, "default": true, "format": true,
	"deprecated": true, "readOnly": true, "writeOnly": true, "pattern": true,
	"minLength": true, "maxLength": true, "minimum": true, "maximum": true, "exclusiveMinimum": true,
	"exclusiveMaximum": true, "multipleOf": true, "minItems": true, "maxItems": true, "uniqueItems": true,
	"minProperties": true, "maxProperties": true,
}

func (s *schema) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if k := n.Content[i].Value; !mapped[k] && !annotations[k] && !strings.HasPrefix(k, "x-") {
				return fmt.Errorf("line %d: the schema keyword %q is not supported", n.Content[i].Line, k)
			}
		}
	}
	type plain schema
	return n.Decode((*plain)(s))
}

// additionalProperties is false, true, or the schema of every member of a map.
type additionalProperties struct {
	allowed bool
	schema  *schema
}

func (a *additionalProperties) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		return n.Decode(&a.allowed)
	}
	a.allowed, a.schema = true, &schema{}
	return n.Decode(a.schema)
}

type parameter struct {
	Name     string  `yaml:"name"`
	In       string  `yaml:"in"`
	Required bool    `yaml:"required"`
	Schema   *schema `yaml:"schema"`
}

type mediaType struct {
	Schema *schema `yaml:"schema"`
}

type response struct {
	Content ordered[mediaType] `yaml:"content"`
}

type operation struct {
	OperationID string                                `yaml:"operationId"`
	Access      string                                `yaml:"x-access"`
	Parameters  []parameter                           `yaml:"parameters"`
	RequestBody *struct{ Content ordered[mediaType] } `yaml:"requestBody"`
	Responses   ordered[response]                     `yaml:"responses"`
}

type document struct {
	Paths      ordered[yaml.Node] `yaml:"paths"`
	Components struct {
		Schemas ordered[*schema] `yaml:"schemas"`
	} `yaml:"components"`
}

// methods are the methods of an operation in the order in which they are listed.
var methods = []string{"get", "put", "post", "patch", "delete", "head"}

// grants lists the permissions of each role, in the order in which the roles
// are generated.
type grants []struct {
	role        string
	permissions []string
}

// roleGrants returns what the server grants to each role.
func roleGrants() grants {
	var out grants
	for _, role := range []user.Role{user.RoleAdmin, user.RoleUser, user.RoleViewer} {
		g := struct {
			role        string
			permissions []string
		}{role: string(role)}
		for _, p := range access.Permissions() {
			if access.Allowed(role, p) {
				g.permissions = append(g.permissions, string(p))
			}
		}
		out = append(out, g)
	}
	return out
}

// generate returns the TypeScript module for the specification and the grants
// of the roles.
func generate(spec []byte, roles grants) ([]byte, error) {
	var doc document
	if err := yaml.Unmarshal(spec, &doc); err != nil {
		return nil, fmt.Errorf("parse specification: %w", err)
	}

	var b bytes.Buffer
	b.WriteString("// SPDX-FileCopyrightText: The Nyktus Authors\n// SPDX-License-Identifier: AGPL-3.0-or-later\n\n")
	b.WriteString("// Code generated by tools/apitypesgen from api/openapi.yaml. DO NOT EDIT.\n\n")

	var errs []error
	for _, name := range doc.Components.Schemas.keys {
		s := doc.Components.Schemas.values[name]
		decl, err := declaration(name, s)
		if err != nil {
			errs = append(errs, fmt.Errorf("schema %s: %w", name, err))
			continue
		}
		b.WriteString(decl)
		b.WriteString("\n")
	}

	ops, err := operations(&doc)
	if err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	b.WriteString(ops)
	b.WriteString("\n")
	b.WriteString(permissions(roles))
	return b.Bytes(), nil
}

// permissions returns what each role may do. The server decides; the console
// uses the table to hide what a role cannot use.
func permissions(roles grants) string {
	var b strings.Builder
	b.WriteString("/** What each role may do. The server decides; the console only hides what a role cannot use. */\n")
	b.WriteString("export const rolePermissions = {\n")
	for _, g := range roles {
		quoted := make([]string, len(g.permissions))
		for i, p := range g.permissions {
			quoted[i] = "'" + p + "'"
		}
		fmt.Fprintf(&b, "  %s: [%s],\n", g.role, strings.Join(quoted, ", "))
	}
	b.WriteString("} as const;\n\n")
	b.WriteString("export type Role = keyof typeof rolePermissions;\n\n")
	b.WriteString("export type Permission = (typeof rolePermissions)[Role][number];\n")
	return b.String()
}

// declaration returns the declaration of a schema of the components: an
// interface for an object with members, a type otherwise.
func declaration(name string, s *schema) (string, error) {
	if s.Ref == "" && len(s.OneOf) == 0 && slices.Equal(s.types(), []string{"object"}) && len(s.Properties.keys) > 0 {
		body, err := objectType(s, 0)
		if err != nil {
			return "", err
		}
		return "export interface " + name + " " + body + "\n", nil
	}
	t, err := tsType(s, 0)
	if err != nil {
		return "", err
	}
	return "export type " + name + " = " + t + ";\n", nil
}

func (s *schema) types() []string {
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

// tsType returns the TypeScript type of a schema. depth is the indentation of
// the line the type starts on, for the members of nested objects.
func tsType(s *schema, depth int) (string, error) {
	switch {
	case s.Ref != "":
		const prefix = "#/components/schemas/"
		if !strings.HasPrefix(s.Ref, prefix) {
			return "", fmt.Errorf("unsupported reference %s", s.Ref)
		}
		return strings.TrimPrefix(s.Ref, prefix), nil
	case len(s.OneOf) > 0:
		parts := make([]string, 0, len(s.OneOf))
		for _, alt := range s.OneOf {
			t, err := tsType(alt, depth)
			if err != nil {
				return "", err
			}
			parts = append(parts, t)
		}
		return strings.Join(parts, " | "), nil
	case s.Const != nil:
		return literal(s.Const)
	}

	types := s.types()
	if len(types) == 0 {
		return "", errors.New("a schema without type, reference, oneOf or const is not supported")
	}
	parts := make([]string, 0, len(types))
	for _, typ := range types {
		t, err := tsTypeOf(s, typ, depth)
		if err != nil {
			return "", err
		}
		parts = append(parts, t)
	}
	return union(parts), nil
}

// union joins alternatives, and drops a repetition such as the null of both a
// nullable type and an enum that lists null.
func union(parts []string) string {
	var out []string
	for _, p := range parts {
		for _, alt := range strings.Split(p, " | ") {
			if !slices.Contains(out, alt) {
				out = append(out, alt)
			}
		}
	}
	return strings.Join(out, " | ")
}

func tsTypeOf(s *schema, typ string, depth int) (string, error) {
	switch typ {
	case "null":
		return "null", nil
	case "boolean":
		return "boolean", nil
	case "integer", "number":
		if len(s.Enum) > 0 {
			return literals(s.Enum)
		}
		return "number", nil
	case "string":
		if len(s.Enum) > 0 {
			return literals(s.Enum)
		}
		return "string", nil
	case "array":
		if s.Items == nil {
			return "", errors.New("an array without items is not supported")
		}
		t, err := tsType(s.Items, depth)
		if err != nil {
			return "", err
		}
		if hasTopLevelOperator(t) {
			t = "(" + t + ")"
		}
		return t + "[]", nil
	case "object":
		return objectType(s, depth)
	}
	return "", fmt.Errorf("unsupported type %q", typ)
}

// hasTopLevelOperator reports whether a type is a union or an intersection that
// is not enclosed in brackets, quotes or braces, so that an array of it needs
// parentheses: {a: string} | null[] is not ({a: string} | null)[].
func hasTopLevelOperator(t string) bool {
	depth, quoted := 0, false
	for i := 0; i < len(t); i++ {
		c := t[i]
		if quoted {
			switch c {
			case '\\':
				i++
			case '\'':
				quoted = false
			}
			continue
		}
		switch c {
		case '\'':
			quoted = true
		case '{', '[', '(', '<':
			depth++
		case '}', ']', ')', '>':
			depth--
		case '|', '&':
			if depth == 0 {
				return true
			}
		}
	}
	return false
}

func objectType(s *schema, depth int) (string, error) {
	switch {
	case len(s.Properties.keys) > 0 && s.AdditionalProperties != nil && s.AdditionalProperties.schema != nil:
		return "", errors.New("an object with members and a schema for further members is not supported")
	case len(s.Properties.keys) > 0:
		return members(s, depth)
	case s.AdditionalProperties != nil && s.AdditionalProperties.schema != nil:
		t, err := tsType(s.AdditionalProperties.schema, depth)
		if err != nil {
			return "", err
		}
		return "Record<string, " + t + ">", nil
	}
	return "Record<string, unknown>", nil
}

// members returns the members of an object as a block that opens on a line
// indented by depth.
func members(s *schema, depth int) (string, error) {
	indent := strings.Repeat("  ", depth+1)
	var b strings.Builder
	b.WriteString("{\n")
	for _, name := range s.Properties.keys {
		t, err := tsType(s.Properties.values[name], depth+1)
		if err != nil {
			return "", fmt.Errorf("member %s: %w", name, err)
		}
		optional := ""
		if !slices.Contains(s.Required, name) {
			optional = "?"
		}
		b.WriteString(indent + key(name) + optional + ": " + t + ";\n")
	}
	b.WriteString(strings.Repeat("  ", depth) + "}")
	return b.String(), nil
}

func literals(values []any) (string, error) {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		l, err := literal(v)
		if err != nil {
			return "", err
		}
		parts = append(parts, l)
	}
	return strings.Join(parts, " | "), nil
}

func literal(v any) (string, error) {
	switch v := v.(type) {
	case nil:
		return "null", nil
	case string:
		return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`, "\n", `\n`).Replace(v) + "'", nil
	case int:
		return strconv.Itoa(v), nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(v), nil
	}
	return "", fmt.Errorf("unsupported value %v", v)
}

// key returns a member name, quoted unless it is an identifier.
func key(name string) string {
	for i, r := range name {
		letter := r == '_' || r == '$' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !letter && (i == 0 || r < '0' || r > '9') {
			return "'" + name + "'"
		}
	}
	return name
}

// operations returns the table of the operations and their types.
func operations(doc *document) (string, error) {
	type described struct {
		id, method, path, access string
		redirect                 bool
		types                    string
	}
	var (
		ops  []described
		errs []error
		seen = map[string]bool{}
	)
	for _, path := range doc.Paths.keys {
		item := doc.Paths.values[path]
		var raw map[string]yaml.Node
		if err := item.Decode(&raw); err != nil {
			return "", fmt.Errorf("path %s: %w", path, err)
		}
		var shared []parameter
		if p, ok := raw["parameters"]; ok {
			if err := p.Decode(&shared); err != nil {
				return "", fmt.Errorf("path %s: parameters: %w", path, err)
			}
		}
		for _, method := range methods {
			node, ok := raw[method]
			if !ok {
				continue
			}
			var op operation
			if err := node.Decode(&op); err != nil {
				errs = append(errs, fmt.Errorf("%s %s: %w", method, path, err))
				continue
			}
			if op.OperationID == "" || seen[op.OperationID] {
				errs = append(errs, fmt.Errorf("%s %s: operationId %q is missing or repeated", method, path, op.OperationID))
				continue
			}
			seen[op.OperationID] = true
			types, redirect, err := operationTypes(&op, path, mergeParameters(shared, op.Parameters))
			if err != nil {
				errs = append(errs, fmt.Errorf("%s %s: %w", strings.ToUpper(method), path, err))
				continue
			}
			ops = append(ops, described{op.OperationID, strings.ToUpper(method), path, op.Access, redirect, types})
		}
	}
	if err := errors.Join(errs...); err != nil {
		return "", err
	}
	slices.SortFunc(ops, func(a, b described) int { return strings.Compare(a.id, b.id) })

	var b strings.Builder
	b.WriteString("/** How an operation is reached: its method, path and the access the server requires. */\n")
	b.WriteString("export interface OperationInfo {\n  method: 'GET' | 'PUT' | 'POST' | 'PATCH' | 'DELETE' | 'HEAD';\n  path: string;\n")
	b.WriteString("  access: string;\n  /** The browser navigates to the operation; the page does not request it. */\n  navigation: boolean;\n}\n\n")
	b.WriteString("export const operations = {\n")
	for _, o := range ops {
		fmt.Fprintf(&b, "  %s: { method: '%s', path: '%s', access: '%s', navigation: %t },\n", o.id, o.method, o.path, o.access, o.redirect)
	}
	b.WriteString("} as const satisfies Record<string, OperationInfo>;\n\n")
	b.WriteString("export type OperationId = keyof typeof operations;\n\n")
	b.WriteString("/** The parameters, the body and the successful responses of every operation. */\n")
	b.WriteString("export interface OperationTypes {\n")
	for _, o := range ops {
		b.WriteString("  " + o.id + ": " + o.types + ";\n")
	}
	b.WriteString("}\n")
	return b.String(), nil
}

// mergeParameters returns the parameters of an operation: those of its path
// item, except where the operation declares one of the same name and location,
// which then replaces it.
func mergeParameters(shared, own []parameter) []parameter {
	out := make([]parameter, 0, len(shared)+len(own))
	for _, p := range shared {
		if !slices.ContainsFunc(own, func(o parameter) bool { return o.Name == p.Name && o.In == p.In }) {
			out = append(out, p)
		}
	}
	return append(out, own...)
}

// operationTypes returns the type of the parameters, the body and the
// successful responses of an operation, and whether it answers with a redirect.
func operationTypes(op *operation, route string, params []parameter) (string, bool, error) {
	var path, query []string
	for _, p := range params {
		if p.Schema == nil {
			return "", false, fmt.Errorf("parameter %s has no schema", p.Name)
		}
		t, err := tsType(p.Schema, 2)
		if err != nil {
			return "", false, fmt.Errorf("parameter %s: %w", p.Name, err)
		}
		switch p.In {
		case "path":
			path = append(path, key(p.Name)+": "+t)
		case "query":
			optional := "?"
			if p.Required {
				optional = ""
			}
			query = append(query, key(p.Name)+optional+": "+t)
		default:
			return "", false, fmt.Errorf("parameter %s is in %q, which is not supported", p.Name, p.In)
		}
	}

	if err := checkPathParameters(route, params); err != nil {
		return "", false, err
	}

	body := "undefined"
	if op.RequestBody != nil {
		mt, ok := op.RequestBody.Content.values["application/json"]
		if !ok || len(op.RequestBody.Content.keys) != 1 || mt.Schema == nil {
			return "", false, errors.New("only a request body of application/json is supported")
		}
		t, err := tsType(mt.Schema, 2)
		if err != nil {
			return "", false, fmt.Errorf("request body: %w", err)
		}
		body = t
	}

	var responses []string
	redirect := false
	for _, code := range op.Responses.keys {
		if code != "default" && !isStatus(code) {
			return "", false, fmt.Errorf("response %q is no status code; ranges such as 2XX are not supported", code)
		}
		if strings.HasPrefix(code, "3") {
			redirect = true
		}
		if !strings.HasPrefix(code, "2") {
			continue
		}
		r := op.Responses.values[code]
		t := "undefined"
		switch {
		case len(r.Content.keys) == 0:
		case len(r.Content.keys) == 1 && r.Content.keys[0] == "application/json" && r.Content.values["application/json"].Schema != nil:
			var err error
			if t, err = tsType(r.Content.values["application/json"].Schema, 2); err != nil {
				return "", false, fmt.Errorf("response %s: %w", code, err)
			}
		default:
			t = "Blob"
		}
		responses = append(responses, code+": "+t)
	}
	if len(responses) == 0 && !redirect {
		return "", false, errors.New("no successful response")
	}

	var b strings.Builder
	b.WriteString("{\n")
	b.WriteString("    path: " + object(path) + ";\n")
	b.WriteString("    query: " + object(query) + ";\n")
	b.WriteString("    body: " + body + ";\n")
	b.WriteString("    responses: " + object(responses) + ";\n")
	b.WriteString("  }")
	return b.String(), redirect, nil
}

// isStatus reports whether code is a status of three digits, as the types write
// it as a key.
func isStatus(code string) bool {
	if len(code) != 3 || code[0] < '1' || code[0] > '5' {
		return false
	}
	return code[1] >= '0' && code[1] <= '9' && code[2] >= '0' && code[2] <= '9'
}

func object(members []string) string {
	if len(members) == 0 {
		return "Record<string, never>"
	}
	return "{ " + strings.Join(members, "; ") + " }"
}

// checkPathParameters requires a parameter for every wildcard of the path and
// the other way round, so that a path and its types cannot disagree.
func checkPathParameters(route string, params []parameter) error {
	var want, got []string
	for _, segment := range strings.Split(route, "/") {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			want = append(want, segment[1:len(segment)-1])
		}
	}
	for _, p := range params {
		if p.In == "path" {
			got = append(got, p.Name)
		}
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		return fmt.Errorf("the path names %v, the path parameters are %v", want, got)
	}
	return nil
}
