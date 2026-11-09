// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits of the configuration. They bound what one listing of the tools sends.
const (
	maxPath          = 128
	maxServerName    = 128
	maxServerVersion = 64
	maxInstructions  = 4 << 10
	maxTools         = 16
	maxDescription   = 2 << 10
	maxArguments     = 8
	maxArgumentText  = 512
	maxResponse      = 16 << 10
	maxPages         = 32
	maxPageKey       = 128
)

// Config is what an MCP honeypot presents. There are no defaults: what every
// installation shared would identify the honeypot.
type Config struct {
	Path          string `yaml:"path"`
	ServerName    string `yaml:"server_name"`
	ServerVersion string `yaml:"server_version"`
	Instructions  string `yaml:"instructions"`
	Tools         []Tool `yaml:"tools"`
	// Certificate, if set, makes the port speak TLS. It comes from the operator:
	// a certificate that the sensor made itself would identify it.
	Certificate *tls.Certificate `yaml:"-"`
}

// Tool is an entry of the list of tools with its fixed answers. Nothing is run:
// a call selects a text of the configuration.
type Tool struct {
	Name string `yaml:"name"`
	// Description is what an AI agent reads to decide whether and how to call
	// the tool, and so the actual bait.
	Description string     `yaml:"description"`
	Arguments   []Argument `yaml:"arguments"`
	// Response is the answer, or with SelectBy the answer when no page matches.
	Response string `yaml:"response"`
	// IsError marks the answer as a failure of the tool, such as a refusal.
	IsError bool `yaml:"is_error"`
	// SelectBy names an argument whose exact value selects one of Responses.
	SelectBy  string            `yaml:"select_by"`
	Responses map[string]string `yaml:"responses"`
}

// Argument is one parameter of a tool.
type Argument struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Description string `yaml:"description"`
	Required    bool   `yaml:"required"`
}

var (
	namePattern   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	argumentTypes = []string{"string", "integer", "boolean"}
	errPrintable  = errors.New("must be printable text")
)

// Validate returns the problems of the configuration, each starting with the
// name of its field.
func (c *Config) Validate() []error {
	var problems []error
	add := func(format string, args ...any) { problems = append(problems, fmt.Errorf(format, args...)) }
	check := func(field, value string, limit int, multiline bool) {
		if err := validateText(value, limit, multiline); err != nil {
			add("%s: %v", field, err)
		}
	}

	if !strings.HasPrefix(c.Path, "/") || len(c.Path) > maxPath || strings.ContainsAny(c.Path, "?#") || !isVisibleASCII(c.Path) {
		add("path: must start with / and be at most %d printable ASCII characters without ? or #", maxPath)
	}
	check("server_name", c.ServerName, maxServerName, false)
	check("server_version", c.ServerVersion, maxServerVersion, false)
	if c.Instructions != "" {
		check("instructions", c.Instructions, maxInstructions, true)
	}
	if n := len(c.Tools); n == 0 || n > maxTools {
		add("tools: from 1 to %d tools", maxTools)
	}
	seen := map[string]bool{}
	for i := range c.Tools {
		t := &c.Tools[i]
		field := fmt.Sprintf("tools[%d]", i)
		if !namePattern.MatchString(t.Name) {
			add("%s.name: required, 1 to 64 letters, digits, _, . or -", field)
		}
		if seen[t.Name] && t.Name != "" {
			add("%s.name: the same name as another tool", field)
		}
		seen[t.Name] = true
		check(field+".description", t.Description, maxDescription, true)
		check(field+".response", t.Response, maxResponse, true)
		problems = append(problems, t.validateArguments(field)...)
		problems = append(problems, t.validatePages(field)...)
	}
	return problems
}

func (t *Tool) validateArguments(field string) []error {
	var problems []error
	add := func(format string, args ...any) { problems = append(problems, fmt.Errorf(format, args...)) }
	if len(t.Arguments) > maxArguments {
		add("%s.arguments: at most %d", field, maxArguments)
	}
	seen := map[string]bool{}
	for i, a := range t.Arguments {
		if !namePattern.MatchString(a.Name) {
			add("%s.arguments[%d].name: required, 1 to 64 letters, digits, _, . or -", field, i)
		}
		if seen[a.Name] && a.Name != "" {
			add("%s.arguments[%d].name: the same name as another argument", field, i)
		}
		seen[a.Name] = true
		if !slices.Contains(argumentTypes, a.Type) {
			add("%s.arguments[%d].type: must be string, integer or boolean", field, i)
		}
		if a.Description != "" {
			if err := validateText(a.Description, maxArgumentText, false); err != nil {
				add("%s.arguments[%d].description: %v", field, i, err)
			}
		}
	}
	return problems
}

func (t *Tool) validatePages(field string) []error {
	if t.SelectBy == "" {
		if len(t.Responses) > 0 {
			return []error{fmt.Errorf("%s.responses: only with select_by", field)}
		}
		return nil
	}
	var problems []error
	add := func(format string, args ...any) { problems = append(problems, fmt.Errorf(format, args...)) }
	selectable := slices.ContainsFunc(t.Arguments, func(a Argument) bool {
		return a.Name == t.SelectBy && (a.Type == "string" || a.Type == "integer")
	})
	if !selectable {
		add("%s.select_by: must name an argument of the type string or integer", field)
	}
	if n := len(t.Responses); n == 0 || n > maxPages {
		add("%s.responses: from 1 to %d with select_by", field, maxPages)
	}
	for key, page := range t.Responses {
		// The key is what a client must send, so that it is not repeated here.
		if validateText(key, maxPageKey, false) != nil {
			add("%s.responses: every key is printable text of at most %d bytes", field, maxPageKey)
		}
		if err := validateText(page, maxResponse, true); err != nil {
			add("%s.responses: %v", field, err)
		}
	}
	return problems
}

// validateText accepts a required text of printable characters, and line breaks
// and tabs where it may have them. Unlike a banner it may be any language: it
// travels inside JSON.
func validateText(s string, limit int, multiline bool) error {
	if s == "" || len(s) > limit {
		return fmt.Errorf("required, at most %d bytes", limit)
	}
	if !utf8.ValidString(s) {
		return errPrintable
	}
	for _, r := range s {
		if !unicode.IsPrint(r) && (!multiline || (r != '\n' && r != '\r' && r != '\t')) {
			return errPrintable
		}
	}
	return nil
}

func isVisibleASCII(s string) bool {
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
