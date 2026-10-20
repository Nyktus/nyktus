// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "nyktus.org/nyktus/sensor"

// The sensor runs in the monitored network and talks to attackers. Its
// dependencies are the standard library and one YAML parser, so that a customer
// can read its go.mod in a minute and a flaw in the server cannot reach it.
func TestGoMod_RequiresOnlyTheYAMLParser(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	var required []string
	inBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "replace"), strings.HasPrefix(line, "exclude"), strings.HasPrefix(line, "retract"):
			t.Errorf("go.mod holds %q, want no directive that changes where code comes from", line)
		case line == "require (":
			inBlock = true
		case line == ")":
			inBlock = false
		case strings.HasPrefix(line, "require "):
			required = append(required, strings.Fields(line)[1])
		case inBlock && line != "" && !strings.HasPrefix(line, "//"):
			required = append(required, strings.Fields(line)[0])
		}
	}
	if want := []string{"go.yaml.in/yaml/v3"}; !slices.Equal(required, want) {
		t.Errorf("go.mod requires %v, want %v: a new dependency needs a decision", required, want)
	}
}

// No file of the sensor imports a package of the server or anything beyond
// the standard library, the YAML parser and the sensor itself.
func TestImports_AreTheStandardLibraryTheYAMLParserAndTheSensor(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			first, _, _ := strings.Cut(p, "/")
			switch {
			case !strings.Contains(first, "."):
				// The standard library.
			case p == "go.yaml.in/yaml/v3", p == modulePath, strings.HasPrefix(p, modulePath+"/"):
			default:
				t.Errorf("%s imports %s", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
