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
// dependencies are the standard library, one YAML parser and the SSH library of
// the Go project, so that a customer can read its go.mod in a minute and a flaw
// in the server cannot reach it. The libraries of the project that the SSH
// library needs only on some platforms follow it as indirect requirements.
func TestGoMod_RequiresOnlyTheYAMLParserAndTheSSHLibrary(t *testing.T) {
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
	// golang.org/x/sys is a requirement of x/crypto for platforms such as s390x
	// and appears in go.mod only as an indirect one.
	allowed := []string{"go.yaml.in/yaml/v3", "golang.org/x/crypto", "golang.org/x/sys"}
	for _, m := range []string{"go.yaml.in/yaml/v3", "golang.org/x/crypto"} {
		if !slices.Contains(required, m) {
			t.Errorf("go.mod requires %v, lacks %s", required, m)
		}
	}
	for _, m := range required {
		if !slices.Contains(allowed, m) {
			t.Errorf("go.mod requires %s, want only %v: a new dependency needs a decision", m, allowed)
		}
	}
}

// No file of the sensor imports a package of the server or anything beyond
// the standard library, the YAML parser, the SSH library and the sensor itself.
func TestImports_AreTheStandardLibraryTheYAMLParserTheSSHLibraryAndTheSensor(t *testing.T) {
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
			case p == "go.yaml.in/yaml/v3", p == "golang.org/x/crypto/ssh", p == modulePath, strings.HasPrefix(p, modulePath+"/"):
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
