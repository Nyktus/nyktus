// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The store test writes every action in Actions to the database, which checks
// the format. This test ensures that Actions misses no declared constant.
func TestActions_ListsEveryDeclaredAction(t *testing.T) {
	t.Parallel()

	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list package files: %v", err)
	}
	declared := map[string]bool{}
	fset := token.NewFileSet()
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			if ident, ok := spec.Type.(*ast.Ident); !ok || ident.Name != "Action" {
				return true
			}
			for _, value := range spec.Values {
				lit, ok := value.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Errorf("action at %s is not a string literal", fset.Position(value.Pos()))
					continue
				}
				name, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("unquote %s: %v", lit.Value, err)
				}
				declared[name] = true
			}
			return true
		})
	}

	listed := map[string]bool{}
	for _, a := range Actions {
		listed[string(a)] = true
	}
	if len(declared) == 0 || !maps.Equal(declared, listed) {
		t.Errorf("declared actions %v, listed in Actions %v; want the same", slices.Sorted(maps.Keys(declared)), slices.Sorted(maps.Keys(listed)))
	}
}
