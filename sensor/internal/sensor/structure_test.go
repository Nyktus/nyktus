// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sensor

import (
	"go/ast"
	goparser "go/parser"
	"go/token"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The honeypots answer the client with the protocol and nothing else: they
// start no process, open no connection of their own, read no file, and the SSH
// honeypot offers neither an agent nor a terminal. The check is structural, so
// that no change can add one without failing here. A package of a service is
// listed here when it is written; the library of the Go project is the one
// import that speaks the SSH protocol.
func TestServices_ImportNothingThatRunsOrForwards(t *testing.T) {
	t.Parallel()

	forbidden := map[string]string{
		"os":            "reads files and starts processes",
		"os/exec":       "starts processes",
		"syscall":       "reaches the system directly",
		"unsafe":        "bypasses the checks of Go",
		"plugin":        "loads code",
		"net/http":      "opens connections of its own",
		"net/rpc":       "opens connections of its own",
		"net/smtp":      "opens connections of its own",
		"net/url":       "a client must not name a target",
		"database/sql":  "opens connections of its own",
		"path/filepath": "reads files",

		"golang.org/x/crypto/ssh/agent":      "talks to an agent",
		"golang.org/x/crypto/ssh/knownhosts": "reads files",
		"golang.org/x/crypto/ssh/terminal":   "opens a terminal",
	}
	for _, service := range []string{"ssh", "telnet", "postgres", "ldap"} {
		t.Run(service, func(t *testing.T) {
			t.Parallel()
			dir := os.DirFS("../" + service)
			files, err := fs.Glob(dir, "*.go")
			if err != nil || len(files) == 0 {
				t.Fatalf("glob = %v, %v", files, err)
			}
			fset := token.NewFileSet()
			for _, file := range files {
				if strings.HasSuffix(file, "_test.go") {
					continue
				}
				src, err := fs.ReadFile(dir, file)
				if err != nil {
					t.Fatal(err)
				}
				f, err := goparser.ParseFile(fset, file, src, 0)
				if err != nil {
					t.Fatal(err)
				}
				// The package needs net for the connection it is given, but
				// never for a connection of its own.
				ast.Inspect(f, func(n ast.Node) bool {
					sel, ok := n.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "net" {
						for _, prefix := range []string{"Dial", "Listen", "Lookup", "Resolve"} {
							if strings.HasPrefix(sel.Sel.Name, prefix) {
								t.Errorf("%s/%s calls net.%s: the honeypot opens no connection of its own", service, file, sel.Sel.Name)
							}
						}
					}
					return true
				})
				for _, imp := range f.Imports {
					path, err := strconv.Unquote(imp.Path.Value)
					if err != nil {
						t.Fatal(err)
					}
					if why, bad := forbidden[path]; bad {
						t.Errorf("%s/%s imports %s, which %s", service, file, path, why)
					}
				}
			}
		})
	}
}
