// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sensor

import (
	"go/ast"
	goparser "go/parser"
	"go/token"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The honeypots answer the client with the protocol and nothing else: they
// start no process, open no connection of their own, read no file, and the SSH
// honeypot offers neither an agent nor a terminal. The check is structural, so
// that no change can add one without failing here. Every package of the sensor
// is either one of the services or one of the helpers, so that a new package is
// checked or named as not needing it; the library of the Go project is the one
// import that speaks the SSH protocol. A service also reads and writes through
// the limits of the guard, so that no protocol can leave one out.
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
	services := []string{"ssh", "telnet", "postgres", "ldap", "mcp"}
	helpers := []string{"clock", "config", "conntest", "guard", "listener", "report", "reporter", "secret", "sensor", "session", "version"}
	packages, err := fs.ReadDir(os.DirFS(".."), ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range packages {
		if p.IsDir() && !slices.Contains(services, p.Name()) && !slices.Contains(helpers, p.Name()) {
			t.Errorf("internal/%s is neither a service nor a helper: add it to the list of this test, and to the services if it speaks a protocol", p.Name())
		}
	}
	for _, service := range services {
		t.Run(service, func(t *testing.T) {
			t.Parallel()
			dir := os.DirFS("../" + service)
			files, err := fs.Glob(dir, "*.go")
			if err != nil || len(files) == 0 {
				t.Fatalf("glob = %v, %v", files, err)
			}
			fset := token.NewFileSet()
			guarded := false
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
					guarded = guarded || path == "nyktus.org/nyktus/sensor/internal/guard"
				}
			}
			if !guarded {
				t.Errorf("%s does not import the guard: it would read and write without the limits of a connection", service)
			}
		})
	}
}
