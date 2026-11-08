// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command licensegen writes the notices of the third-party software that the
// binaries of Nyktus contain: THIRD-PARTY-NOTICES.md for the server, with the
// web console embedded in it, and sensor/THIRD-PARTY-NOTICES.md for the sensor.
// The licenses of these packages require that their text accompany a copy of the
// binary, so the release archives and images carry the files.
//
// The Go modules are the ones that "go list -deps" finds for the binary, with the
// license files of the module cache, and the standard library comes with the
// license of the toolchain. The packages of the web console are the ones that the
// build puts into the bundle, with the license files of web/node_modules and the
// versions of web/package-lock.json. A test compares the files with the output of
// this tool, so a new version of a dependency fails until the files are written
// again:
//
//	go run ./tools/licensegen
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// bundled lists the packages of the web console that its build puts into the
// bundle. The list comes from the source map of a build ("vite build
// --sourcemap" names every file that went into the bundle): the entry point
// "vue" only re-exports. A package that the build starts to bundle has to be added
// here; checkDependencies fails when one of them gains a dependency that neither
// list knows.
var bundled = []string{
	"@paulmillr/qr",
	"@vue/reactivity",
	"@vue/runtime-core",
	"@vue/runtime-dom",
	"@vue/shared",
	"vue",
	"vue-router",
}

// notShipped lists the dependencies of the packages above that the bundle leaves
// out: the compiler and the renderer for the server of Vue, which the console does
// not use, the interface to the developer tools of the browser, which the
// production build removes, and the types of the style properties, which hold no
// code.
var notShipped = []string{
	"@vue/compiler-dom",
	"@vue/compiler-sfc",
	"@vue/devtools-api",
	"@vue/server-renderer",
	"csstype",
}

// fonts are the license texts of the fonts that the console serves itself.
var fonts = []string{
	"web/src/assets/fonts/OFL-JetBrainsMono.txt",
	"web/src/assets/fonts/OFL-SchibstedGrotesk.txt",
}

// Files that a package keeps its license in, compared in lower case.
var licenseNames = []string{"license", "licence", "copying", "notice"} //nolint:misspell // Some packages spell the name of the file LICENCE.

func main() {
	root := flag.String("root", ".", "the root of the repository")
	flag.Parse()

	if err := run(*root); err != nil {
		fmt.Fprintln(os.Stderr, "licensegen:", err)
		os.Exit(1)
	}
}

func run(root string) error {
	files, err := generate(root)
	if err != nil {
		return err
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), content, 0o644); err != nil { //nolint:gosec // A file of the repository, readable by everyone.
			return err
		}
	}
	return nil
}

// generate returns the content of the files by their path below root.
func generate(root string) (map[string][]byte, error) {
	goroot, err := goEnv(root, "GOROOT")
	if err != nil {
		return nil, err
	}
	std, err := readLicenses(goroot, []string{"LICENSE"})
	if err != nil {
		return nil, fmt.Errorf("standard library: %w", err)
	}
	stdlib := component{name: "Go standard library", texts: std}

	server, err := goComponents(root, "./cmd/nyktus")
	if err != nil {
		return nil, err
	}
	web, err := webComponents(root)
	if err != nil {
		return nil, err
	}
	sensor, err := goComponents(filepath.Join(root, "sensor"), "./cmd/nyktus-sensor")
	if err != nil {
		return nil, err
	}

	return map[string][]byte{
		"THIRD-PARTY-NOTICES.md":                          render("Nyktus server", append(append([]component{stdlib}, server...), web...)),
		filepath.Join("sensor", "THIRD-PARTY-NOTICES.md"): render("Nyktus sensor", append([]component{stdlib}, sensor...)),
	}, nil
}

// A component is a piece of third-party software with the texts of its license.
type component struct {
	name  string
	texts []string
}

func goEnv(dir, name string) (string, error) {
	out, err := goCommand(dir, nil, "env", name)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func goCommand(dir string, env []string, args ...string) (string, error) {
	cmd := exec.CommandContext(context.Background(), "go", args...) //nolint:gosec // The arguments are constants of this tool.
	cmd.Dir = dir
	cmd.Env = append(cmd.Environ(), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// targets are the platforms that the releases are built for. The packages of a
// build differ by platform, so the notices cover the union.
var targets = [][]string{
	{"GOOS=linux", "GOARCH=amd64"},
	{"GOOS=linux", "GOARCH=arm64"},
	{"GOOS=darwin", "GOARCH=arm64"},
}

// goComponents returns the modules that the binary of pkg is built from on any
// of the targets, except the module itself.
func goComponents(dir, pkg string) ([]component, error) {
	seen := map[string]bool{}
	var components []component
	for _, env := range targets {
		out, err := goCommand(dir, append([]string{"CGO_ENABLED=0"}, env...), "list", "-deps", "-f",
			"{{if .Module}}{{if not .Module.Main}}{{.Module.Path}}\t{{.Module.Version}}\t{{.Module.Dir}}{{end}}{{end}}", pkg)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if line == "" {
				continue
			}
			fields := strings.Split(line, "\t")
			if len(fields) != 3 {
				return nil, fmt.Errorf("unexpected line of go list: %q", line)
			}
			if seen[fields[0]] {
				continue
			}
			seen[fields[0]] = true
			texts, err := readLicenses(fields[2], licenseNames)
			if err != nil {
				return nil, fmt.Errorf("module %s: %w", fields[0], err)
			}
			components = append(components, component{name: fields[0] + " " + fields[1], texts: texts})
		}
	}
	slices.SortFunc(components, func(a, b component) int { return strings.Compare(a.name, b.name) })
	return components, nil
}

// lockfile is the part of package-lock.json that the tool reads.
type lockfile struct {
	Packages map[string]struct {
		Version      string            `json:"version"`
		Dependencies map[string]string `json:"dependencies"`
	} `json:"packages"`
}

// webComponents returns the packages in the bundle of the console, and its fonts.
func webComponents(root string) ([]component, error) {
	data, err := os.ReadFile(filepath.Join(root, "web", "package-lock.json")) //nolint:gosec // The developer who runs the tool names the root.
	if err != nil {
		return nil, err
	}
	var lock lockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("package-lock.json: %w", err)
	}
	if err := checkDependencies(lock); err != nil {
		return nil, err
	}

	var components []component
	for _, name := range bundled {
		pkg := lock.Packages["node_modules/"+name]
		texts, err := readLicenses(filepath.Join(root, "web", "node_modules", filepath.FromSlash(name)), licenseNames)
		if err != nil {
			return nil, fmt.Errorf("package %s: %w", name, err)
		}
		components = append(components, component{name: name + " " + pkg.Version, texts: texts})
	}
	for _, path := range fonts {
		text, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path))) //nolint:gosec // The paths are constants of this tool.
		if err != nil {
			return nil, err
		}
		components = append(components, component{name: "font " + strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "OFL-"), ".txt"), texts: []string{string(text)}})
	}
	return components, nil
}

// checkDependencies fails when a bundled package depends on one that neither
// list names, because the bundle may then hold code without a notice.
func checkDependencies(lock lockfile) error {
	var problems []string
	for _, name := range bundled {
		pkg, ok := lock.Packages["node_modules/"+name]
		if !ok {
			problems = append(problems, name+" is not in package-lock.json")
			continue
		}
		for dep := range pkg.Dependencies {
			if !slices.Contains(bundled, dep) && !slices.Contains(notShipped, dep) {
				problems = append(problems, fmt.Sprintf("%s depends on %s, which is neither bundled nor known to be left out", name, dep))
			}
		}
	}
	slices.Sort(problems)
	if len(problems) > 0 {
		return errors.New("bundled packages in tools/licensegen: " + strings.Join(problems, "; "))
	}
	return nil
}

// readLicenses returns the text of every license file in dir whose name starts
// with one of names, in the order of the names of the files. It fails when there
// is none: a package without a license text must not ship unnoticed.
func readLicenses(dir string, names []string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var texts []string
	for _, entry := range entries {
		if !entry.Type().IsRegular() && entry.Type()&fs.ModeSymlink == 0 {
			continue
		}
		lower := strings.ToLower(entry.Name())
		if !slices.ContainsFunc(names, func(n string) bool { return strings.HasPrefix(lower, strings.ToLower(n)) }) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name())) //nolint:gosec // A file of a dependency that the build uses.
		if err != nil {
			return nil, err
		}
		texts = append(texts, strings.TrimSpace(string(data)))
	}
	if len(texts) == 0 {
		return nil, fmt.Errorf("no license file in %s", dir)
	}
	return texts, nil
}

// render writes the notices. Components whose license texts are identical share
// one copy of the text.
func render(product string, components []component) []byte {
	type group struct {
		text  string
		names []string
	}
	var groups []*group
	index := map[string]*group{}
	for _, c := range components {
		key := strings.Join(c.texts, "\n\n---\n\n")
		g, ok := index[key]
		if !ok {
			g = &group{text: key}
			index[key] = g
			groups = append(groups, g)
		}
		g.names = append(g.names, c.name)
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "# Third-party notices of the %s\n\n", product)
	b.WriteString("The binaries of Nyktus contain the software below. Each license applies to the software named above its text. The licenses of Nyktus itself and of the data it embeds are in `LICENSE` and `NOTICE`. This file is generated by `go run ./tools/licensegen`; do not edit it.\n")
	for _, g := range groups {
		b.WriteString("\n---\n\n")
		for _, name := range g.names {
			fmt.Fprintf(&b, "- %s\n", name)
		}
		b.WriteString("\n```text\n")
		b.WriteString(g.text)
		b.WriteString("\n```\n")
	}
	return b.Bytes()
}
