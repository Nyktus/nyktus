// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadLicenses_TakesTheLicenseFilesOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "LICENSE"), "MIT text\n")
	writeFile(t, filepath.Join(dir, "NOTICE.txt"), "Apache notice\n")
	writeFile(t, filepath.Join(dir, "README.md"), "not a license")
	writeFile(t, filepath.Join(dir, "main.go"), "package x")

	got, err := readLicenses(dir, licenseNames)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"MIT text", "Apache notice"}; len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("readLicenses() = %q, want %q", got, want)
	}
}

// A package without a license text must not ship unnoticed.
func TestReadLicenses_FailsWithoutALicenseFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "README.md"), "no license here")

	if _, err := readLicenses(dir, licenseNames); err == nil || !strings.Contains(err.Error(), "no license file") {
		t.Errorf("readLicenses() error = %v, want that there is no license file", err)
	}
}

func TestRender_SharesTheCopyOfAnIdenticalText(t *testing.T) {
	t.Parallel()
	out := string(render("Nyktus test", []component{
		{name: "a 1.0.0", texts: []string{"same text"}},
		{name: "b 2.0.0", texts: []string{"same text"}},
		{name: "c 3.0.0", texts: []string{"other text"}},
	}))

	if n := strings.Count(out, "same text"); n != 1 {
		t.Errorf("the shared text stands %d times, want once", n)
	}
	for _, want := range []string{"- a 1.0.0\n- b 2.0.0\n", "- c 3.0.0\n", "other text"} {
		if !strings.Contains(out, want) {
			t.Errorf("render() lacks %q:\n%s", want, out)
		}
	}
}

func TestCheckDependencies(t *testing.T) {
	t.Parallel()

	lock := func(extra map[string]string) lockfile {
		var l lockfile
		l.Packages = map[string]struct {
			Version      string            `json:"version"`
			Dependencies map[string]string `json:"dependencies"`
		}{}
		for _, name := range bundled {
			pkg := l.Packages["node_modules/"+name]
			pkg.Version = "1.0.0"
			l.Packages["node_modules/"+name] = pkg
		}
		pkg := l.Packages["node_modules/vue"]
		pkg.Dependencies = extra
		l.Packages["node_modules/vue"] = pkg
		return l
	}

	tests := []struct {
		name    string
		extra   map[string]string
		wantErr string
	}{
		{name: "known dependencies", extra: map[string]string{"@vue/shared": "1", "@vue/compiler-dom": "1"}},
		{name: "a new dependency", extra: map[string]string{"left-pad": "1"}, wantErr: "vue depends on left-pad"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := checkDependencies(lock(tt.extra))
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("checkDependencies() error = %v, want none", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("checkDependencies() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}

	if err := checkDependencies(lockfile{}); err == nil {
		t.Error("checkDependencies() accepts a lockfile without the bundled packages")
	}
}

// The files in the repository are what the tool writes. A new version of a
// dependency fails this test until "go run ./tools/licensegen" has written the
// files again. It needs the packages of the console and the Go modules, so it
// runs in the job of the web console, which sets NYKTUS_REQUIRE_WEB_BUILD, and
// is skipped where web/node_modules does not exist.
func TestGenerate_MatchesTheFilesInTheRepository(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "web", "node_modules")); err != nil {
		if os.Getenv("NYKTUS_REQUIRE_WEB_BUILD") != "" {
			t.Fatalf("web/node_modules is missing: %v", err)
		}
		t.Skip("web/node_modules is missing")
	}

	files, err := generate(root)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(root, name)) //nolint:gosec // A file of the repository.
		if err != nil {
			t.Fatalf("%s: %v (run go run ./tools/licensegen)", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is out of date; run go run ./tools/licensegen", name)
		}
	}
}
