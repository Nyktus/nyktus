// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package deploy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The files that name the release to install. The release pull request raises
// the version in them, between the markers of release-please, together with the
// manifest.
var filesWithTheRelease = []string{"compose/.env.example", "compose/README.md"}

var imageVersion = regexp.MustCompile(`(?:NYKTUS_VERSION=|ghcr\.io/nyktus/nyktus:)(\d+\.\d+\.\d+[^\s@` + "`" + `]*)`)

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decode(t *testing.T, path string, into any) {
	t.Helper()
	if err := json.Unmarshal(readFile(t, path), into); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// An operator who follows the reference installation gets the version it names,
// so a name that stays behind the manifest installs an outdated release.
func TestReferenceInstallation_NamesTheReleaseOfTheManifest(t *testing.T) {
	t.Parallel()

	var manifest map[string]string
	decode(t, "../.release-please-manifest.json", &manifest)
	want := manifest["."]
	if want == "" {
		t.Fatal("the manifest names no version of the server")
	}

	for _, file := range filesWithTheRelease {
		matches := imageVersion.FindAllSubmatch(readFile(t, file), -1)
		if len(matches) == 0 {
			t.Errorf("%s names no version of the server", file)
		}
		for _, match := range matches {
			if got := string(match[1]); got != want {
				t.Errorf("%s names version %s, want %s", file, got, want)
			}
		}
	}
}

// A release raises only a file that the configuration lists and that carries the
// markers. Without either, the version would stay behind unnoticed until the
// release pull request fails.
func TestReleasePleaseConfig_RaisesEveryFileWithTheRelease(t *testing.T) {
	t.Parallel()

	var config struct {
		Packages map[string]struct {
			ExtraFiles []string `json:"extra-files"`
		} `json:"packages"`
	}
	decode(t, "../release-please-config.json", &config)

	listed := config.Packages["."].ExtraFiles
	for _, file := range filesWithTheRelease {
		path := "deploy/" + file
		if !slices.Contains(listed, path) {
			t.Errorf("release-please-config.json does not list %s in extra-files, got %v", path, listed)
		}
		text := string(readFile(t, file))
		for _, marker := range []string{"x-release-please-start-version", "x-release-please-end"} {
			if strings.Count(text, marker) != 1 {
				t.Errorf("%s holds the marker %s %d times, want once", file, marker, strings.Count(text, marker))
			}
		}
	}
}
