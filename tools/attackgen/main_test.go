// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden file")

// A small bundle covers what the generator keeps, drops and derives: revoked
// and deprecated techniques are dropped, a sub-technique is named after its
// parent, tactics of other matrices are ignored, and tactics are named and
// ordered as in the matrix. Regenerate the golden file with
// go test ./tools/attackgen -update.
func TestGenerate_MatchesGoldenFile(t *testing.T) {
	t.Parallel()

	bundle, err := os.ReadFile(filepath.Join("testdata", "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := generate(bundle, "1.0")
	if err != nil {
		t.Fatalf("generate() error = %v", err)
	}
	golden := filepath.Join("testdata", "techniques.golden.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(filepath.Join("testdata", "techniques.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("generate() =\n%s\nwant\n%s", got, want)
	}
}

func TestGenerate_RejectsInconsistentBundles(t *testing.T) {
	t.Parallel()

	bundle, err := os.ReadFile(filepath.Join("testdata", "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(string) string{
		"other version": func(s string) string {
			return strings.Replace(s, `"x_mitre_version": "1.0"`, `"x_mitre_version": "1.1"`, 1)
		},
		"no parent": func(s string) string { return strings.Replace(s, `"T0001"}]`, `"T0004"}]`, 1) },
		"unknown tactic": func(s string) string {
			return strings.Replace(s, `"phase_name": "credential-access"}]`, `"phase_name": "impact"}]`, 1)
		},
		"sub-technique flag": func(s string) string {
			return strings.Replace(s, `"x_mitre_is_subtechnique": true`, `"x_mitre_is_subtechnique": false`, 1)
		},
		"duplicate identifier": func(s string) string {
			return strings.Replace(strings.Replace(s, `"T0002"`, `"T0001"`, 1), `"revoked": true`, `"revoked": false`, 1)
		},
		"malformed identifier": func(s string) string { return strings.Replace(s, `"T0001.001"`, `"T1.1"`, 1) },
		"unknown matrix tactic": func(s string) string {
			return strings.Replace(s, `"x-mitre-tactic--initial", `, `"x-mitre-tactic--other", `, 1)
		},
	} {
		changed := change(string(bundle))
		if changed == string(bundle) {
			t.Fatalf("%s: the change does not apply to the fixture", name)
		}
		if _, err := generate([]byte(changed), "1.0"); err == nil {
			t.Errorf("%s: generate() error = nil, want an error", name)
		}
	}
}

func TestRun_RejectsABundleWithAnotherDigest(t *testing.T) {
	t.Parallel()

	out := filepath.Join(t.TempDir(), "techniques.json")
	if err := run(t.Context(), filepath.Join("testdata", "bundle.json"), out); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Errorf("run() error = %v, want a digest mismatch", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("run() wrote %s despite the mismatch", out)
	}
}

// The embedded list must come from the pinned version, so that a change of the
// pin without a new list, or the reverse, fails.
func TestEmbeddedList_HasThePinnedVersion(t *testing.T) {
	t.Parallel()

	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "attack", "techniques.json"))
	if err != nil {
		t.Fatal(err)
	}
	var l struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatal(err)
	}
	if l.Version != version {
		t.Errorf("embedded list has version %q, generator pins %q; run go run ./tools/attackgen", l.Version, version)
	}
	if !strings.Contains(bundleURL, "/v"+version+"/") {
		t.Errorf("bundle URL %s does not name the tag of version %s", bundleURL, version)
	}
}
