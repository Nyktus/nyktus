// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden file")

func readFixtures(t *testing.T) (activities, approaches, mappings string) {
	t.Helper()
	read := func(name string) string {
		b, err := fs.ReadFile(os.DirFS(filepath.Join("testdata", "data")), name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	return read(activitiesFile), read(approachesFile), read(mappingsFile)
}

// Small data files cover what the generator keeps, drops and derives:
// strategic activities and approaches are dropped, activities are ordered by
// identifier, and approaches are named and ordered by their identifiers.
// Regenerate the golden file with go test ./tools/engagegen -update.
func TestGenerate_MatchesGoldenFile(t *testing.T) {
	t.Parallel()

	activities, approaches, mappings := readFixtures(t)
	got, err := generate([]byte(activities), []byte(approaches), []byte(mappings), "0.9")
	if err != nil {
		t.Fatalf("generate() error = %v", err)
	}
	golden := filepath.Join("testdata", "activities.golden.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(filepath.Join("testdata", "activities.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("generate() =\n%s\nwant\n%s", got, want)
	}
}

func TestGenerate_RejectsInconsistentData(t *testing.T) {
	t.Parallel()

	activities, approaches, mappings := readFixtures(t)
	// before inserts an entry in front of the strategic entry of a file.
	before := func(file, strategicEntry, entry string) string {
		return strings.Replace(file, strategicEntry, entry+",\n"+strategicEntry, 1)
	}
	const (
		sac = `{"id": "SAC0001"`
		sap = `{"id": "SAP0001"`
		sam = `{"approach_id": "SAP0001"`
	)
	// Each case breaks one rule and leaves the data otherwise consistent, so
	// that no other check rejects it.
	for name, change := range map[string]func(a, p, m string) (string, string, string){
		"duplicate activity": func(a, p, m string) (string, string, string) {
			return before(a, sac, `{"id": "EAC0001", "name": "Again"}`), p, m
		},
		"malformed activity": func(a, p, m string) (string, string, string) {
			return before(a, sac, `{"id": "EAC01", "name": "Malformed"}`), p,
				before(m, sam, `{"approach_id": "EAP0001", "activity_id": "EAC01"}`)
		},
		"unnamed activity": func(a, p, m string) (string, string, string) {
			return strings.Replace(a, `"Second Activity"`, `" "`, 1), p, m
		},
		"activity without approach": func(a, p, m string) (string, string, string) {
			return a, p, strings.Replace(m, `{"approach_id": "EAP0002", "activity_id": "EAC0002"},`, ``, 1)
		},
		"unknown approach": func(a, p, m string) (string, string, string) {
			return a, p, before(m, sam, `{"approach_id": "EAP0009", "activity_id": "EAC0002"}`)
		},
		"unknown activity": func(a, p, m string) (string, string, string) {
			return a, p, before(m, sam, `{"approach_id": "EAP0001", "activity_id": "EAC0009"}`)
		},
		"duplicate mapping": func(a, p, m string) (string, string, string) {
			return a, p, before(m, sam, `{"approach_id": "EAP0001", "activity_id": "EAC0001"}`)
		},
		"duplicate approach": func(a, p, m string) (string, string, string) {
			return a, before(p, sap, `{"id": "EAP0001", "name": "Again"}`), m
		},
		"malformed approach": func(a, p, m string) (string, string, string) {
			return a, before(p, sap, `{"id": "EAP01", "name": "Malformed"}`), m
		},
		"unnamed approach": func(a, p, m string) (string, string, string) {
			return a, strings.Replace(p, `"Detect"`, `"Detect "`, 1), m
		},
	} {
		a, p, m := change(activities, approaches, mappings)
		if a == activities && p == approaches && m == mappings {
			t.Fatalf("%s: the change does not apply to the fixture", name)
		}
		if _, err := generate([]byte(a), []byte(p), []byte(m), "0.9"); err == nil {
			t.Errorf("%s: generate() error = nil, want an error", name)
		}
	}
}

func TestGenerate_RejectsDataWithoutEngagementActivities(t *testing.T) {
	t.Parallel()

	_, approaches, _ := readFixtures(t)
	activities := `[{"id": "SAC0001", "name": "Strategic Activity"}]`
	mappings := `[{"approach_id": "SAP0001", "activity_id": "SAC0001"}]`
	if _, err := generate([]byte(activities), []byte(approaches), []byte(mappings), "0.9"); err == nil {
		t.Error("generate() error = nil, want an error for a list without engagement activities")
	}
}

func TestRun_RejectsDataWithAnotherDigest(t *testing.T) {
	t.Parallel()

	out := filepath.Join(t.TempDir(), "activities.json")
	if err := run(t.Context(), filepath.Join("testdata", "data"), out); err == nil || !strings.Contains(err.Error(), "SHA-256") {
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

	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "engage", "activities.json"))
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
		t.Errorf("embedded list has version %q, generator pins %q; run go run ./tools/engagegen", l.Version, version)
	}
	if !strings.Contains(dataURL, "/v"+version+"/") {
		t.Errorf("data URL %s does not name the tag of version %s", dataURL, version)
	}
}
