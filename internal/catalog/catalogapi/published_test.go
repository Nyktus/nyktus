// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalogapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"nyktus.org/nyktus/api"
	embedded "nyktus.org/nyktus/catalog"
	"nyktus.org/nyktus/internal/attack"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/engage"
	"nyktus.org/nyktus/internal/platform/apispec"
)

var update = flag.Bool("update", false, "rewrite the published catalog from the embedded catalog")

// publishedPath is the published catalog. The documentation serves it, and
// readers without access to the API, such as an AI assistant in a chat, read
// it in place of the API.
const publishedPath = "../../../docs/public/deception-catalog.json"

// publishedVersion is the version of the format of the published catalog.
const publishedVersion = 1

// published is the published catalog. Its deceptions are, in every language,
// what GET /api/v1/catalog/deceptions/{id} returns.
type published struct {
	SchemaVersion int      `json:"schema_version"`
	License       string   `json:"license"`
	Notice        []string `json:"notice"`
	AttackVersion string   `json:"attack_version"`
	EngageVersion string   `json:"engage_version"`
	// Techniques and EngageActivities name the identifiers that the
	// deceptions use, and no others.
	Techniques       map[string]reference         `json:"techniques"`
	EngageActivities map[string]reference         `json:"engage_activities"`
	Deceptions       map[string][]json.RawMessage `json:"deceptions"`
}

type reference struct {
	Name string `json:"name"`
}

// notice travels with the file, which is passed on alone, such as into a
// chat. Unlike an artifact, it is not placed as a decoy, so it credits its
// sources.
var notice = []string{
	"The deceptions of the Nyktus catalog. Copyright The Nyktus Authors. Licensed under the Creative Commons Attribution-ShareAlike 4.0 International License; see catalog/LICENSE in the repository of Nyktus.",
	"Names of techniques from MITRE ATT&CK(R) Enterprise: (c) 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. ATT&CK(R) is a registered trademark of The MITRE Corporation.",
	"Names of activities from MITRE Engage(TM): (c) 2021 The MITRE Corporation. Licensed under the Apache License, Version 2.0. MITRE Engage(TM) is a trademark of The MITRE Corporation.",
}

// publish returns the published catalog of c. It asks the handler that
// serves the API for every deception, so that the file holds what the server
// returns. Nothing in it changes between two runs, such as a time, so that
// readers can compare versions of the file.
func publish(t *testing.T, c *catalog.Catalog) []byte {
	t.Helper()
	h := NewHandler(c)
	p := published{
		SchemaVersion: publishedVersion, License: "CC-BY-SA-4.0", Notice: notice,
		AttackVersion: attack.Version(), EngageVersion: engage.Version(),
		Techniques: map[string]reference{}, EngageActivities: map[string]reference{},
		Deceptions: map[string][]json.RawMessage{},
	}
	for _, d := range c.Deceptions() {
		for _, lang := range catalog.Languages {
			rec := serve(t, h.Get, "/api/v1/catalog/deceptions/"+d.ID+"?lang="+lang, d.ID)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s?lang=%s: status %d, body %s", d.ID, lang, rec.Code, rec.Body)
			}
			p.Deceptions[lang] = append(p.Deceptions[lang], rec.Body.Bytes())
		}
		techniques := slices.Clone(d.Techniques)
		for _, ht := range d.Honeytokens {
			techniques = append(techniques, ht.Techniques...)
		}
		for _, id := range techniques {
			tech, ok := attack.Lookup(id)
			if !ok {
				t.Fatalf("%s: technique %s is not in the bundled list", d.ID, id)
			}
			p.Techniques[id] = reference{Name: tech.Name}
		}
		for _, id := range d.EngageActivities {
			activity, ok := engage.Lookup(id)
			if !ok {
				t.Fatalf("%s: activity %s is not in the bundled list", d.ID, id)
			}
			p.EngageActivities[id] = reference{Name: activity.Name}
		}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	// The file is read by people as well; "ATT&CK" stays readable.
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(p); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// The published catalog is what the server returns for every deception of
// the embedded catalog, so that it cannot differ from the API. A changed,
// added or removed deception changes it. Regenerate it with
// go test ./internal/catalog/... -update and review the diff.
func TestPublishedCatalog_MatchesTheEmbeddedCatalog(t *testing.T) {
	t.Parallel()
	c, err := catalog.Load(embedded.Deceptions())
	if err != nil {
		t.Fatal(err)
	}

	got := publish(t, c)
	if again := publish(t, c); !bytes.Equal(got, again) {
		t.Fatal("two runs publish different files")
	}
	if *update {
		if err := os.MkdirAll(filepath.Dir(publishedPath), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(publishedPath, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(publishedPath)
	if err != nil {
		t.Fatalf("%v; run go test ./internal/catalog/... -update", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the embedded catalog; run go test ./internal/catalog/... -update and review the diff", publishedPath)
	}
}

// The file holds the members of its format and nothing else, and every
// deception in it matches the schema of the API.
func TestPublishedCatalog_MatchesTheSpecification(t *testing.T) {
	t.Parallel()
	schemas, err := apispec.ParseSchemas(api.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(publishedPath)
	if err != nil {
		t.Fatalf("%v; run go test ./internal/catalog/... -update", err)
	}

	var p published
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		t.Fatalf("decode %s: %v", publishedPath, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		t.Fatalf("%s: unexpected data after the catalog", publishedPath)
	}
	if p.SchemaVersion != publishedVersion {
		t.Errorf("schema_version = %d, want %d", p.SchemaVersion, publishedVersion)
	}
	if langs := slices.Sorted(maps.Keys(p.Deceptions)); !slices.Equal(langs, slices.Sorted(slices.Values(catalog.Languages))) {
		t.Errorf("languages %v, want %v", langs, catalog.Languages)
	}

	techniques, activities := map[string]bool{}, map[string]bool{}
	for lang, deceptions := range p.Deceptions {
		if len(deceptions) == 0 {
			t.Errorf("%s: no deceptions", lang)
		}
		for i, raw := range deceptions {
			for _, problem := range schemas.Check("CatalogDeception", raw) {
				t.Errorf("%s[%d]: %s", lang, i, problem)
			}
			var d struct {
				Techniques       []string `json:"techniques"`
				EngageActivities []string `json:"engage_activities"`
				Honeytokens      []struct {
					Techniques []string `json:"techniques"`
				} `json:"honeytokens"`
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				t.Fatalf("%s[%d]: %v", lang, i, err)
			}
			for _, id := range d.Techniques {
				techniques[id] = true
			}
			for _, h := range d.Honeytokens {
				for _, id := range h.Techniques {
					techniques[id] = true
				}
			}
			for _, id := range d.EngageActivities {
				activities[id] = true
			}
		}
	}
	for name, tt := range map[string]struct {
		named map[string]reference
		used  map[string]bool
	}{
		"techniques":        {p.Techniques, techniques},
		"engage_activities": {p.EngageActivities, activities},
	} {
		named := slices.Sorted(maps.Keys(tt.named))
		if used := slices.Sorted(maps.Keys(tt.used)); !slices.Equal(named, used) {
			t.Errorf("%s names %v, the deceptions use %v", name, named, used)
		}
		for id, r := range tt.named {
			if r.Name == "" {
				t.Errorf("%s: %s has no name", name, id)
			}
		}
	}
}
