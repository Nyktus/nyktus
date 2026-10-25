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
	"strings"
	"testing"

	"nyktus.org/nyktus/api"
	embedded "nyktus.org/nyktus/catalog"
	"nyktus.org/nyktus/internal/attack"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/engage"
	"nyktus.org/nyktus/internal/platform/apispec"
)

var update = flag.Bool("update", false, "rewrite the published catalog from the embedded catalog")

// publishedPath is the published catalog, for readers without access to the
// API, such as the documentation or an AI assistant in a chat.
const publishedPath = "../../../docs/public/deception-catalog.json"

// publishedVersion is the version of the format of the published catalog.
const publishedVersion = 2

// published is the published catalog. Its deceptions and artifacts are, in
// every language, what GET /api/v1/catalog/deceptions/{id} and
// GET /api/v1/catalog/artifacts/{id} return.
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
	Artifacts        map[string][]json.RawMessage `json:"artifacts"`
}

type reference struct {
	Name string `json:"name"`
}

// The notices of MITRE, as NOTICE states them.
const (
	attackNotice = "(c) 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. ATT&CK(R) is a registered trademark of The MITRE Corporation. Terms of use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/"
	engageNotice = "(c) 2021 The MITRE Corporation. Approved for Public Release; Distribution Unlimited. Public Release Case Number PR_21-01759-28. Licensed under the Apache License, Version 2.0: https://www.apache.org/licenses/LICENSE-2.0 MITRE Engage(TM) is a trademark of The MITRE Corporation."
)

// notice travels with the file, which is passed on alone, such as into a
// chat. Unlike an artifact, it is not placed as a decoy, so it credits its
// sources.
var notice = []string{
	"The deceptions and artifacts of the Nyktus catalog. Copyright The Nyktus Authors. Licensed under the Creative Commons Attribution-ShareAlike 4.0 International License: https://creativecommons.org/licenses/by-sa/4.0/",
	"Identifiers and names of techniques from MITRE ATT&CK(R) Enterprise: " + attackNotice,
	"Identifiers and names of activities from MITRE Engage(TM): " + engageNotice,
}

// publish returns the published catalog of c. It asks the handler that
// serves the API for every deception and artifact, so that the file holds what
// the server returns. Nothing in it changes between two runs, such as a time, so that
// readers can compare versions of the file.
func publish(t *testing.T, c *catalog.Catalog) []byte {
	t.Helper()
	h := NewHandler(c)
	p := published{
		SchemaVersion: publishedVersion, License: "CC-BY-SA-4.0", Notice: notice,
		AttackVersion: attack.Version(), EngageVersion: engage.Version(),
		Techniques: map[string]reference{}, EngageActivities: map[string]reference{},
		Deceptions: map[string][]json.RawMessage{}, Artifacts: map[string][]json.RawMessage{},
	}
	for _, d := range c.Deceptions() {
		for _, lang := range catalog.Languages {
			rec := serve(t, h.Get, "/api/v1/catalog/deceptions/"+d.ID+"?lang="+lang, d.ID)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s?lang=%s: status %d, body %s", d.ID, lang, rec.Code, rec.Body)
			}
			// The API escapes &, < and > as \u0026, \u003c and \u003e;
			// the file holds the same values without the escapes.
			var resp detail
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			p.Deceptions[lang] = append(p.Deceptions[lang], encode(t, resp, ""))
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
	for _, a := range c.Artifacts() {
		for _, lang := range catalog.Languages {
			rec := serve(t, h.GetArtifact, "/api/v1/catalog/artifacts/"+a.ID+"?lang="+lang, a.ID)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s?lang=%s: status %d, body %s", a.ID, lang, rec.Code, rec.Body)
			}
			var resp artifactDetail
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			p.Artifacts[lang] = append(p.Artifacts[lang], encode(t, resp, ""))
		}
		for _, id := range a.EngageActivities {
			activity, ok := engage.Lookup(id)
			if !ok {
				t.Fatalf("%s: activity %s is not in the bundled list", a.ID, id)
			}
			p.EngageActivities[id] = reference{Name: activity.Name}
		}
	}
	return encode(t, p, "  ")
}

// encode returns v as JSON without escaping &, < and >, because people read
// the file as well.
func encode(t *testing.T, v any, indent string) []byte {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", indent)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// The published catalog is what the server returns for every deception and
// artifact of the embedded catalog, so that it cannot differ from the API. A changed,
// added or removed entry changes it. Regenerate it with
// go test ./internal/catalog/... -update and review the diff.
//
// The test does not run in parallel, so that it has rewritten the file
// before the parallel tests read it.
func TestPublishedCatalog_MatchesTheEmbeddedCatalog(t *testing.T) {
	c, err := catalog.Load(embedded.FS())
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
// deception and artifact in it matches the schema of the API.
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
	for _, escape := range []string{`\u0026`, `\u003c`, `\u003e`} {
		if bytes.Contains(b, []byte(escape)) {
			t.Errorf("%s contains %s, which people read badly", publishedPath, escape)
		}
	}
	if p.SchemaVersion != publishedVersion {
		t.Errorf("schema_version = %d, want %d", p.SchemaVersion, publishedVersion)
	}
	for name, entries := range map[string]map[string][]json.RawMessage{"deceptions": p.Deceptions, "artifacts": p.Artifacts} {
		if langs := slices.Sorted(maps.Keys(entries)); !slices.Equal(langs, slices.Sorted(slices.Values(catalog.Languages))) {
			t.Errorf("%s: languages %v, want %v", name, langs, catalog.Languages)
		}
	}

	techniques, activities := map[string]bool{}, map[string]bool{}
	for lang, artifacts := range p.Artifacts {
		if len(artifacts) == 0 {
			t.Errorf("%s: no artifacts", lang)
		}
		for i, raw := range artifacts {
			for _, problem := range schemas.Check("CatalogArtifact", raw) {
				t.Errorf("artifacts %s[%d]: %s", lang, i, problem)
			}
			var a struct {
				EngageActivities []string `json:"engage_activities"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				t.Fatalf("artifacts %s[%d]: %v", lang, i, err)
			}
			for _, id := range a.EngageActivities {
				activities[id] = true
			}
		}
	}
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
			t.Errorf("%s names %v, the entries use %v", name, named, used)
		}
		for id, r := range tt.named {
			if r.Name == "" {
				t.Errorf("%s: %s has no name", name, id)
			}
		}
	}
}

// The notice of the file credits MITRE as NOTICE does, and NOTICE names the
// versions that the file holds, so that a new version of ATT&CK or Engage
// updates both.
func TestPublishedCatalog_NoticeMatchesNOTICE(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../../NOTICE")
	if err != nil {
		t.Fatal(err)
	}
	// NOTICE wraps its lines.
	text := strings.Join(strings.Fields(string(b)), " ")
	for _, want := range []string{
		"MITRE ATT&CK(R) Enterprise, version " + attack.Version() + ":",
		"MITRE Engage(TM), version " + engage.Version() + ":",
		attackNotice,
		engageNotice,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("NOTICE does not contain %q", want)
		}
	}
}
