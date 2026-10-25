// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalogapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/honeytoken"
)

const definition = `{
  "schema_version": 2,
  "id": "%ID%",
  "category": "network",
  "title": {"en": "Title %ID%", "de": "Titel %ID%"},
  "summary": {"en": "Summary.", "de": "Zusammenfassung."},
  "techniques": ["T1021.004"],
  "engage_activities": ["EAC0005", "EAC0011"],
  "honeytokens": [
    {"key": "Gateway", "type": "dns", "label": {"en": "Gateway", "de": "Zugang"}, "techniques": ["T1021.004"]},
    {"key": "Image", "type": "web_image", "label": {"en": "Image", "de": "Bild"}, "techniques": []}
  ],
  "persona": [
    {"key": "Domain", "kind": "host", "label": {"en": "Domain", "de": "Domaene"}, "example": "corp.example.com"}
  ],
  "artifacts": ["%ID%"],
  "guide": {"en": "guide.en.md.tmpl", "de": "guide.de.md.tmpl"}
}`

// artifact is an artifact with a slot, a value of the persona and a secret.
const artifact = `{
  "schema_version": 1,
  "id": "%ID%",
  "category": "network",
  "title": {"en": "File %ID%", "de": "Datei %ID%"},
  "summary": {"en": "Artifact.", "de": "Artefakt."},
  "slots": [{"key": "Gateway", "accepts": ["dns"], "optional": false}],
  "persona": [
    {"key": "Domain", "kind": "host", "label": {"en": "Domain", "de": "Domaene"}, "example": "corp.example.com"}
  ],
  "secrets": [{"key": "Password", "length": 16}],
  "file_name": "%ID%.conf",
  "format": "config",
  "line_endings": "lf",
  "template": "config.tmpl"
}`

// memo has an optional slot and neither persona nor secrets, and no deception
// recommends it.
const memo = `{
  "schema_version": 1,
  "id": "memo",
  "category": "data",
  "title": {"en": "Memo", "de": "Notiz"},
  "summary": {"en": "Memo.", "de": "Notiz."},
  "slots": [{"key": "Image", "accepts": ["web_image", "web_url"], "optional": true}],
  "persona": [],
  "secrets": [],
  "file_name": "memo.txt",
  "format": "text",
  "line_endings": "crlf",
  "template": "memo.txt.tmpl"
}`

// plain is pocket litter with nothing to fill in.
const plain = `{
  "schema_version": 1,
  "id": "plain",
  "category": "endpoint",
  "title": {"en": "Plain", "de": "Schlicht"},
  "summary": {"en": "Plain.", "de": "Schlicht."},
  "slots": [],
  "persona": [],
  "secrets": [],
  "file_name": "plain.txt",
  "format": "text",
  "line_endings": "lf",
  "template": "plain.txt.tmpl"
}`

// guideOnly has neither a persona nor artifacts, and its honeytoken no
// techniques.
const guideOnly = `{
  "schema_version": 2,
  "id": "guide-only",
  "category": "data",
  "title": {"en": "Guide", "de": "Anleitung"},
  "summary": {"en": "Summary.", "de": "Zusammenfassung."},
  "techniques": ["T1005"],
  "engage_activities": ["EAC0005"],
  "honeytokens": [
    {"key": "Image", "type": "web_image", "label": {"en": "Image", "de": "Bild"}}
  ],
  "artifacts": [],
  "guide": {"en": "guide.en.md.tmpl", "de": "guide.de.md.tmpl"}
}`

func testCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	file := func(content string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(content)} }
	fsys := fstest.MapFS{
		"deceptions/guide-only/deception.json":   file(guideOnly),
		"deceptions/guide-only/guide.en.md.tmpl": file("{{.Honeytokens.Image.URL}}"),
		"deceptions/guide-only/guide.de.md.tmpl": file("{{.Honeytokens.Image.URL}}"),
		"artifacts/memo/artifact.json":           file(memo),
		"artifacts/memo/memo.txt.tmpl":           file("Reminder{{if .Honeytokens.Image.URL}}: {{.Honeytokens.Image.URL}}{{end}}\n"),
		"artifacts/plain/artifact.json":          file(plain),
		"artifacts/plain/plain.txt.tmpl":         file("Reminder\n"),
	}
	for _, id := range []string{"ssh", "rdp"} {
		fsys["deceptions/"+id+"/deception.json"] = file(strings.ReplaceAll(definition, "%ID%", id))
		fsys["deceptions/"+id+"/guide.en.md.tmpl"] = file("{{.Honeytokens.Image.URL}}")
		fsys["deceptions/"+id+"/guide.de.md.tmpl"] = file("{{.Honeytokens.Image.URL}}")
		fsys["artifacts/"+id+"/artifact.json"] = file(strings.ReplaceAll(artifact, "%ID%", id))
		fsys["artifacts/"+id+"/config.tmpl"] = file("Host {{.Honeytokens.Gateway.Host}}.{{.Persona.Domain}} {{.Secrets.Password}}\n")
	}
	// pair recommends both artifacts, which name the same secret.
	fsys["deceptions/pair/deception.json"] = file(strings.Replace(strings.ReplaceAll(definition, "%ID%", "pair"), `"artifacts": ["pair"]`, `"artifacts": ["rdp", "ssh"]`, 1))
	fsys["deceptions/pair/guide.en.md.tmpl"] = file("{{.Honeytokens.Image.URL}}")
	fsys["deceptions/pair/guide.de.md.tmpl"] = file("{{.Honeytokens.Image.URL}}")
	c, err := catalog.Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func serve(t *testing.T, h http.HandlerFunc, target, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if id != "" {
		req.SetPathValue("id", id)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestList_ReturnsEveryDeceptionInEnglish(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	got := decode[listResponse](t, serve(t, h.List, "/api/v1/catalog/deceptions", ""))
	if len(got.Deceptions) != 4 {
		t.Fatalf("deceptions = %+v, want 4", got.Deceptions)
	}
	first := got.Deceptions[0]
	if first.ID != "guide-only" || got.Deceptions[1].ID != "pair" || got.Deceptions[2].ID != "rdp" || got.Deceptions[3].ID != "ssh" {
		t.Errorf("order = %s, %s, %s, %s; want by identifier", first.ID, got.Deceptions[1].ID, got.Deceptions[2].ID, got.Deceptions[3].ID)
	}
	if ssh := got.Deceptions[3]; ssh.Title != "Title ssh" || ssh.Summary != "Summary." || ssh.Category != catalog.CategoryNetwork ||
		len(ssh.Techniques) != 1 || len(ssh.EngageActivities) != 2 {
		t.Errorf("ssh = %+v", ssh)
	}
}

func TestList_SelectsTheLanguage(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	for target, want := range map[string]string{
		"/api/v1/catalog/deceptions?lang=de": "Titel ssh",
		"/api/v1/catalog/deceptions?lang=en": "Title ssh",
	} {
		got := decode[listResponse](t, serve(t, h.List, target, ""))
		if got.Deceptions[3].Title != want {
			t.Errorf("%s: title %q, want %q", target, got.Deceptions[3].Title, want)
		}
	}
	d := decode[detail](t, serve(t, h.Get, "/api/v1/catalog/deceptions/ssh?lang=de", "ssh"))
	if d.Title != "Titel ssh" || d.Honeytokens[0].Label != "Zugang" || d.Persona[0].Label != "Domaene" {
		t.Errorf("detail in German = %+v", d)
	}
}

func TestRoutes_RejectInvalidQueries(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	for _, query := range []string{"?lang=fr", "?lang=DE", "?lang=", "?lang=de&lang=en", "?limit=10", "?lang=de&x=1", "?lang=%zz"} {
		for name, serveRoute := range map[string]func() *httptest.ResponseRecorder{
			"list": func() *httptest.ResponseRecorder { return serve(t, h.List, "/api/v1/catalog/deceptions"+query, "") },
			"get": func() *httptest.ResponseRecorder {
				return serve(t, h.Get, "/api/v1/catalog/deceptions/ssh"+query, "ssh")
			},
		} {
			if rec := serveRoute(); rec.Code != http.StatusBadRequest {
				t.Errorf("%s %s: status %d, want 400", name, query, rec.Code)
			}
		}
	}
}

func TestGet_ReturnsWhatApplyingCreatesAndAsksFor(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	d := decode[detail](t, serve(t, h.Get, "/api/v1/catalog/deceptions/ssh", "ssh"))
	if d.ID != "ssh" || d.Title != "Title ssh" || len(d.Honeytokens) != 2 || d.Honeytokens[0].Key != "Gateway" ||
		d.Honeytokens[0].Type != "dns" || d.Honeytokens[0].Label != "Gateway" || len(d.Honeytokens[0].Techniques) != 1 {
		t.Errorf("detail = %+v", d)
	}
	if len(d.Persona) != 1 || d.Persona[0] != (personaResponse{Key: "Domain", Kind: catalog.KindHost, Label: "Domain", Example: "corp.example.com"}) {
		t.Errorf("persona = %+v", d.Persona)
	}
	// The secrets are those of the artifacts that the deception recommends.
	if len(d.Secrets) != 1 || d.Secrets[0] != (secretResponse{Key: "Password", Length: 16}) {
		t.Errorf("secrets = %+v", d.Secrets)
	}
	if len(d.Artifacts) != 1 || d.Artifacts[0] != (artifactResponse{Key: "ssh", FileName: "ssh.conf", Format: catalog.FormatConfig}) {
		t.Errorf("artifacts = %+v", d.Artifacts)
	}
	// Templates are not part of the response.
	if body := serve(t, h.Get, "/api/v1/catalog/deceptions/ssh", "ssh").Body.String(); strings.Contains(body, "{{") {
		t.Errorf("the response contains a template: %s", body)
	}
}

func TestListArtifacts_ReturnsEveryArtifactInTheRequestedLanguage(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	got := decode[artifactListResponse](t, serve(t, h.ListArtifacts, "/api/v1/catalog/artifacts", ""))
	var ids []string
	for _, a := range got.Artifacts {
		ids = append(ids, a.ID)
	}
	if want := []string{"memo", "plain", "rdp", "ssh"}; !slices.Equal(ids, want) {
		t.Fatalf("artifacts = %v, want %v by identifier", ids, want)
	}
	if ssh := got.Artifacts[3]; ssh.Title != "File ssh" || ssh.Summary != "Artifact." || ssh.Category != catalog.CategoryNetwork {
		t.Errorf("ssh = %+v", ssh)
	}
	de := decode[artifactListResponse](t, serve(t, h.ListArtifacts, "/api/v1/catalog/artifacts?lang=de", ""))
	if de.Artifacts[3].Title != "Datei ssh" {
		t.Errorf("title in German = %q", de.Artifacts[3].Title)
	}
}

func TestGetArtifact_ReturnsTheFileAndWhatItAsksFor(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	a := decode[artifactDetail](t, serve(t, h.GetArtifact, "/api/v1/catalog/artifacts/ssh?lang=de", "ssh"))
	if a.ID != "ssh" || a.Title != "Datei ssh" || a.FileName != "ssh.conf" || a.Format != catalog.FormatConfig {
		t.Errorf("detail = %+v", a)
	}
	if len(a.Slots) != 1 || a.Slots[0].Key != "Gateway" || a.Slots[0].Optional || !slices.Equal(a.Slots[0].Accepts, []honeytoken.Type{honeytoken.TypeDNS}) {
		t.Errorf("slots = %+v", a.Slots)
	}
	if len(a.Persona) != 1 || a.Persona[0] != (personaResponse{Key: "Domain", Kind: catalog.KindHost, Label: "Domaene", Example: "corp.example.com"}) {
		t.Errorf("persona = %+v", a.Persona)
	}
	if len(a.Secrets) != 1 || a.Secrets[0] != (secretResponse{Key: "Password", Length: 16}) {
		t.Errorf("secrets = %+v", a.Secrets)
	}
	// An artifact that no deception recommends is served as well, with an
	// optional slot.
	m := decode[artifactDetail](t, serve(t, h.GetArtifact, "/api/v1/catalog/artifacts/memo", "memo"))
	if len(m.Slots) != 1 || !m.Slots[0].Optional || len(m.Slots[0].Accepts) != 2 {
		t.Errorf("memo slots = %+v", m.Slots)
	}
	// Templates are not part of the response.
	if body := serve(t, h.GetArtifact, "/api/v1/catalog/artifacts/ssh", "ssh").Body.String(); strings.Contains(body, "{{") || strings.Contains(body, "Host ") {
		t.Errorf("the response contains a template: %s", body)
	}
}

func TestGetArtifact_ReturnsEmptyListsAsArrays(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	var got map[string]any
	if err := json.Unmarshal(serve(t, h.GetArtifact, "/api/v1/catalog/artifacts/plain", "plain").Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"slots", "persona", "secrets"} {
		if list, ok := got[field].([]any); !ok || len(list) != 0 {
			t.Errorf("%s = %#v, want []", field, got[field])
		}
	}
}

func TestGetArtifact_UnknownArtifactIsNotFound(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	for _, id := range []string{"telnet", "SSH", "", "ssh/../rdp", "guide-only"} {
		if rec := serve(t, h.GetArtifact, "/api/v1/catalog/artifacts/x", id); rec.Code != http.StatusNotFound {
			t.Errorf("GetArtifact(%q): status %d, want 404", id, rec.Code)
		}
	}
}

// A secret that two artifacts of a deception name is listed once, so that the
// keys of the secrets of a deception stay unique.
func TestGet_ListsASecretOfSeveralArtifactsOnce(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	d := decode[detail](t, serve(t, h.Get, "/api/v1/catalog/deceptions/pair", "pair"))
	if len(d.Artifacts) != 2 || len(d.Secrets) != 1 || d.Secrets[0] != (secretResponse{Key: "Password", Length: 16}) {
		t.Errorf("artifacts = %+v, secrets = %+v, want two artifacts and one secret", d.Artifacts, d.Secrets)
	}
}

// Empty lists are [] rather than null, so that clients need not tell them
// apart.
func TestGet_ReturnsEmptyListsAsArrays(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	var got map[string]any
	rec := serve(t, h.Get, "/api/v1/catalog/deceptions/guide-only", "guide-only")
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"persona", "secrets", "artifacts"} {
		if list, ok := got[field].([]any); !ok || len(list) != 0 {
			t.Errorf("%s = %#v, want []", field, got[field])
		}
	}
	honeytokens, _ := got["honeytokens"].([]any)
	if first, _ := honeytokens[0].(map[string]any); first == nil || fmt.Sprint(first["techniques"]) != "[]" ||
		first["severity"] != string(honeytoken.Type(fmt.Sprint(first["type"])).DefaultSeverity()) {
		t.Errorf("honeytoken = %#v, want no techniques and the default severity of its type", first)
	}
}

func TestGet_UnknownDeceptionIsNotFound(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	for _, id := range []string{"telnet", "SSH", "", "ssh/../rdp"} {
		if rec := serve(t, h.Get, "/api/v1/catalog/deceptions/x", id); rec.Code != http.StatusNotFound {
			t.Errorf("Get(%q): status %d, want 404", id, rec.Code)
		}
	}
}
