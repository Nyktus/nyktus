// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalogapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"nyktus.org/nyktus/internal/catalog"
)

const definition = `{
  "schema_version": 1,
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
    {"key": "Domain", "kind": "host", "label": {"en": "Domain", "de": "Dom\u00e4ne"}, "example": "corp.example.com"}
  ],
  "secrets": [{"key": "Password", "length": 16}],
  "artifacts": [
    {"key": "config", "file_name": "config", "format": "config", "template": "config.tmpl"}
  ],
  "guide": {"en": "guide.en.md.tmpl", "de": "guide.de.md.tmpl"}
}`

// guideOnly has neither a persona, secrets nor artifacts, and its honeytoken
// no techniques.
const guideOnly = `{
  "schema_version": 1,
  "id": "guide-only",
  "category": "data",
  "title": {"en": "Guide", "de": "Anleitung"},
  "summary": {"en": "Summary.", "de": "Zusammenfassung."},
  "techniques": ["T1005"],
  "engage_activities": ["EAC0005"],
  "honeytokens": [
    {"key": "Image", "type": "web_image", "label": {"en": "Image", "de": "Bild"}}
  ],
  "guide": {"en": "guide.en.md.tmpl", "de": "guide.de.md.tmpl"}
}`

func testCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	fsys := fstest.MapFS{
		"guide-only/deception.json":   {Data: []byte(guideOnly)},
		"guide-only/guide.en.md.tmpl": {Data: []byte("{{.Honeytokens.Image.URL}}")},
		"guide-only/guide.de.md.tmpl": {Data: []byte("{{.Honeytokens.Image.URL}}")},
	}
	for _, id := range []string{"ssh", "rdp"} {
		fsys[id+"/deception.json"] = &fstest.MapFile{Data: []byte(strings.ReplaceAll(definition, "%ID%", id))}
		fsys[id+"/config.tmpl"] = &fstest.MapFile{Data: []byte("Host {{.Honeytokens.Gateway.Host}}.{{.Persona.Domain}} {{.Secrets.Password}}\n")}
		fsys[id+"/guide.en.md.tmpl"] = &fstest.MapFile{Data: []byte("{{.Honeytokens.Image.URL}}")}
		fsys[id+"/guide.de.md.tmpl"] = &fstest.MapFile{Data: []byte("{{.Honeytokens.Image.URL}}")}
	}
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
	if len(got.Deceptions) != 3 {
		t.Fatalf("deceptions = %+v, want 3", got.Deceptions)
	}
	first := got.Deceptions[0]
	if first.ID != "guide-only" || got.Deceptions[1].ID != "rdp" || got.Deceptions[2].ID != "ssh" {
		t.Errorf("order = %s, %s, %s; want by identifier", first.ID, got.Deceptions[1].ID, got.Deceptions[2].ID)
	}
	if ssh := got.Deceptions[2]; ssh.Title != "Title ssh" || ssh.Summary != "Summary." || ssh.Category != catalog.CategoryNetwork ||
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
		if got.Deceptions[2].Title != want {
			t.Errorf("%s: title %q, want %q", target, got.Deceptions[2].Title, want)
		}
	}
	d := decode[detail](t, serve(t, h.Get, "/api/v1/catalog/deceptions/ssh?lang=de", "ssh"))
	if d.Title != "Titel ssh" || d.Honeytokens[0].Label != "Zugang" || d.Persona[0].Label != "Dom\u00e4ne" {
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
	if len(d.Secrets) != 1 || d.Secrets[0] != (secretResponse{Key: "Password", Length: 16}) {
		t.Errorf("secrets = %+v", d.Secrets)
	}
	if len(d.Artifacts) != 1 || d.Artifacts[0] != (artifactResponse{Key: "config", FileName: "config", Format: catalog.FormatConfig}) {
		t.Errorf("artifacts = %+v", d.Artifacts)
	}
	// Templates are not part of the response.
	if body := serve(t, h.Get, "/api/v1/catalog/deceptions/ssh", "ssh").Body.String(); strings.Contains(body, "{{") {
		t.Errorf("the response contains a template: %s", body)
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
	if first, _ := honeytokens[0].(map[string]any); first == nil || fmt.Sprint(first["techniques"]) != "[]" {
		t.Errorf("honeytoken techniques = %#v, want []", first)
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
