// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalogapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/honeypot"
)

const definition = `{
  "schema_version": 3,
  "id": "%ID%",
  "category": "network",
  "title": {"en": "Title %ID%", "de": "Titel %ID%"},
  "summary": {"en": "Summary.", "de": "Zusammenfassung."},
  "techniques": ["T1021.004"],
  "engage_activities": ["EAC0005", "EAC0011"],
  "honeytokens": [
    {"label": {"en": "Gateway", "de": "Zugang"}, "type": "dns", "techniques": ["T1021.004"]},
    {"label": {"en": "Image", "de": "Bild"}, "type": "web_image", "techniques": []}
  ],
  "honeypots": [
    {"label": {"en": "Database", "de": "Datenbank"}, "service": "postgres"}
  ],
  "files": [
    {"name": "app.conf", "format": "config", "file": "app.conf"},
    {"name": "Read me.txt", "format": "text", "file": "Read me.txt"}
  ],
  "guide": {"en": "guide.en.md", "de": "guide.de.md"}
}`

// notes has no honeypot and no file, and its honeytoken no techniques.
const notes = `{
  "schema_version": 3,
  "id": "notes",
  "category": "data",
  "title": {"en": "Notes", "de": "Notizen"},
  "summary": {"en": "Summary.", "de": "Zusammenfassung."},
  "techniques": ["T1005"],
  "engage_activities": ["EAC0005"],
  "honeytokens": [
    {"label": {"en": "Image", "de": "Bild"}, "type": "web_image"}
  ],
  "honeypots": [],
  "files": [],
  "guide": {"en": "guide.en.md", "de": "guide.de.md"}
}`

// configContent has CRLF line endings, which a download keeps.
const configContent = "host=Honeytoken-Domain\r\nuser=svc-backup\r\n"

func testCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	file := func(content string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(content)} }
	fsys := fstest.MapFS{
		"deceptions/notes/deception.json": file(notes),
		"deceptions/notes/guide.en.md":    file("Place the image Honeytoken-URL.\n"),
		"deceptions/notes/guide.de.md":    file("Legen Sie das Bild Honeytoken-URL ab.\n"),
	}
	for _, id := range []string{"ssh", "rdp"} {
		fsys["deceptions/"+id+"/deception.json"] = file(strings.ReplaceAll(definition, "%ID%", id))
		fsys["deceptions/"+id+"/guide.en.md"] = file("Place the file with Honeytoken-Domain & Honeytoken-URL.\n")
		fsys["deceptions/"+id+"/guide.de.md"] = file("Legen Sie die Datei mit Honeytoken-Domain ab.\n")
		fsys["deceptions/"+id+"/files/app.conf"] = file(configContent)
		fsys["deceptions/"+id+"/files/Read me.txt"] = file("Call the service desk.\n")
	}
	c, err := catalog.Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// serve calls h with the path values given as name, value pairs.
func serve(t *testing.T, h http.HandlerFunc, target string, pathValues ...string) *httptest.ResponseRecorder {
	t.Helper()
	return serveMethod(t, h, http.MethodGet, target, pathValues...)
}

func serveMethod(t *testing.T, h http.HandlerFunc, method, target string, pathValues ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	for i := 0; i+1 < len(pathValues); i += 2 {
		req.SetPathValue(pathValues[i], pathValues[i+1])
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

	got := decode[listResponse](t, serve(t, h.List, "/api/v1/catalog/deceptions"))
	if len(got.Deceptions) != 3 {
		t.Fatalf("deceptions = %+v, want 3", got.Deceptions)
	}
	if got.Deceptions[0].ID != "notes" || got.Deceptions[1].ID != "rdp" || got.Deceptions[2].ID != "ssh" {
		t.Errorf("order = %s, %s, %s; want by identifier", got.Deceptions[0].ID, got.Deceptions[1].ID, got.Deceptions[2].ID)
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
		got := decode[listResponse](t, serve(t, h.List, target))
		if got.Deceptions[2].Title != want {
			t.Errorf("%s: title %q, want %q", target, got.Deceptions[2].Title, want)
		}
	}
	d := decode[detail](t, serve(t, h.Get, "/api/v1/catalog/deceptions/ssh?lang=de", "id", "ssh"))
	if d.Title != "Titel ssh" || d.Honeytokens[0].Label != "Zugang" || d.Honeypots[0].Label != "Datenbank" ||
		!strings.HasPrefix(d.Guide, "Legen Sie") {
		t.Errorf("detail in German = %+v", d)
	}
}

func TestRoutes_RejectInvalidQueries(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	for _, query := range []string{"?lang=fr", "?lang=DE", "?lang=", "?lang=de&lang=en", "?limit=10", "?lang=de&x=1", "?lang=%zz"} {
		for name, serveRoute := range map[string]func() *httptest.ResponseRecorder{
			"list": func() *httptest.ResponseRecorder { return serve(t, h.List, "/api/v1/catalog/deceptions"+query) },
			"get": func() *httptest.ResponseRecorder {
				return serve(t, h.Get, "/api/v1/catalog/deceptions/ssh"+query, "id", "ssh")
			},
		} {
			if rec := serveRoute(); rec.Code != http.StatusBadRequest {
				t.Errorf("%s %s: status %d, want 400", name, query, rec.Code)
			}
		}
	}
	// The download takes no query at all, also not the language: a file is
	// the same in both.
	for _, query := range []string{"?lang=de", "?x=1"} {
		if rec := serve(t, h.File, "/api/v1/catalog/deceptions/ssh/files/app.conf"+query, "id", "ssh", "name", "app.conf"); rec.Code != http.StatusBadRequest {
			t.Errorf("file %s: status %d, want 400", query, rec.Code)
		}
	}
}

func TestGet_ReturnsTheGuideTheSlotsAndTheFiles(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	d := decode[detail](t, serve(t, h.Get, "/api/v1/catalog/deceptions/ssh", "id", "ssh"))
	if d.ID != "ssh" || d.Title != "Title ssh" || len(d.Honeytokens) != 2 || d.Honeytokens[0].Type != "dns" ||
		d.Honeytokens[0].Label != "Gateway" || len(d.Honeytokens[0].Techniques) != 1 {
		t.Errorf("detail = %+v", d)
	}
	if len(d.Honeypots) != 1 || d.Honeypots[0] != (honeypotResponse{Label: "Database", Service: honeypot.ServicePostgres}) {
		t.Errorf("honeypots = %+v", d.Honeypots)
	}
	if want := "Place the file with Honeytoken-Domain & Honeytoken-URL.\n"; d.Guide != want {
		t.Errorf("guide = %q, want %q", d.Guide, want)
	}
	if len(d.Files) != 2 || d.Files[0] != (fileResponse{Name: "app.conf", Format: catalog.FormatConfig, Size: len(configContent)}) ||
		d.Files[1].Name != "Read me.txt" {
		t.Errorf("files = %+v", d.Files)
	}
	// The files are downloaded through their own route, not part of the detail.
	if body := serve(t, h.Get, "/api/v1/catalog/deceptions/ssh", "id", "ssh").Body.String(); strings.Contains(body, "svc-backup") {
		t.Errorf("the response contains the content of a file: %s", body)
	}
}

func TestGet_ReturnsEmptyListsAsArrays(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	body := serve(t, h.Get, "/api/v1/catalog/deceptions/notes", "id", "notes").Body.String()
	for _, want := range []string{`"honeypots":[]`, `"files":[]`, `"techniques":[]`} {
		if !strings.Contains(body, want) {
			t.Errorf("response %s does not contain %s", body, want)
		}
	}
}

func TestGet_UnknownDeceptionIsNotFound(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	if rec := serve(t, h.Get, "/api/v1/catalog/deceptions/missing", "id", "missing"); rec.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", rec.Code)
	}
}

// A file is served as it stands in the catalog, as an attachment that a browser
// saves and never renders.
func TestFile_ServesTheFileAsAnAttachmentThatIsNeverRendered(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	rec := serve(t, h.File, "/api/v1/catalog/deceptions/ssh/files/app.conf", "id", "ssh", "name", "app.conf")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	if got := rec.Body.String(); got != configContent {
		t.Errorf("body = %q, want the file as it stands, %q", got, configContent)
	}
	for name, want := range map[string]string{
		"Content-Type":            "application/octet-stream",
		"Content-Disposition":     `attachment; filename=app.conf`,
		"Content-Length":          strconv.Itoa(len(configContent)),
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'; sandbox",
		"Cache-Control":           "no-store",
	} {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	rec = serve(t, h.File, "/api/v1/catalog/deceptions/ssh/files/Read%20me.txt", "id", "ssh", "name", "Read me.txt")
	if got := rec.Header().Get("Content-Disposition"); got != `attachment; filename="Read me.txt"` {
		t.Errorf("Content-Disposition = %q, want the name quoted", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/plain", got)
	}
}

func TestFile_UnknownDeceptionOrFileIsNotFound(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	for _, path := range [][]string{{"missing", "app.conf"}, {"ssh", "missing.conf"}, {"notes", "app.conf"}, {"ssh", "../app.conf"}, {"ssh", "APP.conf"}} {
		rec := serve(t, h.File, "/api/v1/catalog/deceptions/"+path[0]+"/files/"+path[1], "id", path[0], "name", path[1])
		if rec.Code != http.StatusNotFound {
			t.Errorf("%v: status %d, want 404", path, rec.Code)
		}
	}
}

// A HEAD request receives the headers of the download and no body, which a
// real server guarantees.
func TestFile_HeadReceivesNoBody(t *testing.T) {
	t.Parallel()
	h := NewHandler(testCatalog(t))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /deceptions/{id}/files/{name}", h.File)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodHead, srv.URL+"/deceptions/ssh/files/app.conf", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK || resp.ContentLength != int64(len(configContent)) {
		t.Errorf("status %d, length %d, want 200 and %d", resp.StatusCode, resp.ContentLength, len(configContent))
	}
}
