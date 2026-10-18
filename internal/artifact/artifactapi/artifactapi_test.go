// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package artifactapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/artifact"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/platform/apispec"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/user"
)

type fixture struct {
	h              *Handler
	owner, console *pgxpool.Pool
	principal      access.Principal
	scenario       string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ownerURL, consoleURL := schematest.Console(t)
	owner := schematest.Open(t, ownerURL)
	var userID, scenarioID string
	err := owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, password_hash)
VALUES ('user@example.com', 'Test User', 'user', 'active', '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA')
RETURNING id`).Scan(&userID)
	if err != nil {
		t.Fatal(err)
	}
	err = owner.QueryRow(t.Context(), `
INSERT INTO scenarios (name, deception_id, language, persona, guide) VALUES ('s', 'browser-bookmarks', 'en', '{}', 'g')
RETURNING id`).Scan(&scenarioID)
	if err != nil {
		t.Fatal(err)
	}
	console := schematest.Open(t, consoleURL)
	return fixture{
		h:         NewHandler(slog.New(slog.DiscardHandler), console),
		owner:     owner,
		console:   console,
		principal: access.Principal{UserID: userID, Role: user.RoleUser, Method: audit.AuthSession, SessionID: "s1"},
		scenario:  scenarioID,
	}
}

// artifact stores an artifact in the scenario of the fixture, as applying a
// deception does.
func (f fixture) artifact(t *testing.T, fileName string, format catalog.Format, content string) artifact.Artifact {
	t.Helper()
	a, err := artifact.NewStore(f.console).Create(t.Context(), artifact.Spec{
		ScenarioID: f.scenario, DeceptionArtifact: "bookmarks", FileName: fileName, Format: format, Content: []byte(content),
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// serve calls handler as the router would, with the principal and the path
// value of the route.
func (f fixture) serve(t *testing.T, handler http.HandlerFunc, method, target, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(access.WithPrincipal(t.Context(), f.principal), method, target, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if id != "" {
		req.SetPathValue("id", id)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %s: %v", rec.Body, err)
	}
	return v
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	return decode[struct {
		Error struct{ Code string } `json:"error"`
	}](t, rec).Error.Code
}

func (f fixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := f.owner.QueryRow(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestListAndGet(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	first := f.artifact(t, "bookmarks.html", catalog.FormatHTML, "<p>x</p>")
	second := f.artifact(t, "config", catalog.FormatConfig, "Host a\n")

	page := decode[listResponse](t, f.serve(t, f.h.List, http.MethodGet, "/api/v1/artifacts?limit=1&scenario_id="+f.scenario, "", ""))
	if len(page.Artifacts) != 1 || page.Artifacts[0].ID != second.ID || page.NextCursor == "" {
		t.Fatalf("GET ?limit=1 = %+v, want the newest and a cursor", page)
	}
	page = decode[listResponse](t, f.serve(t, f.h.List, http.MethodGet, "/api/v1/artifacts?limit=1&scenario_id="+f.scenario+"&cursor="+page.NextCursor, "", ""))
	if len(page.Artifacts) != 1 || page.Artifacts[0].ID != first.ID || page.NextCursor != "" ||
		page.Artifacts[0].MediaType != "text/html; charset=utf-8" || page.Artifacts[0].Size != len("<p>x</p>") {
		t.Errorf("GET second page = %+v", page)
	}
	for _, q := range []string{"limit=0", "limit=201", "scenario_id=x", "name=x", "cursor=x"} {
		if rec := f.serve(t, f.h.List, http.MethodGet, "/api/v1/artifacts?"+q, "", ""); rec.Code != http.StatusBadRequest {
			t.Errorf("GET ?%s = %d, want 400", q, rec.Code)
		}
	}

	rec := f.serve(t, f.h.Get, http.MethodGet, "/", first.ID, "")
	if got := decode[Response](t, rec); rec.Code != http.StatusOK || got.ID != first.ID || got.FileName != "bookmarks.html" ||
		got.ScenarioID == nil || *got.ScenarioID != f.scenario {
		t.Errorf("GET = %d %s", rec.Code, rec.Body)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if rec := f.serve(t, f.h.Get, http.MethodGet, "/", id, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", id, rec.Code)
		}
	}
	// Reading metadata is not recorded; only downloads are.
	if n := f.count(t, `SELECT count(*) FROM audit_entries`); n != 0 {
		t.Errorf("%d audit entries, want none", n)
	}
}

func TestUpdateAndDelete(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	a := f.artifact(t, "config", catalog.FormatConfig, "Host a\n")

	rec := f.serve(t, f.h.Update, http.MethodPatch, "/", a.ID, `{"placement_notes": "~/.ssh/config of ws07"}`)
	if got := decode[Response](t, rec); rec.Code != http.StatusOK || got.PlacementNotes != "~/.ssh/config of ws07" {
		t.Errorf("PATCH = %d %s", rec.Code, rec.Body)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'artifact.update' AND changed_fields = '{placement_notes}' AND resource_id = $1`, a.ID); n != 1 {
		t.Errorf("%d entries of the change, want 1", n)
	}
	for _, body := range []string{
		`{}`, `{"placement_notes": null}`, `{"placement_notes": "a\u0000"}`,
		`{"placement_notes": "` + strings.Repeat("x", artifact.MaxPlacementNotesLength+1) + `"}`,
		`{"file_name": "other"}`, `{"scenario_id": null}`, `{"content": "x"}`,
	} {
		if rec := f.serve(t, f.h.Update, http.MethodPatch, "/", a.ID, body); rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
			t.Errorf("PATCH %s = %d %s, want 400 invalid_request", body, rec.Code, rec.Body)
		}
	}
	if rec := f.serve(t, f.h.Update, http.MethodPatch, "/", "00000000-0000-4000-8000-000000000000", `{"placement_notes": ""}`); rec.Code != http.StatusNotFound {
		t.Errorf("PATCH unknown = %d, want 404", rec.Code)
	}

	if rec := f.serve(t, f.h.Delete, http.MethodDelete, "/", a.ID, ""); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Errorf("DELETE = %d %s, want 204", rec.Code, rec.Body)
	}
	if rec := f.serve(t, f.h.Delete, http.MethodDelete, "/", a.ID, ""); rec.Code != http.StatusNotFound {
		t.Errorf("DELETE again = %d, want 404", rec.Code)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'artifact.delete' AND resource_id = $1`, a.ID); n != 1 {
		t.Errorf("%d entries of the deletion, want 1", n)
	}
}

// A real client receives the file as an attachment with the media type of
// its format, which it must not sniff, and in a sandbox if a browser renders
// it anyway, also for HEAD, which receives no body. The test runs a server,
// because a recorder keeps what a real server would not send.
func TestDownload_IsAnAttachmentForARealClient(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	html := f.artifact(t, "bookmarks.html", catalog.FormatHTML, "<script>alert(1)</script>")
	config := f.artifact(t, "Read me.txt", catalog.FormatText, "notes\r\n")
	// Beyond the buffer of net/http, a response without a length would be
	// sent in chunks.
	large := strings.Repeat("# notes\n", 16<<10)
	markdown := f.artifact(t, "notes.md", catalog.FormatMarkdown, large)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(access.WithPrincipal(r.Context(), f.principal))
		r.SetPathValue("id", strings.TrimPrefix(r.URL.Path, "/"))
		f.h.Download(w, r)
	}))
	t.Cleanup(srv.Close)

	for _, tt := range []struct {
		a         artifact.Artifact
		mediaType string
		content   string
	}{
		{html, "text/html; charset=utf-8", "<script>alert(1)</script>"},
		{config, "text/plain; charset=utf-8", "notes\r\n"},
		{markdown, "text/markdown; charset=utf-8", large},
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+"/"+tt.a.ID, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			disposition, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
			if resp.StatusCode != http.StatusOK || err != nil || disposition != "attachment" || params["filename"] != tt.a.FileName {
				t.Errorf("%s %s: status %d, Content-Disposition %q, %v", method, tt.a.FileName, resp.StatusCode, resp.Header.Get("Content-Disposition"), err)
			}
			for header, want := range map[string]string{
				"Content-Type":            tt.mediaType,
				"X-Content-Type-Options":  "nosniff",
				"Content-Security-Policy": "default-src 'none'; sandbox",
				"Cache-Control":           "no-store",
			} {
				if got := resp.Header.Get(header); got != want {
					t.Errorf("%s %s: %s = %q, want %q", method, tt.a.FileName, header, got, want)
				}
			}
			wantBody := tt.content
			if method == http.MethodHead {
				wantBody = ""
			}
			if string(body) != wantBody || resp.ContentLength != int64(len(tt.content)) {
				t.Errorf("%s %s: body of %d bytes, length %d; want %d bytes of %d", method, tt.a.FileName, len(body), resp.ContentLength, len(wantBody), len(tt.content))
			}
		}
	}
	// Every download is recorded, at most once per actor and minute.
	if n := f.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'artifacts.read' AND outcome = 'success' AND actor_user_id = $1`, f.principal.UserID); n != 1 {
		t.Errorf("%d reads recorded, want 1", n)
	}
}

// A download that cannot be recorded sends nothing.
func TestDownload_FailsWithoutItsAuditEntry(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	a := f.artifact(t, "config", catalog.FormatConfig, "Host secret.d.example.net\n")
	f.principal.UserID = "00000000-0000-4000-8000-000000000000"

	rec := f.serve(t, f.h.Download, http.MethodGet, "/", a.ID, "")
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret.d.example.net") {
		t.Errorf("GET content without audit entry = %d %s, want 500 without the content", rec.Code, rec.Body)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if rec := f.serve(t, f.h.Download, http.MethodGet, "/", id, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET content of %s = %d, want 404", id, rec.Code)
		}
	}
}

// Every kind of response matches the schema of the specification.
func TestResponses_MatchTheSpecification(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	schemas, err := apispec.ParseSchemas(api.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
	a := f.artifact(t, "config", catalog.FormatConfig, "Host a\n")
	f.artifact(t, "notes.md", catalog.FormatMarkdown, "# x\n")
	if _, err := f.owner.Exec(t.Context(), `UPDATE artifacts SET scenario_id = NULL WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}

	for _, b := range []struct {
		schema string
		rec    *httptest.ResponseRecorder
	}{
		{"ArtifactPage", f.serve(t, f.h.List, http.MethodGet, "/api/v1/artifacts", "", "")},
		{"ArtifactPage", f.serve(t, f.h.List, http.MethodGet, "/api/v1/artifacts?limit=1", "", "")},
		{"Artifact", f.serve(t, f.h.Get, http.MethodGet, "/", a.ID, "")},
		{"Artifact", f.serve(t, f.h.Update, http.MethodPatch, "/", a.ID, `{"placement_notes": "n"}`)},
	} {
		if b.rec.Code >= 300 {
			t.Fatalf("%s: status %d %s", b.schema, b.rec.Code, b.rec.Body)
		}
		for _, p := range schemas.Check(b.schema, b.rec.Body.Bytes()) {
			t.Error(p)
		}
	}
}
