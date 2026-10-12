// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeytokenapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/user"
)

const triggerURL = "https://t.example.com"

type fixture struct {
	h         *Handler
	owner     *pgxpool.Pool
	principal access.Principal
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ownerURL, consoleURL := schematest.Console(t)
	owner := schematest.Open(t, ownerURL)
	var id string
	err := owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, password_hash)
VALUES ('user@example.com', 'Test User', 'user', 'active', '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA')
RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{
		h:         NewHandler(slog.New(slog.DiscardHandler), schematest.Open(t, consoleURL), triggerURL),
		owner:     owner,
		principal: access.Principal{UserID: id, Role: user.RoleUser, Method: audit.AuthSession, SessionID: "s1"},
	}
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

func (f fixture) create(t *testing.T, body string) response {
	t.Helper()
	rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeytokens", "", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST %s: %d %s", body, rec.Code, rec.Body)
	}
	return decode[response](t, rec)
}

func TestCreate_ReturnsTheHoneytokenWithItsTriggerURL(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	got := f.create(t, `{"type": "web_url", "name": "Wiki link", "notes": "page Finance",
		"redirect_url": "https://wiki.example.com/finance", "techniques": ["T1213"]}`)
	if got.Type != "web_url" || got.Name != "Wiki link" || got.Notes != "page Finance" || !got.Enabled ||
		got.RedirectURL == nil || *got.RedirectURL != "https://wiki.example.com/finance" || !slices.Equal(got.Techniques, []string{"T1213"}) {
		t.Errorf("POST = %+v", got)
	}
	if got.TriggerURL != triggerURL+"/"+got.TriggerValue || len(got.TriggerValue) != 26 {
		t.Errorf("trigger_url = %q, trigger_value = %q; want the address of the trigger and the value", got.TriggerURL, got.TriggerValue)
	}

	// Without the optional members, a honeytoken is enabled and has no notes,
	// redirect or techniques; the lists are empty, never null.
	rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeytokens", "", `{"type": "web_image", "name": "Pixel"}`)
	raw := decode[map[string]any](t, rec)
	if rec.Code != http.StatusCreated || raw["enabled"] != true || raw["notes"] != "" || raw["redirect_url"] != nil ||
		raw["techniques"] == nil || len(raw["techniques"].([]any)) != 0 {
		t.Errorf("POST minimal = %d %s", rec.Code, rec.Body)
	}
	if got := f.create(t, `{"type": "web_url", "name": "Off", "enabled": false}`); got.Enabled {
		t.Error("POST with enabled false created an enabled honeytoken")
	}
}

func TestCreate_RejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	for _, body := range []string{
		`{"name": "a"}`,
		`{"type": "dns", "name": "a"}`,
		`{"type": "qr_code", "name": "a"}`,
		`{"type": "web_url"}`,
		`{"type": "web_url", "name": null}`,
		`{"type": "web_url", "name": " a"}`,
		`{"type": "web_url", "name": "a", "notes": "\u0000"}`,
		`{"type": "web_url", "name": "a", "redirect_url": ""}`,
		`{"type": "web_url", "name": "a", "redirect_url": "https://192.168.0.1/"}`,
		`{"type": "web_image", "name": "a", "redirect_url": "https://example.com"}`,
		`{"type": "web_url", "name": "a", "techniques": ["T9999"]}`,
		`{"type": "web_url", "name": "a", "techniques": ["T1078", "T1078"]}`,
		`{"type": "web_url", "name": "a", "trigger_value": "aaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
		`{"type": "web_url", "name": "a", "enabled": "yes"}`,
		`{"type": "web_url", "name": "a", "enabled": null}`,
		`{"type": "web_url", "name": "a", "notes": null}`,
		`{"type": "web_url", "name": "a", "redirect_url": null}`,
		`{"type": "web_url", "name": "a", "techniques": null}`,
	} {
		rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeytokens", "", body)
		if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
			t.Errorf("POST %s: %d %s, want 400 invalid_request", body, rec.Code, rec.Body)
		}
	}
	var n int
	if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM honeytokens`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d honeytokens, %v; want none", n, err)
	}
}

func TestGet(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	created := f.create(t, `{"type": "web_url", "name": "a"}`)

	rec := f.serve(t, f.h.Get, http.MethodGet, "/api/v1/honeytokens/"+created.ID, created.ID, "")
	if got := decode[response](t, rec); rec.Code != http.StatusOK || got.ID != created.ID || got.TriggerURL != created.TriggerURL {
		t.Errorf("GET = %d %s", rec.Code, rec.Body)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if rec := f.serve(t, f.h.Get, http.MethodGet, "/api/v1/honeytokens/"+id, id, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", id, rec.Code)
		}
	}
}

func TestList_PagesAndFilters(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	url := f.create(t, `{"type": "web_url", "name": "u"}`)
	image := f.create(t, `{"type": "web_image", "name": "i", "enabled": false}`)

	list := func(query string) (listResponse, int) {
		rec := f.serve(t, f.h.List, http.MethodGet, "/api/v1/honeytokens?"+query, "", "")
		if rec.Code != http.StatusOK {
			return listResponse{}, rec.Code
		}
		return decode[listResponse](t, rec), rec.Code
	}
	ids := func(l listResponse) []string {
		var ids []string
		for _, h := range l.Honeytokens {
			ids = append(ids, h.ID)
		}
		return ids
	}

	page, _ := list("limit=1")
	if !slices.Equal(ids(page), []string{image.ID}) || page.NextCursor == "" {
		t.Errorf("first page = %v, cursor %q", ids(page), page.NextCursor)
	}
	if next, _ := list("limit=1&cursor=" + page.NextCursor); !slices.Equal(ids(next), []string{url.ID}) || next.NextCursor != "" {
		t.Errorf("second page = %v, cursor %q", ids(next), next.NextCursor)
	}
	for query, want := range map[string][]string{
		"":                           {image.ID, url.ID},
		"type=web_url":               {url.ID},
		"type=web_image":             {image.ID},
		"enabled=true":               {url.ID},
		"enabled=false":              {image.ID},
		"type=web_url&enabled=false": nil,
	} {
		if got, code := list(query); code != http.StatusOK || !slices.Equal(ids(got), want) {
			t.Errorf("GET ?%s = %d %v, want %v", query, code, ids(got), want)
		}
	}
	if got, _ := list("type=web_image"); got.Honeytokens == nil {
		t.Error("an empty list is null, want []")
	}
	for _, query := range []string{"type=dns", "type=", "enabled=yes", "enabled=1", "type=web_url&type=web_image", "name=u", "limit=201"} {
		if _, code := list(query); code != http.StatusBadRequest {
			t.Errorf("GET ?%s = %d, want 400", query, code)
		}
	}
}

func TestUpdate(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h := f.create(t, `{"type": "web_url", "name": "a", "redirect_url": "https://example.com", "techniques": ["T1078"]}`)
	patch := func(body string) *httptest.ResponseRecorder {
		return f.serve(t, f.h.Update, http.MethodPatch, "/api/v1/honeytokens/"+h.ID, h.ID, body)
	}

	rec := patch(`{"name": "b", "notes": "n", "enabled": false, "techniques": []}`)
	got := decode[response](t, rec)
	if rec.Code != http.StatusOK || got.Name != "b" || got.Notes != "n" || got.Enabled || len(got.Techniques) != 0 ||
		got.RedirectURL == nil || got.TriggerValue != h.TriggerValue {
		t.Errorf("PATCH = %d %s", rec.Code, rec.Body)
	}
	// null removes the redirect.
	if rec := patch(`{"redirect_url": null}`); rec.Code != http.StatusOK || decode[response](t, rec).RedirectURL != nil {
		t.Errorf("PATCH redirect_url null = %d %s, want the redirect removed", rec.Code, rec.Body)
	}
	if rec := patch(`{"redirect_url": "https://other.example.com"}`); rec.Code != http.StatusOK {
		t.Errorf("PATCH redirect_url = %d %s", rec.Code, rec.Body)
	}

	for _, body := range []string{
		`{}`,
		`{"name": null}`,
		`{"enabled": null}`,
		`{"techniques": null}`,
		`{"notes": null}`,
		`{"redirect_url": ""}`,
		`{"redirect_url": "https://10.0.0.1"}`,
		`{"type": "web_image"}`,
		`{"trigger_value": "aaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
		`{"name": ""}`,
		`{"techniques": ["T1086"]}`,
	} {
		if rec := patch(body); rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
			t.Errorf("PATCH %s = %d %s, want 400 invalid_request", body, rec.Code, rec.Body)
		}
	}

	image := f.create(t, `{"type": "web_image", "name": "i"}`)
	rec = f.serve(t, f.h.Update, http.MethodPatch, "/", image.ID, `{"redirect_url": "https://example.com"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "web_url") {
		t.Errorf("PATCH redirect of an image = %d %s, want 400", rec.Code, rec.Body)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if rec := f.serve(t, f.h.Update, http.MethodPatch, "/", id, `{"name": "x"}`); rec.Code != http.StatusNotFound {
			t.Errorf("PATCH %s = %d, want 404", id, rec.Code)
		}
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h := f.create(t, `{"type": "web_url", "name": "a"}`)

	if rec := f.serve(t, f.h.Delete, http.MethodDelete, "/", h.ID, ""); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Errorf("DELETE = %d %s, want 204", rec.Code, rec.Body)
	}
	for _, id := range []string{h.ID, "not-a-uuid"} {
		if rec := f.serve(t, f.h.Delete, http.MethodDelete, "/", id, ""); rec.Code != http.StatusNotFound {
			t.Errorf("DELETE %s = %d, want 404", id, rec.Code)
		}
	}
}

// The representation carries exactly the members that the specification
// documents, so that a member added to one place only fails.
func TestResponse_HasTheDocumentedMembers(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	rec := f.serve(t, f.h.Create, http.MethodPost, "/api/v1/honeytokens", "", `{"type": "web_url", "name": "a"}`)
	got := slices.Sorted(maps.Keys(decode[map[string]any](t, rec)))
	want := slices.Sorted(maps.Keys(specSchemas(t)["Honeytoken"].Properties))
	if !slices.Equal(got, want) {
		t.Errorf("members %v, documented %v", got, want)
	}
}
