// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"net/http"
	"testing"
	"time"
)

// Through the whole console: every role reads and downloads artifacts,
// viewers cannot change them, and a key holds exactly its artifact scopes,
// which require reading honeytokens, whose URLs the content holds. A denied
// write is rejected before the artifact is looked up. Downloads are requested
// with HEAD, which runs the same handler, so that the test reads JSON only.
func TestArtifacts_FollowRolesAndKeyScopes(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	createUser(t, d, "uma@example.com", "user", "active", testPassword)
	createUser(t, d, "vic@example.com", "viewer", "active", testPassword)
	srv := startConsole(t, d)
	admin := mustSignIn(t, srv)
	sessionOf := func(email string) *http.Cookie {
		r := signIn(t, srv, email, testPassword, nil)
		if r.status != http.StatusOK || r.cookie == nil {
			t.Fatalf("sign in %s: %d %v", email, r.status, r.body)
		}
		return r.cookie
	}
	keyRequest := func(scopes ...string) string {
		return mustJSON(t, map[string]any{
			"name": scopes[0], "scopes": scopes, "password": testPassword,
			"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
	}
	keyWith := func(scopes ...string) map[string]string {
		r := send(t, srv, http.MethodPost, "/api/v1/api-keys", keyRequest(scopes...), admin, nil)
		key, _ := r.body["key"].(string)
		if r.status != http.StatusCreated || key == "" {
			t.Fatalf("create key with %v: %d %v", scopes, r.status, r.body)
		}
		return bearer(key)
	}
	user, viewer := sessionOf("uma@example.com"), sessionOf("vic@example.com")
	reader := keyWith("artifacts:read", "honeytokens:read")
	writer := keyWith("artifacts:write", "artifacts:read", "honeytokens:read")
	tokens := keyWith("honeytokens:read")

	applied := send(t, srv, http.MethodPost, "/api/v1/catalog/deceptions/adcs-template-catalog/apply", `{"name": "s", "persona": {"Company": "Example Ltd", "Authority": "Example CA"}}`, user, nil)
	if applied.status != http.StatusCreated {
		t.Fatalf("apply as user: %d %v", applied.status, applied.body)
	}
	sc, _ := applied.body["scenario"].(map[string]any)
	artifacts, _ := applied.body["artifacts"].([]any)
	if sc == nil || len(artifacts) != 2 {
		t.Fatalf("apply = %v, want a scenario with two artifacts", applied.body)
	}
	id, _ := artifacts[0].(map[string]any)["id"].(string)
	path := "/api/v1/artifacts/" + id
	unknown := "/api/v1/artifacts/00000000-0000-4000-8000-000000000000"
	notes := `{"placement_notes": "desktop of ws07"}`

	for _, tt := range []struct {
		name         string
		cookie       *http.Cookie
		header       map[string]string
		method, path string
		body         string
		status       int
	}{
		{"admin lists", admin, nil, http.MethodGet, "/api/v1/artifacts", "", http.StatusOK},
		{"viewer lists", viewer, nil, http.MethodGet, "/api/v1/artifacts", "", http.StatusOK},
		{"viewer reads", viewer, nil, http.MethodGet, path, "", http.StatusOK},
		{"viewer downloads", viewer, nil, http.MethodHead, path + "/content", "", http.StatusOK},
		{"viewer changes", viewer, nil, http.MethodPatch, path, notes, http.StatusForbidden},
		{"viewer deletes an unknown one", viewer, nil, http.MethodDelete, unknown, "", http.StatusForbidden},
		{"reading key lists", nil, reader, http.MethodGet, "/api/v1/artifacts", "", http.StatusOK},
		{"reading key downloads", nil, reader, http.MethodHead, path + "/content", "", http.StatusOK},
		{"reading key changes an unknown one", nil, reader, http.MethodPatch, unknown, notes, http.StatusForbidden},
		{"reading key reads scenarios", nil, reader, http.MethodGet, "/api/v1/scenarios", "", http.StatusForbidden},
		{"honeytoken key lists", nil, tokens, http.MethodGet, "/api/v1/artifacts", "", http.StatusForbidden},
		{"honeytoken key downloads", nil, tokens, http.MethodHead, path + "/content", "", http.StatusForbidden},
		{"writing key changes", nil, writer, http.MethodPatch, path, notes, http.StatusOK},
		{"user changes", user, nil, http.MethodPatch, path, `{"placement_notes": ""}`, http.StatusOK},
		{"writing key deletes", nil, writer, http.MethodDelete, path, "", http.StatusNoContent},
		{"deleted", user, nil, http.MethodGet, path, "", http.StatusNotFound},
	} {
		if r := send(t, srv, tt.method, tt.path, tt.body, tt.cookie, tt.header); r.status != tt.status {
			t.Errorf("%s: %s %s = %d %v, want %d", tt.name, tt.method, tt.path, r.status, r.body, tt.status)
		}
	}

	// Reading artifacts is reading the URLs of honeytokens, and changing them
	// returns them.
	for _, scopes := range [][]string{{"artifacts:read"}, {"artifacts:write", "honeytokens:read"}} {
		if r := send(t, srv, http.MethodPost, "/api/v1/api-keys", keyRequest(scopes...), admin, nil); r.status != http.StatusBadRequest {
			t.Errorf("key with %v: %d %v, want 400", scopes, r.status, r.body)
		}
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'artifacts.write' AND outcome = 'denied'`); n == 0 {
		t.Error("no denied write is recorded in the audit log")
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'artifacts.read' AND outcome = 'success'`); n != 2 {
		t.Errorf("%d downloads recorded, want one for the viewer and one for the key", n)
	}
}
