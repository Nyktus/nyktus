// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"net/http"
	"testing"
	"time"
)

// Through the whole console: every role reads honeytokens, viewers cannot
// change them, and a key holds exactly its honeytoken scopes. A denied write
// is rejected before the honeytoken is looked up, so it cannot reveal whether
// a honeytoken exists.
func TestHoneytokens_FollowRolesAndKeyScopes(t *testing.T) {
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
	keyWith := func(scopes ...string) map[string]string {
		body := mustJSON(t, map[string]any{
			"name": scopes[0], "scopes": scopes, "password": testPassword,
			"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
		r := send(t, srv, http.MethodPost, "/api/v1/api-keys", body, admin, nil)
		key, _ := r.body["key"].(string)
		if r.status != http.StatusCreated || key == "" {
			t.Fatalf("create key with %v: %d %v", scopes, r.status, r.body)
		}
		return bearer(key)
	}
	user, viewer := sessionOf("uma@example.com"), sessionOf("vic@example.com")
	reader, writer, auditor := keyWith("honeytokens:read"), keyWith("honeytokens:write", "honeytokens:read"), keyWith("audit:read")

	created := send(t, srv, http.MethodPost, "/api/v1/honeytokens", `{"type": "web_url", "name": "a"}`, user, nil)
	id, _ := created.body["id"].(string)
	if created.status != http.StatusCreated || id == "" {
		t.Fatalf("create as user: %d %v", created.status, created.body)
	}
	unknown := "/api/v1/honeytokens/00000000-0000-4000-8000-000000000000"

	for _, tt := range []struct {
		name         string
		cookie       *http.Cookie
		header       map[string]string
		method, path string
		body         string
		status       int
	}{
		{"admin lists", admin, nil, http.MethodGet, "/api/v1/honeytokens", "", http.StatusOK},
		{"viewer lists", viewer, nil, http.MethodGet, "/api/v1/honeytokens", "", http.StatusOK},
		{"viewer reads", viewer, nil, http.MethodGet, "/api/v1/honeytokens/" + id, "", http.StatusOK},
		{"viewer creates", viewer, nil, http.MethodPost, "/api/v1/honeytokens", `{"type": "web_url", "name": "v"}`, http.StatusForbidden},
		{"viewer changes", viewer, nil, http.MethodPatch, "/api/v1/honeytokens/" + id, `{"name": "v"}`, http.StatusForbidden},
		{"viewer deletes an unknown one", viewer, nil, http.MethodDelete, unknown, "", http.StatusForbidden},
		{"viewer deletes", viewer, nil, http.MethodDelete, "/api/v1/honeytokens/" + id, "", http.StatusForbidden},
		{"reading key lists", nil, reader, http.MethodGet, "/api/v1/honeytokens", "", http.StatusOK},
		{"reading key creates", nil, reader, http.MethodPost, "/api/v1/honeytokens", `{"type": "web_url", "name": "r"}`, http.StatusForbidden},
		{"reading key changes an unknown one", nil, reader, http.MethodPatch, unknown, `{"name": "r"}`, http.StatusForbidden},
		{"writing key creates", nil, writer, http.MethodPost, "/api/v1/honeytokens", `{"type": "web_image", "name": "w"}`, http.StatusCreated},
		{"writing key changes", nil, writer, http.MethodPatch, "/api/v1/honeytokens/" + id, `{"name": "w"}`, http.StatusOK},
		{"writing key lists", nil, writer, http.MethodGet, "/api/v1/honeytokens", "", http.StatusOK},
		{"audit key lists", nil, auditor, http.MethodGet, "/api/v1/honeytokens", "", http.StatusForbidden},
		{"audit key reads an unknown one", nil, auditor, http.MethodGet, unknown, "", http.StatusForbidden},
		{"user deletes", user, nil, http.MethodDelete, "/api/v1/honeytokens/" + id, "", http.StatusNoContent},
	} {
		if r := send(t, srv, tt.method, tt.path, tt.body, tt.cookie, tt.header); r.status != tt.status {
			t.Errorf("%s: %s %s = %d %v, want %d", tt.name, tt.method, tt.path, r.status, r.body, tt.status)
		}
	}

	// A key cannot change honeytokens without reading them, because every
	// change returns the honeytoken.
	writeOnly := mustJSON(t, map[string]any{
		"name": "w", "scopes": []string{"honeytokens:write"}, "password": testPassword,
		"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	})
	if r := send(t, srv, http.MethodPost, "/api/v1/api-keys", writeOnly, admin, nil); r.status != http.StatusBadRequest {
		t.Errorf("key with honeytokens:write alone: %d %v, want 400", r.status, r.body)
	}

	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'honeytokens.write' AND outcome = 'denied'`); n == 0 {
		t.Error("no denied write is recorded in the audit log")
	}
	if n := d.count(t, `
SELECT count(*) FROM audit_entries WHERE action = 'honeytoken.create' AND outcome = 'success' AND actor_kind = 'api_key'`); n != 1 {
		t.Errorf("%d creations by the key recorded, want 1", n)
	}
}
