// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"net/http"
	"testing"
	"time"
)

// Through the whole console: every role reads scenarios, viewers cannot
// change them, and a key holds exactly its scenario scopes. The scenario of a
// honeytoken changes with honeytokens:write alone. Adding a deception or an
// artifact needs scenarios:write. A denied write is rejected before the
// scenario or the honeytoken is looked up, so it cannot reveal whether one
// exists.
func TestScenarios_FollowRolesAndKeyScopes(t *testing.T) {
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
	reader := keyWith("scenarios:read", "honeytokens:read")
	writer := keyWith("scenarios:write", "scenarios:read", "honeytokens:read")
	tokens := keyWith("honeytokens:write", "honeytokens:read")

	created := send(t, srv, http.MethodPost, "/api/v1/scenarios", `{"name": "a"}`, user, nil)
	id, _ := created.body["id"].(string)
	if created.status != http.StatusCreated || id == "" {
		t.Fatalf("create as user: %d %v", created.status, created.body)
	}
	honeytoken := send(t, srv, http.MethodPost, "/api/v1/honeytokens", `{"type": "web_url", "name": "h"}`, user, nil)
	h, _ := honeytoken.body["id"].(string)
	if honeytoken.status != http.StatusCreated || h == "" {
		t.Fatalf("create honeytoken: %d %v", honeytoken.status, honeytoken.body)
	}
	unknown := "/api/v1/scenarios/00000000-0000-4000-8000-000000000000"
	assign := `{"scenario_id": "` + id + `"}`
	addDeception := `{"deception_id": "browser-bookmarks", "persona": {"Company": "Example Ltd", "PortalName": "Intranet"}}`
	addArtifact := `{"catalog_artifact": "browser-bookmarks"}`

	for _, tt := range []struct {
		name         string
		cookie       *http.Cookie
		header       map[string]string
		method, path string
		body         string
		status       int
	}{
		{"admin lists", admin, nil, http.MethodGet, "/api/v1/scenarios", "", http.StatusOK},
		{"viewer lists", viewer, nil, http.MethodGet, "/api/v1/scenarios", "", http.StatusOK},
		{"viewer reads", viewer, nil, http.MethodGet, "/api/v1/scenarios/" + id, "", http.StatusOK},
		{"viewer creates", viewer, nil, http.MethodPost, "/api/v1/scenarios", `{"name": "v"}`, http.StatusForbidden},
		{"viewer changes", viewer, nil, http.MethodPatch, "/api/v1/scenarios/" + id, `{"name": "v"}`, http.StatusForbidden},
		{"viewer deletes an unknown one", viewer, nil, http.MethodDelete, unknown, "", http.StatusForbidden},
		{"viewer assigns", viewer, nil, http.MethodPut, "/api/v1/honeytokens/" + h + "/scenario", assign, http.StatusForbidden},
		{"viewer detaches", viewer, nil, http.MethodDelete, "/api/v1/honeytokens/" + h + "/scenario", "", http.StatusForbidden},
		{"reading key lists", nil, reader, http.MethodGet, "/api/v1/scenarios", "", http.StatusOK},
		{"reading key creates", nil, reader, http.MethodPost, "/api/v1/scenarios", `{"name": "r"}`, http.StatusForbidden},
		{"reading key changes an unknown one", nil, reader, http.MethodPatch, unknown, `{"name": "r"}`, http.StatusForbidden},
		{"reading key creates honeytokens", nil, reader, http.MethodPost, "/api/v1/honeytokens", `{"type": "web_url", "name": "r"}`, http.StatusForbidden},
		{"writing key creates", nil, writer, http.MethodPost, "/api/v1/scenarios", `{"name": "w"}`, http.StatusCreated},
		{"writing key changes", nil, writer, http.MethodPatch, "/api/v1/scenarios/" + id, `{"name": "w"}`, http.StatusOK},
		{"writing key assigns", nil, writer, http.MethodPut, "/api/v1/honeytokens/" + h + "/scenario", assign, http.StatusForbidden},
		{"honeytoken key reads", nil, tokens, http.MethodGet, "/api/v1/scenarios/" + id, "", http.StatusForbidden},
		{"honeytoken key assigns", nil, tokens, http.MethodPut, "/api/v1/honeytokens/" + h + "/scenario", assign, http.StatusOK},
		{"honeytoken key detaches", nil, tokens, http.MethodDelete, "/api/v1/honeytokens/" + h + "/scenario", "", http.StatusOK},
		{"user assigns", user, nil, http.MethodPut, "/api/v1/honeytokens/" + h + "/scenario", assign, http.StatusOK},
		// Adding a deception or an artifact needs scenarios:write, and is
		// refused before the scenario is looked up.
		{"viewer adds a deception to an unknown scenario", viewer, nil, http.MethodPost, unknown + "/deceptions", addDeception, http.StatusForbidden},
		{"viewer adds an artifact to an unknown scenario", viewer, nil, http.MethodPost, unknown + "/artifacts", addArtifact, http.StatusForbidden},
		{"viewer adds a deception", viewer, nil, http.MethodPost, "/api/v1/scenarios/" + id + "/deceptions", addDeception, http.StatusForbidden},
		{"reading key adds a deception to an unknown scenario", nil, reader, http.MethodPost, unknown + "/deceptions", addDeception, http.StatusForbidden},
		{"reading key adds an artifact", nil, reader, http.MethodPost, "/api/v1/scenarios/" + id + "/artifacts", addArtifact, http.StatusForbidden},
		{"honeytoken key adds a deception", nil, tokens, http.MethodPost, "/api/v1/scenarios/" + id + "/deceptions", addDeception, http.StatusForbidden},
		{"writing key adds an unknown deception", nil, writer, http.MethodPost, "/api/v1/scenarios/" + id + "/deceptions", `{"deception_id": "nothing"}`, http.StatusBadRequest},
		{"writing key adds an unknown artifact", nil, writer, http.MethodPost, "/api/v1/scenarios/" + id + "/artifacts", `{"catalog_artifact": "nothing"}`, http.StatusBadRequest},
		{"user adds a deception to an unknown scenario", user, nil, http.MethodPost, unknown + "/deceptions", addDeception, http.StatusNotFound},
		{"user adds a deception", user, nil, http.MethodPost, "/api/v1/scenarios/" + id + "/deceptions", addDeception, http.StatusCreated},
		{"user adds it twice", user, nil, http.MethodPost, "/api/v1/scenarios/" + id + "/deceptions", addDeception, http.StatusConflict},
		{"user deletes", user, nil, http.MethodDelete, "/api/v1/scenarios/" + id + "?honeytokens=delete", "", http.StatusNoContent},
		{"honeytoken deleted with the scenario", user, nil, http.MethodGet, "/api/v1/honeytokens/" + h, "", http.StatusNotFound},
	} {
		if r := send(t, srv, tt.method, tt.path, tt.body, tt.cookie, tt.header); r.status != tt.status {
			t.Errorf("%s: %s %s = %d %v, want %d", tt.name, tt.method, tt.path, r.status, r.body, tt.status)
		}
	}

	// A key cannot change scenarios without reading them, because every
	// change returns the scenario.
	writeOnly := mustJSON(t, map[string]any{
		"name": "w", "scopes": []string{"scenarios:write"}, "password": testPassword,
		"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	})
	if r := send(t, srv, http.MethodPost, "/api/v1/api-keys", writeOnly, admin, nil); r.status != http.StatusBadRequest {
		t.Errorf("key with scenarios:write alone: %d %v, want 400", r.status, r.body)
	}
	// A key cannot read scenarios without reading honeytokens, because the
	// guide of a scenario names its honeytokens.
	readOnly := mustJSON(t, map[string]any{
		"name": "r", "scopes": []string{"scenarios:read"}, "password": testPassword,
		"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	})
	if r := send(t, srv, http.MethodPost, "/api/v1/api-keys", readOnly, admin, nil); r.status != http.StatusBadRequest {
		t.Errorf("key with scenarios:read alone: %d %v, want 400", r.status, r.body)
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'scenarios.write' AND outcome = 'denied'`); n == 0 {
		t.Error("no denied write is recorded in the audit log")
	}
}
