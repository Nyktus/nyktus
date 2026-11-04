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
// honeytoken changes with honeytokens:write alone. Adding or removing a
// deception needs scenarios:write, and creating its honeytokens and honeypots
// as well needs the permissions of both. A denied write is rejected before the
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
	addDeception := `{"deception_id": "adcs-template-catalog"}`
	addWithResources := `{"deception_id": "adcs-template-catalog", "create_resources": true}`
	apply := `{"name": "a", "create_resources": true}`
	noHoneypots := keyWith("scenarios:write", "scenarios:read", "honeytokens:write", "honeytokens:read")
	noHoneytokens := keyWith("scenarios:write", "scenarios:read", "honeypots:write", "honeypots:read", "honeytokens:read")
	everything := keyWith("scenarios:write", "scenarios:read", "honeytokens:write", "honeytokens:read", "honeypots:write", "honeypots:read")

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
		// Adding a deception needs scenarios:write, and is refused before the
		// scenario is looked up.
		{"viewer adds a deception to an unknown scenario", viewer, nil, http.MethodPost, unknown + "/deceptions", addDeception, http.StatusForbidden},
		{"viewer removes a deception from an unknown scenario", viewer, nil, http.MethodDelete, unknown + "/deceptions/adcs-template-catalog", "", http.StatusForbidden},
		{"viewer adds a deception", viewer, nil, http.MethodPost, "/api/v1/scenarios/" + id + "/deceptions", addDeception, http.StatusForbidden},
		{"reading key adds a deception to an unknown scenario", nil, reader, http.MethodPost, unknown + "/deceptions", addDeception, http.StatusForbidden},
		{"reading key removes a deception", nil, reader, http.MethodDelete, "/api/v1/scenarios/" + id + "/deceptions/adcs-template-catalog", "", http.StatusForbidden},
		{"honeytoken key adds a deception", nil, tokens, http.MethodPost, "/api/v1/scenarios/" + id + "/deceptions", addDeception, http.StatusForbidden},
		{"writing key adds an unknown deception", nil, writer, http.MethodPost, "/api/v1/scenarios/" + id + "/deceptions", `{"deception_id": "nothing"}`, http.StatusBadRequest},
		// Creating the resources of a deception needs the permissions of the
		// resources, whatever the deception asks for, and is refused before
		// the scenario or the deception is looked up.
		{"writing key creates the resources in an unknown scenario", nil, writer, http.MethodPost, unknown + "/deceptions", addWithResources, http.StatusForbidden},
		{"writing key creates the resources of an unknown deception", nil, writer, http.MethodPost, unknown + "/deceptions", `{"deception_id": "nothing", "create_resources": true}`, http.StatusForbidden},
		{"writing key applies with the resources", nil, writer, http.MethodPost, "/api/v1/catalog/deceptions/adcs-template-catalog/apply", apply, http.StatusForbidden},
		{"writing key applies without the resources", nil, writer, http.MethodPost, "/api/v1/catalog/deceptions/adcs-template-catalog/apply", `{"name": "w"}`, http.StatusCreated},
		{"key without honeypots:write creates the resources", nil, noHoneypots, http.MethodPost, "/api/v1/catalog/deceptions/adcs-template-catalog/apply", apply, http.StatusForbidden},
		{"key without honeytokens:write creates the resources", nil, noHoneytokens, http.MethodPost, "/api/v1/catalog/deceptions/adcs-template-catalog/apply", apply, http.StatusForbidden},
		{"honeytoken key creates the resources", nil, tokens, http.MethodPost, "/api/v1/catalog/deceptions/adcs-template-catalog/apply", apply, http.StatusForbidden},
		{"viewer applies with the resources", viewer, nil, http.MethodPost, "/api/v1/catalog/deceptions/adcs-template-catalog/apply", apply, http.StatusForbidden},
		{"key with every write scope applies with the resources", nil, everything, http.MethodPost, "/api/v1/catalog/deceptions/adcs-template-catalog/apply", apply, http.StatusCreated},
		{"key with every write scope adds to an unknown scenario", nil, everything, http.MethodPost, unknown + "/deceptions", addWithResources, http.StatusNotFound},
		{"user adds a deception to an unknown scenario", user, nil, http.MethodPost, unknown + "/deceptions", addDeception, http.StatusNotFound},
		{"user adds a deception", user, nil, http.MethodPost, "/api/v1/scenarios/" + id + "/deceptions", addDeception, http.StatusCreated},
		{"user adds it twice", user, nil, http.MethodPost, "/api/v1/scenarios/" + id + "/deceptions", addDeception, http.StatusConflict},
		{"user removes it", user, nil, http.MethodDelete, "/api/v1/scenarios/" + id + "/deceptions/adcs-template-catalog", "", http.StatusOK},
		{"user removes it twice", user, nil, http.MethodDelete, "/api/v1/scenarios/" + id + "/deceptions/adcs-template-catalog", "", http.StatusNotFound},
		{"user removes it from an unknown scenario", user, nil, http.MethodDelete, unknown + "/deceptions/adcs-template-catalog", "", http.StatusNotFound},
		{"user adds it again", user, nil, http.MethodPost, "/api/v1/scenarios/" + id + "/deceptions", addDeception, http.StatusCreated},
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
	// A scenario names no honeytoken, so a key reads scenarios without reading
	// honeytokens.
	readOnly := mustJSON(t, map[string]any{
		"name": "r", "scopes": []string{"scenarios:read"}, "password": testPassword,
		"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	})
	if r := send(t, srv, http.MethodPost, "/api/v1/api-keys", readOnly, admin, nil); r.status != http.StatusCreated {
		t.Errorf("key with scenarios:read alone: %d %v, want 201", r.status, r.body)
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'scenarios.write' AND outcome = 'denied'`); n == 0 {
		t.Error("no denied write is recorded in the audit log")
	}
	// The permissions that creating the resources needs beyond the route are
	// recorded when they are denied, like those of the route.
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'honeypots.write' AND outcome = 'denied'`); n == 0 {
		t.Error("no denied creation of the resources is recorded in the audit log")
	}
}
