// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"net/http"
	"testing"
	"time"
)

// Through the whole console: every role reads honeypots, viewers cannot
// change them or replace their secrets, and a key holds exactly its honeypot
// scopes. A denied request is rejected before the honeypot is looked up, so it
// cannot reveal whether a honeypot exists.
func TestHoneypots_FollowRolesAndKeyScopes(t *testing.T) {
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
	reader, writer := keyWith("honeypots:read"), keyWith("honeypots:write", "honeypots:read")
	tokens := keyWith("honeytokens:write", "honeytokens:read")

	created := send(t, srv, http.MethodPost, "/api/v1/honeypots", `{"service": "ssh", "name": "a"}`, user, nil)
	id, _ := created.body["id"].(string)
	if created.status != http.StatusCreated || id == "" || created.body["secret"] == nil {
		t.Fatalf("create as user: %d %v", created.status, created.body)
	}
	var scenarioID string
	if err := d.owner.QueryRow(t.Context(), `INSERT INTO scenarios (name) VALUES ('s') RETURNING id`).Scan(&scenarioID); err != nil {
		t.Fatal(err)
	}
	unknown := "/api/v1/honeypots/00000000-0000-4000-8000-000000000000"
	assign := `{"scenario_id": "` + scenarioID + `"}`

	for _, tt := range []struct {
		name         string
		cookie       *http.Cookie
		header       map[string]string
		method, path string
		body         string
		status       int
	}{
		{"admin lists", admin, nil, http.MethodGet, "/api/v1/honeypots", "", http.StatusOK},
		{"viewer lists", viewer, nil, http.MethodGet, "/api/v1/honeypots", "", http.StatusOK},
		{"viewer reads", viewer, nil, http.MethodGet, "/api/v1/honeypots/" + id, "", http.StatusOK},
		{"viewer creates", viewer, nil, http.MethodPost, "/api/v1/honeypots", `{"service": "ssh", "name": "v"}`, http.StatusForbidden},
		{"viewer changes", viewer, nil, http.MethodPatch, "/api/v1/honeypots/" + id, `{"name": "v"}`, http.StatusForbidden},
		{"viewer reads the secret", viewer, nil, http.MethodGet, "/api/v1/honeypots/" + id + "/secret", "", http.StatusForbidden},
		{"viewer reads the secret of an unknown one", viewer, nil, http.MethodGet, unknown + "/secret", "", http.StatusForbidden},
		{"viewer replaces the secret", viewer, nil, http.MethodPost, "/api/v1/honeypots/" + id + "/secret", "", http.StatusForbidden},
		{"viewer replaces the secret of an unknown one", viewer, nil, http.MethodPost, unknown + "/secret", "", http.StatusForbidden},
		{"viewer assigns", viewer, nil, http.MethodPut, "/api/v1/honeypots/" + id + "/scenario", assign, http.StatusForbidden},
		{"viewer deletes an unknown one", viewer, nil, http.MethodDelete, unknown, "", http.StatusForbidden},
		{"viewer deletes", viewer, nil, http.MethodDelete, "/api/v1/honeypots/" + id, "", http.StatusForbidden},
		{"reading key lists", nil, reader, http.MethodGet, "/api/v1/honeypots", "", http.StatusOK},
		{"reading key creates", nil, reader, http.MethodPost, "/api/v1/honeypots", `{"service": "ssh", "name": "r"}`, http.StatusForbidden},
		{"reading key changes an unknown one", nil, reader, http.MethodPatch, unknown, `{"name": "r"}`, http.StatusForbidden},
		{"reading key reads a secret", nil, reader, http.MethodGet, "/api/v1/honeypots/" + id + "/secret", "", http.StatusForbidden},
		{"reading key replaces a secret", nil, reader, http.MethodPost, "/api/v1/honeypots/" + id + "/secret", "", http.StatusForbidden},
		{"honeytoken key lists", nil, tokens, http.MethodGet, "/api/v1/honeypots", "", http.StatusForbidden},
		{"honeytoken key reads an unknown one", nil, tokens, http.MethodGet, unknown, "", http.StatusForbidden},
		{"honeytoken key assigns", nil, tokens, http.MethodPut, "/api/v1/honeypots/" + id + "/scenario", assign, http.StatusForbidden},
		{"writing key creates", nil, writer, http.MethodPost, "/api/v1/honeypots", `{"service": "ldap", "name": "w"}`, http.StatusCreated},
		{"writing key changes", nil, writer, http.MethodPatch, "/api/v1/honeypots/" + id, `{"name": "w"}`, http.StatusOK},
		{"writing key assigns without scenarios:write", nil, writer, http.MethodPut, "/api/v1/honeypots/" + id + "/scenario", assign, http.StatusOK},
		{"writing key detaches", nil, writer, http.MethodDelete, "/api/v1/honeypots/" + id + "/scenario", "", http.StatusOK},
		{"writing key reads the secret", nil, writer, http.MethodGet, "/api/v1/honeypots/" + id + "/secret", "", http.StatusOK},
		{"writing key replaces the secret", nil, writer, http.MethodPost, "/api/v1/honeypots/" + id + "/secret", "", http.StatusOK},
		{"user reads the secret", user, nil, http.MethodGet, "/api/v1/honeypots/" + id + "/secret", "", http.StatusOK},
		{"user reads the secret of an unknown one", user, nil, http.MethodGet, unknown + "/secret", "", http.StatusNotFound},
		{"user deletes", user, nil, http.MethodDelete, "/api/v1/honeypots/" + id, "", http.StatusNoContent},
	} {
		if r := send(t, srv, tt.method, tt.path, tt.body, tt.cookie, tt.header); r.status != tt.status {
			t.Errorf("%s: %s %s = %d %v, want %d", tt.name, tt.method, tt.path, r.status, r.body, tt.status)
		}
	}

	// A key cannot change honeypots without reading them, because every
	// change returns the honeypot.
	writeOnly := mustJSON(t, map[string]any{
		"name": "w", "scopes": []string{"honeypots:write"}, "password": testPassword,
		"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	})
	if r := send(t, srv, http.MethodPost, "/api/v1/api-keys", writeOnly, admin, nil); r.status != http.StatusBadRequest {
		t.Errorf("key with honeypots:write alone: %d %v, want 400", r.status, r.body)
	}

	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'honeypots.write' AND outcome = 'denied'`); n == 0 {
		t.Error("no denied write is recorded in the audit log")
	}
	if n := d.count(t, `
SELECT count(*) FROM audit_entries WHERE action = 'honeypot.create' AND outcome = 'success' AND actor_kind = 'api_key'`); n != 1 {
		t.Errorf("%d creations by the key recorded, want 1", n)
	}
}

// Deleting a scenario with its honeypots needs honeypots:write as well, because
// only that permission puts a honeypot into a scenario. A key that manages
// scenarios but not honeypots can still delete the scenario and keep its
// honeypots. The denial comes before the scenario is looked up and is recorded.
func TestScenarioDeletion_DeletesHoneypotsOnlyWithTheirPermission(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	srv := startConsole(t, d)
	admin := mustSignIn(t, srv)
	body := mustJSON(t, map[string]any{
		"name": "scenarios", "scopes": []string{"scenarios:write", "scenarios:read", "honeytokens:read"},
		"password": testPassword, "expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	})
	r := send(t, srv, http.MethodPost, "/api/v1/api-keys", body, admin, nil)
	key, _ := r.body["key"].(string)
	if r.status != http.StatusCreated || key == "" {
		t.Fatalf("create key: %d %v", r.status, r.body)
	}
	scenarios := bearer(key)

	scenarioWithHoneypot := func() (string, string) {
		t.Helper()
		sc := send(t, srv, http.MethodPost, "/api/v1/scenarios", `{"name": "s"}`, admin, nil)
		hp := send(t, srv, http.MethodPost, "/api/v1/honeypots", `{"service": "ssh", "name": "p"}`, admin, nil)
		scID, _ := sc.body["id"].(string)
		hpID, _ := hp.body["id"].(string)
		if put := send(t, srv, http.MethodPut, "/api/v1/honeypots/"+hpID+"/scenario", `{"scenario_id": "`+scID+`"}`, admin, nil); put.status != http.StatusOK {
			t.Fatalf("assign: %d %v", put.status, put.body)
		}
		return scID, hpID
	}

	sc, hp := scenarioWithHoneypot()
	for _, path := range []string{"/api/v1/scenarios/" + sc, "/api/v1/scenarios/00000000-0000-4000-8000-000000000000"} {
		if r := send(t, srv, http.MethodDelete, path+"?honeypots=delete", "", nil, scenarios); r.status != http.StatusForbidden {
			t.Errorf("DELETE %s?honeypots=delete with scenarios:write only = %d %v, want 403", path, r.status, r.body)
		}
	}
	if n := d.count(t, `SELECT count(*) FROM honeypots WHERE id = $1 AND scenario_id = $2`, hp, sc); n != 1 {
		t.Error("a denied deletion changed the honeypot")
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'honeypots.write' AND outcome = 'denied' AND actor_kind = 'api_key'`); n == 0 {
		t.Error("the denied deletion is not recorded in the audit log")
	}
	if r := send(t, srv, http.MethodDelete, "/api/v1/scenarios/"+sc+"?honeypots=keep", "", nil, scenarios); r.status != http.StatusNoContent {
		t.Errorf("DELETE ?honeypots=keep with scenarios:write = %d %v, want 204", r.status, r.body)
	}
	if n := d.count(t, `SELECT count(*) FROM honeypots WHERE id = $1 AND scenario_id IS NULL`, hp); n != 1 {
		t.Error("the kept honeypot does not stand alone")
	}

	sc, hp = scenarioWithHoneypot()
	if r := send(t, srv, http.MethodDelete, "/api/v1/scenarios/"+sc+"?honeypots=delete", "", admin, nil); r.status != http.StatusNoContent {
		t.Errorf("DELETE ?honeypots=delete as admin = %d %v, want 204", r.status, r.body)
	}
	if n := d.count(t, `SELECT count(*) FROM honeypots WHERE id = $1`, hp); n != 0 {
		t.Error("the honeypot was not deleted with its scenario")
	}
}
