// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"net/http"
	"testing"
	"time"
)

// Through the whole console: every role reads incidents and events, viewers
// cannot triage, and a key holds exactly its scopes. A denied triage is
// rejected before the incident is looked up, so it cannot reveal whether an
// incident exists.
func TestIncidents_FollowRolesAndKeyScopes(t *testing.T) {
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
	reader, triager, events, inventory := keyWith("incidents:read"), keyWith("incidents:write", "incidents:read"),
		keyWith("events:read"), keyWith("honeytokens:read")

	var id string
	if err := d.owner.QueryRow(t.Context(), `
INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at)
VALUES ('honeytoken', gen_random_uuid(), 'medium', now(), now()) RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	incident := "/api/v1/incidents/" + id
	unknown := "/api/v1/incidents/00000000-0000-4000-8000-000000000000"

	for _, tt := range []struct {
		name         string
		cookie       *http.Cookie
		header       map[string]string
		method, path string
		body         string
		status       int
	}{
		{"viewer lists incidents", viewer, nil, http.MethodGet, "/api/v1/incidents", "", http.StatusOK},
		{"viewer reads an incident", viewer, nil, http.MethodGet, incident, "", http.StatusOK},
		{"viewer lists events", viewer, nil, http.MethodGet, "/api/v1/events", "", http.StatusOK},
		{"viewer triages", viewer, nil, http.MethodPatch, incident, `{"status": "acknowledged"}`, http.StatusForbidden},
		{"viewer triages an unknown one", viewer, nil, http.MethodPatch, unknown, `{"status": "acknowledged"}`, http.StatusForbidden},
		{"user triages", user, nil, http.MethodPatch, incident, `{"status": "acknowledged"}`, http.StatusOK},
		{"admin triages", admin, nil, http.MethodPatch, incident, `{"notes": "a"}`, http.StatusOK},
		{"reading key lists", nil, reader, http.MethodGet, "/api/v1/incidents", "", http.StatusOK},
		{"reading key triages", nil, reader, http.MethodPatch, incident, `{"notes": "r"}`, http.StatusForbidden},
		{"reading key lists events", nil, reader, http.MethodGet, "/api/v1/events", "", http.StatusForbidden},
		{"triaging key triages", nil, triager, http.MethodPatch, incident, `{"notes": "t"}`, http.StatusOK},
		{"event key lists events", nil, events, http.MethodGet, "/api/v1/events", "", http.StatusOK},
		{"event key lists incidents", nil, events, http.MethodGet, "/api/v1/incidents", "", http.StatusForbidden},
		{"inventory key lists incidents", nil, inventory, http.MethodGet, "/api/v1/incidents", "", http.StatusForbidden},
		{"inventory key reads an unknown one", nil, inventory, http.MethodGet, unknown, "", http.StatusForbidden},
	} {
		if r := send(t, srv, tt.method, tt.path, tt.body, tt.cookie, tt.header); r.status != tt.status {
			t.Errorf("%s: %s %s = %d %v, want %d", tt.name, tt.method, tt.path, r.status, r.body, tt.status)
		}
	}

	// A key cannot triage incidents without reading them, because every change
	// returns the incident.
	writeOnly := mustJSON(t, map[string]any{
		"name": "w", "scopes": []string{"incidents:write"}, "password": testPassword,
		"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	})
	if r := send(t, srv, http.MethodPost, "/api/v1/api-keys", writeOnly, admin, nil); r.status != http.StatusBadRequest {
		t.Errorf("key with incidents:write alone: %d %v, want 400", r.status, r.body)
	}

	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'incidents.write' AND outcome = 'denied'`); n == 0 {
		t.Error("no denied triage is recorded in the audit log")
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'events.read' AND outcome = 'denied'`); n == 0 {
		t.Error("no denied read of events is recorded in the audit log")
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'incident.update' AND outcome = 'success' AND actor_kind = 'api_key'`); n != 1 {
		t.Errorf("%d triages by the key recorded, want 1", n)
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE action = 'events.read' AND outcome = 'success'`); n != 2 {
		t.Errorf("%d reads of events recorded, want one by the viewer and one by the key", n)
	}
}
