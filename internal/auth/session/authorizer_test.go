// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/platform/logging"
)

// guardedServer serves a route that requires a permission no role holds, and one
// that only requires a signed-in caller, behind the session authorizer and the
// shared middleware. It records the log.
func guardedServer(t *testing.T, d testDB, logs *bytes.Buffer) (*httptest.Server, *int) {
	t.Helper()
	svc, err := session.NewService(t.Context(), d.console, hasher, testSessions)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	logger := logging.New(logs, slog.LevelInfo)
	loaded := 0
	rt := httpx.NewRouter(logger, session.NewAuthorizer(svc))
	rt.Handle(http.MethodGet, "/guarded", httpx.Require("test:read"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		loaded++
		w.WriteHeader(http.StatusNoContent)
	}))
	rt.Handle(http.MethodGet, "/mine", httpx.Authenticated, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := access.PrincipalFrom(r.Context())
		if !ok || p.SessionID == "" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"user_id": p.UserID, "role": string(p.Role)})
	}))
	srv := httptest.NewServer(httpx.Chain(rt, httpx.RequestID, httpx.AccessLog(logger), httpx.Recover(logger)))
	t.Cleanup(srv.Close)
	return srv, &loaded
}

func TestAuthorizer_DeniesMissingPermissionBeforeTheHandlerAndRecordsIt(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	id := createUser(t, d, "ada@example.com", "admin", "active", testPassword)
	c := mustSignIn(t, startConsole(t, d))
	var logs bytes.Buffer
	srv, loaded := guardedServer(t, d, &logs)

	if r := send(t, srv, http.MethodGet, "/guarded", "", nil, nil); r.status != http.StatusUnauthorized {
		t.Errorf("without a session: status %d, want 401", r.status)
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE outcome = 'denied'`); n != 0 {
		t.Errorf("a request without a session was recorded in the audit log")
	}

	if r := send(t, srv, http.MethodGet, "/guarded", "", c, nil); r.status != http.StatusForbidden {
		t.Errorf("without the permission: status %d, want 403", r.status)
	}
	if *loaded != 0 {
		t.Error("the handler ran for a denied request")
	}
	// The permission becomes the action, which the database checks.
	if n := d.count(t, `
SELECT count(*) FROM audit_entries WHERE action = 'test.read' AND outcome = 'denied'
	AND actor_kind = 'user' AND auth_method = 'session' AND actor_user_id = $1 AND request_id IS NOT NULL`, id); n != 1 {
		t.Errorf("%d denials recorded, want 1", n)
	}

	r := send(t, srv, http.MethodGet, "/mine", "", c, nil)
	if r.status != http.StatusOK || r.body["user_id"] != id || r.body["role"] != "admin" {
		t.Errorf("authenticated route: %d %v, want the principal", r.status, r.body)
	}

	// The access log names the principal, although the authorizer runs inside
	// the router, after the access log received the request.
	var named int
	for line := range strings.SplitSeq(strings.TrimSpace(logs.String()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode log record %q: %v", line, err)
		}
		if record["msg"] == "http: request" && record["user_id"] == id && record["auth_method"] == "session" {
			named++
		}
	}
	if named != 2 {
		t.Errorf("%d access log records name the principal, want 2 (denied and allowed):\n%s", named, logs.String())
	}
}

// A denied request is recorded with an action derived from the permission. Every
// permission that a role grants, and that a route can therefore require, must
// yield an action that the database accepts.
func TestDeniedActions_OfEveryPermissionAreAccepted(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	store := audit.NewStore(d.console)
	perms := access.Permissions()
	if len(perms) == 0 {
		t.Fatal("no role grants a permission")
	}
	for _, perm := range perms {
		err := store.Record(t.Context(), audit.Entry{
			Action:  access.DeniedAction(perm),
			Outcome: audit.OutcomeDenied,
			Actor:   audit.Actor{Kind: audit.ActorSystem, Method: audit.AuthNone},
		})
		if err != nil {
			t.Errorf("record denial of %s: %v", perm, err)
		}
	}
}
