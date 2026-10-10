// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package auditapi_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/auth/password"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/auth/setup"
	"nyktus.org/nyktus/internal/console"
	"nyktus.org/nyktus/internal/platform/schematest"
)

const testPassword = "correct horse battery"

var hasher = password.NewHasher()

type env struct {
	srv   *httptest.Server
	owner *pgxpool.Pool
}

func newEnv(t *testing.T) env {
	t.Helper()
	ownerURL, consoleURL := schematest.Console(t)
	pool := schematest.Open(t, consoleURL)
	h, err := console.New(t.Context(), console.Options{
		Logger:   slog.New(slog.DiscardHandler),
		DB:       pool,
		Setup:    setup.NewService(pool),
		Hasher:   hasher,
		Sessions: session.Config{IdleTimeout: time.Hour, MaxAge: 12 * time.Hour},
		Origin:   "https://nyktus.example.com",
	})
	if err != nil {
		t.Fatalf("console.New() error = %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return env{srv: srv, owner: schematest.Open(t, ownerURL)}
}

// signIn creates an account with role and returns its ID and session token.
func (e env) signIn(t *testing.T, email, role string) (id, tok string) {
	t.Helper()
	hash, err := hasher.Hash(t.Context(), testPassword)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if err := e.owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, password_hash) VALUES ($1, 'Test User', $2, 'active', $3)
RETURNING id`, email, role, hash).Scan(&id); err != nil {
		t.Fatalf("create user: %v", err)
	}
	body, err := json.Marshal(map[string]string{"email": email, "password": testPassword})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, e.srv.URL+"/api/v1/session", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	_ = resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == session.CookieName {
			return id, c.Value
		}
	}
	t.Fatalf("sign in %s: status %d without a session cookie", email, resp.StatusCode)
	return "", ""
}

func (e env) get(t *testing.T, tok, query string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, e.srv.URL+"/api/v1/audit-entries"+query, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if tok != "" {
		req.Header.Add("Cookie", session.CookieName+"="+tok)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	return resp.StatusCode, body
}

func entries(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()
	list, ok := body["entries"].([]any)
	if !ok {
		t.Fatalf("body = %v, want entries", body)
	}
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		out = append(out, e.(map[string]any))
	}
	return out
}

func TestListAuditEntries_OnlyAdministratorsMayRead(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, adminSession := e.signIn(t, "ada@example.com", "admin")
	for _, role := range []string{"editor", "viewer"} {
		id, tok := e.signIn(t, role+"@example.com", role)
		if status, _ := e.get(t, tok, ""); status != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", role, status)
		}
		var denied int
		if err := e.owner.QueryRow(t.Context(), `
SELECT count(*) FROM audit_entries WHERE action = 'audit.read' AND outcome = 'denied' AND actor_user_id = $1`, id).Scan(&denied); err != nil {
			t.Fatalf("count denials: %v", err)
		}
		if denied != 1 {
			t.Errorf("%s: %d denials recorded, want 1", role, denied)
		}
	}
	if status, _ := e.get(t, "", ""); status != http.StatusUnauthorized {
		t.Errorf("without a session: status %d, want 401", status)
	}
	if status, _ := e.get(t, adminSession, ""); status != http.StatusOK {
		t.Errorf("administrator: status %d, want 200", status)
	}
}

// The response carries exactly the documented fields, and the copies of the actor
// stay after the account is deleted.
func TestListAuditEntries_ReturnsDocumentedFields(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, tok := e.signIn(t, "ada@example.com", "admin")
	goneID, _ := e.signIn(t, "gone@example.com", "viewer")
	if _, err := e.owner.Exec(t.Context(), `DELETE FROM users WHERE id = $1`, goneID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	status, body := e.get(t, tok, "")
	if status != http.StatusOK {
		t.Fatalf("status %d, body %v", status, body)
	}
	allowed := map[string][]string{
		"entry":    {"id", "occurred_at", "action", "outcome", "actor", "resource", "changed_fields", "client_ip", "request_id"},
		"actor":    {"kind", "auth_method", "user_id", "email", "display_name", "api_key_id"},
		"resource": {"type", "id"},
	}
	var gone map[string]any
	for _, entry := range entries(t, body) {
		for k := range entry {
			if !slices.Contains(allowed["entry"], k) {
				t.Errorf("undocumented field %q in entry %v", k, entry)
			}
		}
		actor, _ := entry["actor"].(map[string]any)
		for k := range actor {
			if !slices.Contains(allowed["actor"], k) {
				t.Errorf("undocumented field %q in actor %v", k, actor)
			}
		}
		if resource, ok := entry["resource"].(map[string]any); ok {
			for k := range resource {
				if !slices.Contains(allowed["resource"], k) {
					t.Errorf("undocumented field %q in resource %v", k, resource)
				}
			}
		}
		if actor["email"] == "gone@example.com" {
			gone = entry
		}
	}
	if gone == nil {
		t.Fatal("the sign-in of the deleted account is missing")
	}
	actor := gone["actor"].(map[string]any)
	if gone["action"] != "session.create" || gone["outcome"] != "success" || actor["kind"] != "user" ||
		actor["auth_method"] != "password" || actor["user_id"] != nil || actor["display_name"] != "Test User" ||
		gone["request_id"] == nil {
		t.Errorf("entry of the deleted account = %v", gone)
	}
}

func TestListAuditEntries_PagesWithCursor(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, tok := e.signIn(t, "ada@example.com", "admin")
	for _, email := range []string{"b@example.com", "c@example.com", "d@example.com"} {
		e.signIn(t, email, "viewer")
	}
	var want []string
	if err := e.owner.QueryRow(t.Context(), `SELECT array_agg(id::text ORDER BY occurred_at DESC, id DESC) FROM audit_entries`).Scan(&want); err != nil {
		t.Fatalf("read IDs: %v", err)
	}

	var got []string
	query := "?limit=1"
	for range len(want) + 1 {
		status, body := e.get(t, tok, query)
		if status != http.StatusOK {
			t.Fatalf("GET %s: status %d, body %v", query, status, body)
		}
		for _, entry := range entries(t, body) {
			got = append(got, entry["id"].(string))
		}
		next, ok := body["next_cursor"].(string)
		if !ok {
			break
		}
		query = "?limit=1&cursor=" + url.QueryEscape(next)
	}
	if !slices.Equal(got, want) {
		t.Errorf("pages = %v, want %v", got, want)
	}

	status, body := e.get(t, tok, "")
	if status != http.StatusOK || len(entries(t, body)) != len(want) || body["next_cursor"] != nil {
		t.Errorf("default page: status %d, %d entries, next %v; want all %d without a cursor", status, len(entries(t, body)), body["next_cursor"], len(want))
	}
}

func TestListAuditEntries_RejectsInvalidQueries(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, tok := e.signIn(t, "ada@example.com", "admin")
	b64 := base64.RawURLEncoding.EncodeToString
	for _, query := range []string{
		"?limit=0",
		"?limit=201",
		"?limit=ten",
		"?limit=1&limit=2",
		"?offset=10",
		"?cursor=%%%",
		"?cursor=" + b64([]byte("2026-10-10T12:00:00Z")),
		"?cursor=" + b64([]byte("yesterday|00000000-0000-4000-8000-000000000000")),
		"?cursor=" + b64([]byte("2026-10-10T12:00:00Z|' OR 1=1 --")),
		"?cursor=" + b64([]byte("2026-10-10T12:00:00Z|00000000-0000-4000-8000-000000000000")) + "%3D",
	} {
		status, body := e.get(t, tok, query)
		errBody, _ := body["error"].(map[string]any)
		if status != http.StatusBadRequest || errBody["code"] != "invalid_request" {
			t.Errorf("GET %s: status %d, body %v; want 400", query, status, body)
		}
	}
	if status, _ := e.get(t, tok, "?cursor="+b64([]byte("2026-10-10T12:00:00.123456Z|00000000-0000-4000-8000-000000000000"))); status != http.StatusOK {
		t.Errorf("valid cursor: status %d, want 200", status)
	}
}
