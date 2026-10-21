// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/auth/password/passwordtest"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
)

const testPassword = "correct horse battery"

var (
	testSessions = session.Config{IdleTimeout: time.Hour, MaxAge: 12 * time.Hour}
	hasher       = passwordtest.NewHasher()
)

// testDB is a migrated database with a pool of the owner, for setting up state,
// and a pool of the console's database role.
type testDB struct {
	owner, console *pgxpool.Pool
}

func newTestDB(t *testing.T) testDB {
	t.Helper()
	ownerURL, consoleURL := schematest.Console(t)
	return testDB{owner: schematest.Open(t, ownerURL), console: schematest.Open(t, consoleURL)}
}

func (d testDB) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := d.owner.QueryRow(t.Context(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (d testDB) sessions(t *testing.T) *session.Service {
	t.Helper()
	svc, err := session.NewService(t.Context(), d.console, hasher, secretboxtest.Keyring(t), testSessions)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return svc
}

// createUser inserts an active account with the test password.
func createUser(t *testing.T, d testDB, email, role string) string {
	t.Helper()
	h, err := hasher.Hash(t.Context(), testPassword)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	var id string
	err = d.owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, password_hash) VALUES ($1, 'Test User', $2, 'active', $3)
RETURNING id`, email, role, h).Scan(&id)
	if err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	return id
}

// signIn starts a session of the account email and returns its cookie.
func signIn(t *testing.T, svc *session.Service, email string) *http.Cookie {
	t.Helper()
	result, err := svc.SignIn(t.Context(), email, testPassword, "")
	if err != nil || result.Token == "" {
		t.Fatalf("SignIn(%s) = %+v, %v", email, result, err)
	}
	return &http.Cookie{Name: session.CookieName, Value: result.Token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

type response struct {
	status int
	body   map[string]any
}

// send makes a request. The session cookie is sent by hand, because a cookie jar
// does not send Secure cookies to the plain HTTP test server.
func send(t *testing.T, srv *httptest.Server, method, path string, cookie *http.Cookie, header map[string]string) response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	if cookie != nil {
		req.Header.Add("Cookie", cookie.Name+"="+cookie.Value)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	r := response{status: resp.StatusCode}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &r.body); err != nil {
			t.Fatalf("decode body %q: %v", raw, err)
		}
	}
	return r
}
