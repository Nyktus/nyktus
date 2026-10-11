// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

const (
	origin = "https://nyktus.example.com"
	// testPassword is the password of every test account.
	testPassword = "correct horse battery"
)

var testSessions = session.Config{IdleTimeout: time.Hour, MaxAge: 12 * time.Hour}

// hasher is shared by all tests, as by all handlers of a process. Hashing with
// the real parameters keeps the timing property of the sign-in under test.
var hasher = password.NewHasher()

// testDB is a migrated database with a pool of the owner, for setting up state
// that the console cannot create, and a pool of the console's database role.
type testDB struct {
	owner, console *pgxpool.Pool
}

func newTestDB(t *testing.T) testDB {
	t.Helper()
	ownerURL, consoleURL := schematest.Console(t)
	return testDB{owner: schematest.Open(t, ownerURL), console: schematest.Open(t, consoleURL)}
}

func (d testDB) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := d.owner.Exec(t.Context(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (d testDB) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := d.owner.QueryRow(t.Context(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

// createUser inserts an account. With an empty password, the account has no
// password hash, as a pending one.
func createUser(t *testing.T, d testDB, email, role, status, pw string) string {
	t.Helper()
	var hash *string
	if pw != "" {
		h, err := hasher.Hash(t.Context(), pw)
		if err != nil {
			t.Fatalf("Hash() error = %v", err)
		}
		hash = &h
	}
	var id string
	err := d.owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, password_hash) VALUES ($1, 'Test User', $2, $3, $4)
RETURNING id`, email, role, status, hash).Scan(&id)
	if err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	return id
}

// startConsole starts the console as a process would, on a real server, so that
// the tests see what a client receives.
func startConsole(t *testing.T, d testDB) *httptest.Server {
	t.Helper()
	h, err := console.New(t.Context(), console.Options{
		Logger:         slog.New(slog.DiscardHandler),
		DB:             d.console,
		Setup:          setup.NewService(d.console),
		Hasher:         hasher,
		Sessions:       testSessions,
		ConsoleURL:     origin,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	})
	if err != nil {
		t.Fatalf("console.New() error = %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

type response struct {
	status int
	header http.Header
	body   map[string]any
	// cookie is the session cookie that the response sets, if any.
	cookie *http.Cookie
}

// send makes a request. The session cookie is sent by hand, because a cookie jar
// does not send Secure cookies to the plain HTTP test server.
func send(t *testing.T, srv *httptest.Server, method, path, body string, cookie *http.Cookie, header map[string]string) response {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
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
	r := response{status: resp.StatusCode, header: resp.Header}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &r.body); err != nil {
			t.Fatalf("decode body %q: %v", raw, err)
		}
	}
	for _, c := range resp.Cookies() {
		if c.Name == session.CookieName {
			r.cookie = c
		}
	}
	return r
}

func signInBody(email, pw string) string {
	b, err := json.Marshal(map[string]string{"email": email, "password": pw})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func signIn(t *testing.T, srv *httptest.Server, email, pw string, cookie *http.Cookie) response {
	t.Helper()
	return send(t, srv, http.MethodPost, "/api/v1/session", signInBody(email, pw), cookie, nil)
}

// mustSignIn signs in the account ada@example.com and returns the session cookie.
func mustSignIn(t *testing.T, srv *httptest.Server) *http.Cookie {
	t.Helper()
	r := signIn(t, srv, "ada@example.com", testPassword, nil)
	if r.status != http.StatusOK || r.cookie == nil {
		t.Fatalf("sign in: status %d, body %v", r.status, r.body)
	}
	return r.cookie
}

// normalized returns what a client can compare between two responses: status,
// headers and body, without the values that differ for every request.
func normalized(t *testing.T, r response) string {
	t.Helper()
	h := r.header.Clone()
	h.Del("X-Request-ID")
	h.Del("Date")
	body := map[string]any{}
	for k, v := range r.body {
		body[k] = v
	}
	if e, ok := body["error"].(map[string]any); ok {
		e = map[string]any{"code": e["code"], "message": e["message"]}
		body["error"] = e
	}
	b, err := json.Marshal(map[string]any{"status": r.status, "header": h, "body": body})
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	return string(b)
}

// clientCookie returns a session cookie with the given value, as a client would
// send it.
func clientCookie(value string) *http.Cookie {
	return &http.Cookie{Name: session.CookieName, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}
