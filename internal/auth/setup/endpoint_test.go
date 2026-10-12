// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package setup_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"nyktus.org/nyktus/internal/auth/password"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/auth/setup"
	"nyktus.org/nyktus/internal/console"
	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
)

// startConsole starts the console as a process would, on a real server, so that
// the tests see what a client receives. Each call stands for a start of the
// process: it issues a setup token if the setup is open.
func startConsole(t *testing.T, d testDB) (srv *httptest.Server, tok setup.Token, issued bool) {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	svc := setup.NewService(d.console)
	tok, issued, err := svc.Issue(t.Context())
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	h, err := console.New(t.Context(), console.Options{
		Logger:         logger,
		DB:             d.console,
		Setup:          svc,
		Hasher:         password.NewHasher(),
		Sessions:       session.Config{IdleTimeout: time.Hour, MaxAge: 12 * time.Hour},
		Keys:           secretboxtest.Keyring(t),
		ConsoleURL:     "https://nyktus.example.com",
		TriggerURL:     "https://t.example.net",
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	})
	if err != nil {
		t.Fatalf("console.New() error = %v", err)
	}
	srv = httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, tok, issued
}

type response struct {
	status int
	header http.Header
	body   map[string]any
}

func post(t *testing.T, srv *httptest.Server, path, body string) response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	r := response{status: resp.StatusCode, header: resp.Header}
	if err := json.Unmarshal(raw, &r.body); err != nil {
		t.Fatalf("decode body %q: %v", raw, err)
	}
	return r
}

func setupBody(token, email string) string {
	b, err := json.Marshal(map[string]string{
		"token": token, "email": email, "display_name": "Ada Admin", "password": "correct horse battery",
	})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// assertUnknownRoute fails unless r cannot be told apart from the response to a
// route that does not exist. Only the request ID differs between requests.
func assertUnknownRoute(t *testing.T, srv *httptest.Server, r response) {
	t.Helper()
	unknown := post(t, srv, "/api/v1/unknown", setupBody("", ""))
	normalize := func(r response) string {
		h := r.header.Clone()
		h.Del("X-Request-ID")
		h.Del("Date")
		if e, ok := r.body["error"].(map[string]any); ok {
			delete(e, "request_id")
		}
		b, err := json.Marshal(map[string]any{"status": r.status, "header": h, "body": r.body})
		if err != nil {
			t.Fatalf("encode response: %v", err)
		}
		return string(b)
	}
	if got, want := normalize(r), normalize(unknown); got != want {
		t.Errorf("response = %s, want the response of an unknown route: %s", got, want)
	}
}

func TestSetupEndpoint_AcceptsOnlyCurrentTokenAndReturns404OnceAdministratorExists(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	srv, tok, issued := startConsole(t, d)
	if !issued {
		t.Fatal("no setup token issued on the first start")
	}

	t.Run("unknown token", func(t *testing.T) {
		assertUnknownRoute(t, srv, post(t, srv, "/api/v1/setup", setupBody(strings.Repeat("A", 43), "ada@example.com")))
	})

	created := post(t, srv, "/api/v1/setup", setupBody(tok.Value, "Ada@Example.com"))
	if created.status != http.StatusCreated {
		t.Fatalf("setup with the current token: status = %d, body = %v", created.status, created.body)
	}
	if created.body["email"] != "ada@example.com" || created.body["role"] != "admin" || created.body["status"] != "active" {
		t.Errorf("created = %v, want an active administrator", created.body)
	}
	if _, ok := created.body["password_hash"]; ok {
		t.Error("the response contains the password hash")
	}

	var clientIP, requestID string
	err := d.owner.QueryRow(t.Context(), `SELECT host(client_ip), request_id FROM audit_entries WHERE resource_id = $1`,
		created.body["id"]).Scan(&clientIP, &requestID)
	if err != nil {
		t.Fatalf("read audit entry: %v", err)
	}
	if clientIP != "203.0.113.9" || requestID != created.header.Get("X-Request-ID") {
		t.Errorf("audit entry client_ip = %s, request_id = %s; want 203.0.113.9 and %s", clientIP, requestID, created.header.Get("X-Request-ID"))
	}

	t.Run("used token", func(t *testing.T) {
		assertUnknownRoute(t, srv, post(t, srv, "/api/v1/setup", setupBody(tok.Value, "eve@example.com")))
	})
	t.Run("malformed request", func(t *testing.T) {
		assertUnknownRoute(t, srv, post(t, srv, "/api/v1/setup", `{"role":"admin"}`))
	})
	t.Run("after a restart", func(t *testing.T) {
		restarted, tok, issued := startConsole(t, d)
		if issued || tok != (setup.Token{}) {
			t.Errorf("the restarted console issued a token: %+v", tok)
		}
		assertUnknownRoute(t, restarted, post(t, restarted, "/api/v1/setup", setupBody(tok.Value, "eve@example.com")))
	})

	if n := d.count(t, `SELECT count(*) FROM users`); n != 1 {
		t.Errorf("%d users, want 1", n)
	}
}

// Each start of a console process issues a token. All of them work, as long as no
// administrator exists, so that the setup works behind a load balancer.
func TestSetupEndpoint_AcceptsTokenOfAnotherProcess(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	_, first, _ := startConsole(t, d)
	srv, _, _ := startConsole(t, d)
	if r := post(t, srv, "/api/v1/setup", setupBody(first.Value, "ada@example.com")); r.status != http.StatusCreated {
		t.Errorf("status = %d, body = %v; want 201", r.status, r.body)
	}
}
