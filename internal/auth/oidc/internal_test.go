// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"nyktus.org/nyktus/internal/user"
)

// Outside development, the provider vouches for identities only over TLS: the
// client refuses plain HTTP, also for the endpoints that discovery names and
// for redirects.
func TestProvider_RefusesRequestsWithoutTLS(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	t.Cleanup(srv.Close)

	p := NewProvider(ProviderConfig{Issuer: srv.URL, ClientID: "c", RedirectURL: "https://nyktus.example.com/cb"},
		slog.New(slog.DiscardHandler))
	err := p.discover(t.Context())
	if err == nil || !strings.Contains(err.Error(), "without TLS") {
		t.Errorf("discover() error = %v, want a refusal of plain HTTP", err)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("%d requests reached the server, want none", n)
	}
	if _, err := p.endpoints(); !errors.Is(err, ErrUnavailable) {
		t.Errorf("endpoints() error = %v, want ErrUnavailable", err)
	}
}

func TestGroupsClaim(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string][]string{
		`["a", "b c"]`: {"a", "b c"},
		`"a"`:          {"a"},
		`[]`:           {},
		`null`:         nil,
		`42`:           nil,
		`[1, 2]`:       nil,
		`{"a": 1}`:     nil,
		``:             nil,
	} {
		if got := groupsClaim(json.RawMessage(raw)); !slices.Equal(got, want) {
			t.Errorf("groupsClaim(%s) = %q, want %q", raw, got, want)
		}
	}
}

func TestRole_HighestGroupWins(t *testing.T) {
	t.Parallel()

	s := &Service{groups: Groups{Admin: []string{"admins"}, User: []string{"users"}, Viewer: []string{"viewers"}}}
	for _, tc := range []struct {
		groups []string
		want   user.Role
		ok     bool
	}{
		{[]string{"viewers"}, user.RoleViewer, true},
		{[]string{"viewers", "users"}, user.RoleUser, true},
		{[]string{"users", "admins", "viewers"}, user.RoleAdmin, true},
		{[]string{"Admins", "other"}, "", false},
		{nil, "", false},
	} {
		if got, ok := s.role(tc.groups); got != tc.want || ok != tc.ok {
			t.Errorf("role(%q) = %q, %v; want %q, %v", tc.groups, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDisplayName(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("l", 120) + "@example.com"
	for _, tc := range []struct{ name, email, want string }{
		{"Jane Doe", "jane@example.com", "Jane Doe"},
		{"", "jane@example.com", "jane@example.com"},
		{" Jane", "jane@example.com", "jane@example.com"},
		{"Jane\u202eeoD", "jane@example.com", "jane@example.com"},
		{strings.Repeat("n", 101), "jane@example.com", "jane@example.com"},
		{"", long, strings.Repeat("l", 100)},
		{"", strings.Repeat("ä", 120) + "@example.com", strings.Repeat("ä", 100)},
	} {
		got := displayName(tc.name, tc.email)
		if got != tc.want {
			t.Errorf("displayName(%q, %q) = %q, want %q", tc.name, tc.email, got, tc.want)
		}
		if _, err := user.ParseDisplayName(got); err != nil || !utf8.ValidString(got) {
			t.Errorf("displayName(%q, %q) = %q, which is not a valid name", tc.name, tc.email, got)
		}
	}
}

// Only registered error codes reach the log; the rest is input of whoever
// sent the browser to the callback.
func TestErrorCode(t *testing.T) {
	t.Parallel()

	for code, want := range map[string]string{
		"access_denied":      "access_denied",
		"login_required":     "login_required",
		"Access_Denied":      "unregistered",
		"access_denied\nx=1": "unregistered",
		"":                   "unregistered",
	} {
		if got := errorCode(code); got != want {
			t.Errorf("errorCode(%q) = %q, want %q", code, got, want)
		}
	}
}
