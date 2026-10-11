// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package console

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/platform/apispec"
	"nyktus.org/nyktus/internal/platform/httpx"
)

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

// denyAll authenticates no request.
type denyAll struct{}

func (denyAll) Authorize(*http.Request, httpx.Access) (*http.Request, error) {
	return nil, httpx.ErrUnauthenticated
}

func deps(db Pinger) Deps {
	return Deps{
		Logger: slog.New(slog.DiscardHandler), DB: db, Setup: http.NotFoundHandler(),
		Authorizer: denyAll{}, SignIn: http.NotFoundHandler(), Session: http.NotFoundHandler(), SignOut: http.NotFoundHandler(),
		AuditEntries: http.NotFoundHandler(),
		Accounts: Accounts{
			List: http.NotFoundHandler(), Get: http.NotFoundHandler(), Create: http.NotFoundHandler(),
			Update: http.NotFoundHandler(), Delete: http.NotFoundHandler(), IssueLink: http.NotFoundHandler(),
			Activate: http.NotFoundHandler(),
		},
		Origin: "https://nyktus.example.com",
	}
}

func TestHealthEndpoints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		path   string
		dbErr  error
		status int
	}{
		{name: "live with database up", path: "/livez", status: http.StatusOK},
		{name: "live with database down", path: "/livez", dbErr: errors.New("down"), status: http.StatusOK},
		{name: "ready with database up", path: "/readyz", status: http.StatusOK},
		{name: "ready with database down", path: "/readyz", dbErr: errors.New("down"), status: http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := NewHandler(deps(fakePinger{err: tt.dbErr}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.path, nil))
			if w.Code != tt.status {
				t.Errorf("GET %s status = %d, want %d", tt.path, w.Code, tt.status)
			}
		})
	}
}

// TestRoutes_MatchSpecification keeps the router and the OpenAPI specification in
// sync. Every route, and the access it requires, is documented in the
// specification, so every change to the attack surface is visible in review.
func TestRoutes_MatchSpecification(t *testing.T) {
	t.Parallel()

	spec, err := apispec.Parse(api.OpenAPI())
	if err != nil {
		t.Fatalf("invalid specification: %v", err)
	}
	for _, problem := range spec.Compare(NewRouter(deps(fakePinger{})).Routes()) {
		t.Error(problem)
	}
}

// Requests that hash a password wait for a free hashing slot and must not wait
// longer than the deadline.
func TestHashingRoutes_HaveDeadline(t *testing.T) {
	t.Parallel()

	for path, set := range map[string]func(*Deps, http.Handler){
		"/api/v1/setup":      func(d *Deps, h http.Handler) { d.Setup = h },
		"/api/v1/session":    func(d *Deps, h http.Handler) { d.SignIn = h },
		"/api/v1/activation": func(d *Deps, h http.Handler) { d.Accounts.Activate = h },
	} {
		var deadline time.Time
		var ok bool
		d := deps(fakePinger{})
		set(&d, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			deadline, ok = r.Context().Deadline()
			w.WriteHeader(http.StatusNoContent)
		}))
		before := time.Now()
		NewHandler(d).ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, nil))
		if !ok || deadline.Before(before.Add(hashDeadline)) || deadline.After(time.Now().Add(hashDeadline)) {
			t.Errorf("POST %s: deadline = %v, %v; want %v after the request started", path, deadline, ok, hashDeadline)
		}
	}
}

// A route that requires a permission no role grants could never be used. The
// grants and the routes are maintained in two places, so they are compared.
func TestRoutes_RequireOnlyGrantedPermissions(t *testing.T) {
	t.Parallel()

	granted := access.Permissions()
	for _, route := range NewRouter(deps(fakePinger{})).Routes() {
		if perm, ok := route.Access.Permission(); ok && !slices.Contains(granted, perm) {
			t.Errorf("route %s %s requires %s, which no role grants", route.Method, route.Path, perm)
		}
	}
}
