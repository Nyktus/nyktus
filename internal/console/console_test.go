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
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

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
		ChangePassword: http.NotFoundHandler(), AuditEntries: http.NotFoundHandler(),
		SecondFactor: SecondFactor{
			CompleteSignIn: http.NotFoundHandler(), Begin: http.NotFoundHandler(), Confirm: http.NotFoundHandler(),
			ReplaceRecoveryCodes: http.NotFoundHandler(), Remove: http.NotFoundHandler(),
		},
		Accounts: Accounts{
			List: http.NotFoundHandler(), Get: http.NotFoundHandler(), Create: http.NotFoundHandler(),
			Update: http.NotFoundHandler(), Delete: http.NotFoundHandler(), IssueLink: http.NotFoundHandler(),
			Activate: http.NotFoundHandler(), IssueResetLink: http.NotFoundHandler(), ResetPassword: http.NotFoundHandler(),
		},
		APIKeys: APIKeys{List: http.NotFoundHandler(), Create: http.NotFoundHandler(), Revoke: http.NotFoundHandler()},
		Honeytokens: Honeytokens{
			List: http.NotFoundHandler(), Get: http.NotFoundHandler(), Create: http.NotFoundHandler(),
			Update: http.NotFoundHandler(), Delete: http.NotFoundHandler(),
		},
		Incidents: Incidents{List: http.NotFoundHandler(), Get: http.NotFoundHandler(), Update: http.NotFoundHandler()},
		Events:    Events{List: http.NotFoundHandler(), Get: http.NotFoundHandler()},
		OIDC:      OIDC{Authorize: http.NotFoundHandler(), Reauthenticate: http.NotFoundHandler(), Callback: http.NotFoundHandler()},
		Origin:    "https://nyktus.example.com",
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

// The session and how the account signs in, under /api/v1/session, and the API
// keys are managed only with a session, so that a leaked API key can neither
// end the session, take over the account nor issue itself a successor. The
// authorizer enforces the restriction that the route declares.
func TestSessionRoutes_AdmitOnlySessions(t *testing.T) {
	t.Parallel()

	under := func(path, prefix string) bool { return path == prefix || strings.HasPrefix(path, prefix+"/") }
	for _, route := range NewRouter(deps(fakePinger{})).Routes() {
		managed := under(route.Path, "/api/v1/session") || under(route.Path, "/api/v1/api-keys") ||
			route.Path == "/api/v1/oidc/reauthenticate"
		protected := route.Access != httpx.Public
		if want := managed && protected; route.Access.RequiresSession() != want {
			t.Errorf("route %s %s: RequiresSession() = %v, want %v", route.Method, route.Path, route.Access.RequiresSession(), want)
		}
	}
}

// The specification names the credentials of every operation: the session
// cookie always, and an API key only where a key can hold the access, that is,
// on routes that admit more than sessions and require no permission or one that
// keys may carry. Routes that admit only sessions document the 403 that keys
// receive.
func TestRoutes_AdmitAPIKeysAsSpecified(t *testing.T) {
	t.Parallel()

	spec, err := apispec.Parse(api.OpenAPI())
	if err != nil {
		t.Fatalf("invalid specification: %v", err)
	}
	ops := make(map[string]apispec.Operation, len(spec.Operations))
	for _, o := range spec.Operations {
		ops[o.Method+" "+o.Path] = o
	}
	keyScopes := access.KeyScopes()
	keys := 0
	for _, route := range NewRouter(deps(fakePinger{})).Routes() {
		o, ok := ops[route.Method+" "+route.Path]
		if !ok || route.Access == httpx.Public {
			continue
		}
		perm, hasPerm := route.Access.Permission()
		admitsKeys := !route.Access.RequiresSession() && (!hasPerm || slices.Contains(keyScopes, perm))
		want := []string{"sessionCookie"}
		if admitsKeys {
			want = []string{"bearerKey", "sessionCookie"}
			keys++
		}
		if !slices.Equal(o.Schemes, want) {
			t.Errorf("%s %s: security %v, want %v", route.Method, route.Path, o.Schemes, want)
		}
		if route.Access.RequiresSession() && !slices.Contains(o.Statuses, "403") {
			t.Errorf("%s %s admits only sessions, but does not document 403", route.Method, route.Path)
		}
	}
	if keys == 0 {
		t.Error("no route admits API keys")
	}
}

// The scopes that a new key may request are documented as an enumeration, which
// must list exactly the scopes that keys may carry.
func TestCreateAPIKeyRequest_ListsTheScopesKeysMayCarry(t *testing.T) {
	t.Parallel()

	var doc struct {
		Components struct {
			Schemas struct {
				CreateAPIKeyRequest struct {
					Properties struct {
						Scopes struct {
							Items struct {
								Enum []httpx.Permission `yaml:"enum"`
							} `yaml:"items"`
						} `yaml:"scopes"`
					} `yaml:"properties"`
				} `yaml:"CreateAPIKeyRequest"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(api.OpenAPI(), &doc); err != nil {
		t.Fatalf("parse specification: %v", err)
	}
	got := slices.Sorted(slices.Values(doc.Components.Schemas.CreateAPIKeyRequest.Properties.Scopes.Items.Enum))
	if want := slices.Sorted(slices.Values(access.KeyScopes())); !slices.Equal(got, want) {
		t.Errorf("documented scopes %v, want %v", got, want)
	}
}
