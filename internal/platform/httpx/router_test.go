// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type principalKey struct{}

// fakeAuthorizer grants the permissions in granted to every request that carries
// an Authorization header, and records the permission of every call.
type fakeAuthorizer struct {
	granted map[Permission]bool
	calls   []Permission
}

func (f *fakeAuthorizer) Authorize(w http.ResponseWriter, r *http.Request, perm Permission) (*http.Request, bool) {
	f.calls = append(f.calls, perm)
	if r.Header.Get("Authorization") == "" {
		WriteError(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return nil, false
	}
	if perm != "" && !f.granted[perm] {
		WriteError(w, r, http.StatusForbidden, "forbidden", "permission denied")
		return nil, false
	}
	return r.WithContext(context.WithValue(r.Context(), principalKey{}, "alice")), true
}

func TestRouter_DeniedRequestsNeverReachTheHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		access     Access
		authorized bool
		wantStatus int
		wantPerm   Permission
	}{
		{name: "permission without credentials", access: Require("users:read"), wantStatus: http.StatusUnauthorized, wantPerm: "users:read"},
		{name: "permission not granted", access: Require("users:write"), authorized: true, wantStatus: http.StatusForbidden, wantPerm: "users:write"},
		{name: "authenticated without credentials", access: Authenticated, wantStatus: http.StatusUnauthorized, wantPerm: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authz := &fakeAuthorizer{granted: map[Permission]bool{"users:read": true}}
			rt := NewRouter(authz)
			rt.Handle(http.MethodGet, "/items/{id}", tt.access, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("handler ran for a denied request")
			}))

			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/items/1", nil)
			if tt.authorized {
				r.Header.Set("Authorization", "Bearer test")
			}
			w := httptest.NewRecorder()
			rt.ServeHTTP(w, r)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if len(authz.calls) != 1 || authz.calls[0] != tt.wantPerm {
				t.Errorf("authorizer calls = %q, want one call with %q", authz.calls, tt.wantPerm)
			}
		})
	}
}

func TestRouter_AuthorizedRequestReachesHandlerWithPrincipal(t *testing.T) {
	t.Parallel()

	for _, access := range []Access{Authenticated, Require("users:read")} {
		t.Run(access.String(), func(t *testing.T) {
			t.Parallel()

			rt := NewRouter(&fakeAuthorizer{granted: map[Permission]bool{"users:read": true}})
			var principal any
			rt.Handle(http.MethodGet, "/me", access, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				principal = r.Context().Value(principalKey{})
				w.WriteHeader(http.StatusNoContent)
			}))

			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/me", nil)
			r.Header.Set("Authorization", "Bearer test")
			w := httptest.NewRecorder()
			rt.ServeHTTP(w, r)

			if w.Code != http.StatusNoContent {
				t.Errorf("status = %d, want 204", w.Code)
			}
			if principal != "alice" {
				t.Errorf("handler saw principal %v, want the one set by the authorizer", principal)
			}
		})
	}
}

func TestRouter_PublicRoutesBypassTheAuthorizer(t *testing.T) {
	t.Parallel()

	authz := &fakeAuthorizer{}
	rt := NewRouter(authz)
	rt.Handle(http.MethodGet, "/livez", Public, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	w := httptest.NewRecorder()
	rt.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/livez", nil))

	if w.Code != http.StatusNoContent || len(authz.calls) != 0 {
		t.Errorf("status = %d, authorizer calls = %q; want 204 without authorization", w.Code, authz.calls)
	}
}

func TestRouter_RejectsProtectedRouteWithoutAuthorizer(t *testing.T) {
	t.Parallel()

	for _, access := range []Access{Authenticated, Require("users:read")} {
		t.Run(access.String(), func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Error("Handle() accepted a protected route on a router without authorizer")
				}
			}()
			NewRouter(nil).Handle(http.MethodGet, "/me", access, http.NotFoundHandler())
		})
	}
}

func TestRequire_RejectsMalformedPermissions(t *testing.T) {
	t.Parallel()

	for _, perm := range []Permission{"", "users", "users:", ":read", "Users:read", "users:read:all", "users read"} {
		t.Run(string(perm), func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Errorf("Require(%q) accepted a malformed permission", perm)
				}
			}()
			Require(perm)
		})
	}
}

func TestAccess_String(t *testing.T) {
	t.Parallel()

	for access, want := range map[Access]string{
		Public:                    "public",
		Authenticated:             "authenticated",
		Require("api_keys:write"): "api_keys:write",
		{}:                        "undeclared",
	} {
		if got := access.String(); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
}
