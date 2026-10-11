// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type principalKey struct{}

// fakeAuthorizer returns err, or the request with a principal if err is nil. It
// records the access of every call.
type fakeAuthorizer struct {
	err       error
	noRequest bool
	calls     []Access
}

func (f *fakeAuthorizer) Authorize(r *http.Request, access Access) (*http.Request, error) {
	f.calls = append(f.calls, access)
	if f.err != nil {
		return nil, f.err
	}
	if f.noRequest {
		return nil, nil
	}
	return r.WithContext(context.WithValue(r.Context(), principalKey{}, "alice")), nil
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestRouter_DeniedRequestsNeverReachTheHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		authz      *fakeAuthorizer
		method     string
		wantStatus int
		wantCode   string
	}{
		{name: "unauthenticated", authz: &fakeAuthorizer{err: ErrUnauthenticated}, wantStatus: http.StatusUnauthorized, wantCode: CodeUnauthenticated},
		{name: "forbidden", authz: &fakeAuthorizer{err: ErrForbidden}, wantStatus: http.StatusForbidden, wantCode: CodeForbidden},
		{name: "wrapped forbidden", authz: &fakeAuthorizer{err: fmt.Errorf("role viewer: %w", ErrForbidden)}, wantStatus: http.StatusForbidden, wantCode: CodeForbidden},
		{name: "authorizer failure", authz: &fakeAuthorizer{err: errors.New("session store down")}, wantStatus: http.StatusInternalServerError, wantCode: CodeInternal},
		{name: "authorizer returns no request", authz: &fakeAuthorizer{noRequest: true}, wantStatus: http.StatusInternalServerError, wantCode: CodeInternal},
		// http.ServeMux answers HEAD with the GET route, so HEAD must be authorized too.
		// A real server sends no body for HEAD, so only status and headers are checked.
		{name: "head on a get route", authz: &fakeAuthorizer{err: ErrUnauthenticated}, method: http.MethodHead, wantStatus: http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rt := NewRouter(discardLogger(), tt.authz)
			rt.Handle(http.MethodGet, "/items/{id}", Require("items:read"), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("handler ran for a denied request")
			}))

			method := tt.method
			if method == "" {
				method = http.MethodGet
			}
			w := httptest.NewRecorder()
			rt.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), method, "/items/1", nil))

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if tt.wantCode != "" {
				if got := decodeErrorResponse(t, w); got.Error.Code != tt.wantCode {
					t.Errorf("code = %q, want %q", got.Error.Code, tt.wantCode)
				}
			}
			wantChallenge := ""
			if tt.wantStatus == http.StatusUnauthorized {
				wantChallenge = "Bearer"
			}
			if got := w.Header().Get("WWW-Authenticate"); got != wantChallenge {
				t.Errorf("WWW-Authenticate = %q, want %q", got, wantChallenge)
			}
			if strings.Contains(w.Body.String(), "session store down") {
				t.Errorf("response leaks the authorizer error: %s", w.Body.String())
			}
			if len(tt.authz.calls) != 1 || tt.authz.calls[0] != Require("items:read") {
				t.Errorf("authorizer calls = %v, want one call with items:read", tt.authz.calls)
			}
		})
	}
}

func TestRouter_AuthorizedRequestReachesHandlerWithPrincipal(t *testing.T) {
	t.Parallel()

	for name, access := range map[string]Access{
		"authenticated":              Authenticated,
		"permission":                 Require("users:read"),
		"authenticated session only": Authenticated.SessionOnly(),
		"permission session only":    Require("users:read").SessionOnly(),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			authz := &fakeAuthorizer{}
			rt := NewRouter(discardLogger(), authz)
			var principal any
			rt.Handle(http.MethodGet, "/me", access, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				principal = r.Context().Value(principalKey{})
				w.WriteHeader(http.StatusNoContent)
			}))

			w := httptest.NewRecorder()
			rt.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/me", nil))

			if w.Code != http.StatusNoContent {
				t.Errorf("status = %d, want 204", w.Code)
			}
			if principal != "alice" {
				t.Errorf("handler saw principal %v, want the one set by the authorizer", principal)
			}
			if len(authz.calls) != 1 || authz.calls[0] != access {
				t.Errorf("authorizer calls = %v, want one call with %v", authz.calls, access)
			}
		})
	}
}

func TestRouter_PublicRoutesBypassTheAuthorizer(t *testing.T) {
	t.Parallel()

	authz := &fakeAuthorizer{err: ErrUnauthenticated}
	rt := NewRouter(discardLogger(), authz)
	rt.Handle(http.MethodGet, "/livez", Public, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	w := httptest.NewRecorder()
	rt.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/livez", nil))

	if w.Code != http.StatusNoContent || len(authz.calls) != 0 {
		t.Errorf("status = %d, authorizer calls = %v; want 204 without authorization", w.Code, authz.calls)
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
			NewRouter(discardLogger(), nil).Handle(http.MethodGet, "/me", access, http.NotFoundHandler())
		})
	}
}

func TestNewRouter_RequiresLogger(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("NewRouter() accepted a nil logger")
		}
	}()
	NewRouter(nil, &fakeAuthorizer{})
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

// The restriction to sessions is enforced by the authorizer, which receives the
// access of the route. It does not change what the specification declares in
// x-access.
func TestAccess_SessionOnly(t *testing.T) {
	t.Parallel()

	for _, access := range []Access{Authenticated, Require("users:read")} {
		restricted := access.SessionOnly()
		if access.RequiresSession() || !restricted.RequiresSession() {
			t.Errorf("%v: RequiresSession() = %v before and %v after SessionOnly(), want false and true",
				access, access.RequiresSession(), restricted.RequiresSession())
		}
		if restricted.String() != access.String() || restricted.permission != access.permission {
			t.Errorf("SessionOnly() changed %v into %v", access, restricted)
		}
	}
	for _, access := range []Access{Public, {}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%v.SessionOnly() did not panic", access)
				}
			}()
			access.SessionOnly()
		}()
	}
}

func TestAccess_Permission(t *testing.T) {
	t.Parallel()

	for access, want := range map[Access]Permission{Public: "", Authenticated: "", {}: ""} {
		if perm, ok := access.Permission(); ok || perm != want {
			t.Errorf("%v.Permission() = %q, %v; want no permission", access, perm, ok)
		}
	}
	if perm, ok := Require("users:read").Permission(); !ok || perm != "users:read" {
		t.Errorf("Require(users:read).Permission() = %q, %v", perm, ok)
	}
}

func TestRouter_AnswersUncleanPathsAndConnectWithJSONNotFound(t *testing.T) {
	t.Parallel()

	tests := []struct{ method, target string }{
		{http.MethodGet, "//livez"},
		{http.MethodGet, "/./livez"},
		{http.MethodGet, "/x/../livez"},
		{http.MethodGet, "/items//1"},
		{http.MethodGet, "/items/1/"},
		{http.MethodConnect, "/livez"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.target, func(t *testing.T) {
			t.Parallel()

			authz := &fakeAuthorizer{}
			rt := NewRouter(discardLogger(), authz)
			handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("handler ran for a request that matches no clean route")
			})
			rt.Handle(http.MethodGet, "/livez", Public, handler)
			rt.Handle(http.MethodGet, "/items/{id}", Require("items:read"), handler)

			w := httptest.NewRecorder()
			rt.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), tt.method, tt.target, nil))

			if w.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404", w.Code)
			}
			if got := decodeErrorResponse(t, w); got.Error.Code != CodeNotFound {
				t.Errorf("code = %q, want %q", got.Error.Code, CodeNotFound)
			}
			if loc := w.Header().Get("Location"); loc != "" {
				t.Errorf("Location = %q, want no redirect", loc)
			}
			if len(authz.calls) != 0 {
				t.Errorf("authorizer calls = %v, want none", authz.calls)
			}
		})
	}
}

func TestRouter_RejectsPatternsWithoutOpenAPIEquivalent(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"/", "/items/", "/assets/{file...}", "/{$}", "items", "example.com/items",
		"/items//1", "/a/../b", "/items/{id}.json", "/items/{1id}",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Errorf("Handle() accepted path %q", path)
				}
			}()
			NewRouter(discardLogger(), nil).Handle(http.MethodGet, path, Public, http.NotFoundHandler())
		})
	}

	rt := NewRouter(discardLogger(), nil)
	for _, path := range []string{"/livez", "/items/{id}", "/api/v1/users/{user_id}/api_keys"} {
		rt.Handle(http.MethodGet, path, Public, http.NotFoundHandler())
	}
}
