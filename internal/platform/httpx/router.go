// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
)

// Permission names an action on a resource in the form "resource:action", for
// example "users:write". Roles and API key scopes grant permissions.
type Permission string

var permissionFormat = regexp.MustCompile(`^[a-z][a-z_]*:[a-z][a-z_]*$`)

// Valid reports whether p has the form "resource:action".
func (p Permission) Valid() bool { return permissionFormat.MatchString(string(p)) }

type accessKind int

const (
	accessUndeclared accessKind = iota
	accessPublic
	accessAuthenticated
	accessPermission
)

// Access declares who may call a route. The zero value is invalid, so a route
// cannot be registered without an explicit decision.
type Access struct {
	kind       accessKind
	permission Permission
}

// Public allows unauthenticated calls.
var Public = Access{kind: accessPublic}

// Authenticated allows calls by every authenticated principal, regardless of its
// permissions. It is meant for routes that only concern the caller itself.
var Authenticated = Access{kind: accessAuthenticated}

// Require allows calls by authenticated principals that hold perm. It panics if
// perm is not of the form "resource:action".
func Require(perm Permission) Access {
	if !perm.Valid() {
		panic(fmt.Sprintf("httpx: invalid permission %q; expected resource:action", perm))
	}
	return Access{kind: accessPermission, permission: perm}
}

// String describes the access requirement: "public", "authenticated" or the
// required permission. The OpenAPI specification uses the same values.
func (a Access) String() string {
	switch a.kind {
	case accessPublic:
		return "public"
	case accessAuthenticated:
		return "authenticated"
	case accessPermission:
		return string(a.permission)
	default:
		return "undeclared"
	}
}

// Permission returns the permission that the access requires. ok is false for
// public and authenticated access, which require no permission.
func (a Access) Permission() (perm Permission, ok bool) {
	return a.permission, a.kind == accessPermission
}

// Errors returned by an Authorizer. The router answers them with 401 and 403.
var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrForbidden       = errors.New("forbidden")
)

// Authorizer authenticates requests and checks permissions for the router.
type Authorizer interface {
	// Authorize authenticates r and checks that the principal satisfies access,
	// which is never Public. On success it returns the request to pass on, which
	// carries the principal in its context. It returns ErrUnauthenticated if r
	// carries no valid credentials and ErrForbidden if the principal lacks the
	// permission; every other error is answered as a server error. The router writes
	// all error responses, so an Authorizer cannot leave a denied request unanswered.
	Authorize(r *http.Request, access Access) (*http.Request, error)
}

// Route describes a registered endpoint and its access requirement.
type Route struct {
	Method string
	Path   string
	Access Access
}

// Router dispatches requests by method and path pattern and records every route
// together with its access requirement. Routes that are not public pass through
// the Authorizer before their handler runs, so a handler never loads a resource for
// a caller that lacks the permission.
type Router struct {
	mux    *http.ServeMux
	logger *slog.Logger
	authz  Authorizer
	routes []Route
}

// NewRouter returns a router without routes. authz may be nil as long as only
// public routes are registered. logger receives authorization failures.
//
// Requests that match no route receive a JSON 404, also when only the method
// differs. This replaces the plain-text responses of http.ServeMux, which identify
// the server as written in Go, and its 405 responses, whose Allow header lists the
// methods of a route.
func NewRouter(logger *slog.Logger, authz Authorizer) *Router {
	mux := http.NewServeMux()
	mux.HandleFunc("/", notFound)
	return &Router{mux: mux, logger: logger, authz: authz}
}

func notFound(w http.ResponseWriter, r *http.Request) {
	WriteError(w, r, http.StatusNotFound, CodeNotFound, "not found")
}

// Handle registers h for method and path, using the pattern syntax of
// http.ServeMux. As in http.ServeMux, a GET route also answers HEAD, with the same
// access requirement. It panics if access is not declared, or if the route needs
// authorization and the router has no Authorizer: the process then stops at
// startup instead of serving a route without an enforced authorization decision.
func (rt *Router) Handle(method, path string, access Access, h http.Handler) {
	switch access.kind {
	case accessPublic:
	case accessAuthenticated, accessPermission:
		if rt.authz == nil {
			panic(fmt.Sprintf("httpx: route %s %s requires authorization, but the router has no authorizer", method, path))
		}
		h = rt.authorize(access, h)
	default:
		panic(fmt.Sprintf("httpx: route %s %s has no access declaration", method, path))
	}
	rt.mux.Handle(method+" "+path, h)
	rt.routes = append(rt.routes, Route{Method: method, Path: path, Access: access})
}

func (rt *Router) authorize(access Access, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorized, err := rt.authz.Authorize(r, access)
		switch {
		case errors.Is(err, ErrUnauthenticated):
			WriteError(w, r, http.StatusUnauthorized, CodeUnauthenticated, "authentication required")
		case errors.Is(err, ErrForbidden):
			WriteError(w, r, http.StatusForbidden, CodeForbidden, "permission denied")
		case err != nil:
			ServerError(w, r, rt.logger, "authorize", err)
		case authorized == nil:
			ServerError(w, r, rt.logger, "authorize", errors.New("authorizer returned no request"))
		default:
			next.ServeHTTP(w, authorized)
		}
	})
}

// Routes returns all registered routes in registration order.
func (rt *Router) Routes() []Route {
	return slices.Clone(rt.routes)
}

// ServeHTTP dispatches the request to the matching route.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt.mux.ServeHTTP(w, r)
}
