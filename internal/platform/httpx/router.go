// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	pathpkg "path"
	"regexp"
	"slices"
	"strings"
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
	// session restricts the route to principals that signed in with a session.
	session bool
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

// SessionOnly returns a copy of a that admits only principals who signed in with
// a session, never an API key. Routes that change how the account itself
// authenticates use it, so that a leaked key cannot take over the account. It
// panics for public access, which authenticates no one.
func (a Access) SessionOnly() Access {
	if a.kind != accessAuthenticated && a.kind != accessPermission {
		panic("httpx: only authenticated access can be restricted to sessions")
	}
	a.session = true
	return a
}

// RequiresSession reports whether a admits only principals who signed in with a
// session.
func (a Access) RequiresSession() bool { return a.session }

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
	// ErrSessionRequired means that the route admits only sessions and the
	// request authenticated otherwise, such as with an API key.
	ErrSessionRequired = errors.New("session required")
)

// Authorizer authenticates requests and checks permissions for the router.
type Authorizer interface {
	// Authorize authenticates r and checks that the principal satisfies access,
	// which is never Public, including its restriction to sessions. On success it returns the request to pass on, which
	// carries the principal in its context. It returns ErrUnauthenticated if r
	// carries no valid credentials and ErrForbidden if the principal lacks the
	// permission, or ErrSessionRequired if the route admits only sessions and
	// the request authenticated otherwise; every other error is answered as a
	// server error. The router writes
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
	// fallback answers GET and HEAD requests that match no route.
	fallback http.Handler
}

// NewRouter returns a router without routes. authz may be nil as long as only
// public routes are registered. logger receives unexpected authorizer errors; denied
// requests are recorded by the Authorizer, which knows the principal. NewRouter
// panics if logger is nil, so that a wiring mistake stops the process at startup
// instead of failing the first protected request.
//
// Requests that match no route receive a JSON 404, also when only the method
// differs. This replaces the plain-text responses of http.ServeMux, which identify
// the server as written in Go, and its 405 responses, whose Allow header lists the
// methods of a route.
func NewRouter(logger *slog.Logger, authz Authorizer) *Router {
	if logger == nil {
		panic("httpx: router needs a logger")
	}
	rt := &Router{mux: http.NewServeMux(), logger: logger, authz: authz}
	rt.mux.HandleFunc("/", rt.unmatched)
	return rt
}

func (rt *Router) unmatched(w http.ResponseWriter, r *http.Request) {
	if rt.fallback != nil && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		rt.fallback.ServeHTTP(w, r)
		return
	}
	NotFound(w, r)
}

// Fallback registers h for GET and HEAD requests that match no route, such as the
// pages of a single-page application, which the browser requests under paths that
// only its script knows. Every other request still receives the JSON 404. h must
// answer with NotFound for what it does not serve, such as unknown paths of the
// API, so that they keep the JSON 404.
//
// The fallback is public, and the caller says so, like for a route: it is reached
// without authentication, so it must never serve anything that is not meant for
// everyone. Fallback panics if access is not Public, if h is nil or if a fallback
// is already registered.
func (rt *Router) Fallback(access Access, h http.Handler) {
	if access.kind != accessPublic || h == nil || rt.fallback != nil {
		panic("httpx: the fallback must be public, non-nil and registered once")
	}
	rt.fallback = h
}

// NotFound writes the response to a request that matches no route. A handler that
// must not reveal that its route exists, such as a disabled endpoint, answers with
// it as well, so that its response is the same as for an unknown route.
func NotFound(w http.ResponseWriter, r *http.Request) {
	WriteError(w, r, http.StatusNotFound, CodeNotFound, "not found")
}

// Handle registers h for method and path. A GET route also answers HEAD, with the
// same access requirement, as in http.ServeMux.
//
// path consists of literal segments and {name} wildcards. The other pattern forms
// of http.ServeMux are rejected: subtree patterns with a trailing slash or a
// {name...} wildcard make the mux redirect requests before authorization runs,
// host patterns bypass the path, and none of them has an OpenAPI equivalent.
//
// Handle panics on an invalid path, if access is not declared, or if the route
// needs authorization and the router has no Authorizer: the process then stops at
// startup instead of serving a route without an enforced authorization decision.
func (rt *Router) Handle(method, path string, access Access, h http.Handler) {
	if err := validatePath(path); err != nil {
		panic(fmt.Sprintf("httpx: route %s %s: %v", method, path, err))
	}
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

var wildcardSegment = regexp.MustCompile(`^\{[A-Za-z_][A-Za-z0-9_]*\}$`)

func validatePath(path string) error {
	if !strings.HasPrefix(path, "/") || path == "/" || strings.HasSuffix(path, "/") || !canonical(path) {
		return errors.New("path must start with a slash, must not end with one and must be clean")
	}
	for segment := range strings.SplitSeq(path[1:], "/") {
		if strings.ContainsAny(segment, "{}") && !wildcardSegment.MatchString(segment) {
			return fmt.Errorf("segment %q must be a literal or a {name} wildcard", segment)
		}
	}
	return nil
}

// canonical reports whether p is a clean absolute path, as http.ServeMux expects.
// A trailing slash is kept, as the mux does.
func canonical(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	clean := pathpkg.Clean(p)
	if strings.HasSuffix(p, "/") && clean != "/" {
		clean += "/"
	}
	return clean == p
}

func (rt *Router) authorize(access Access, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorized, err := rt.authz.Authorize(r, access)
		switch {
		case errors.Is(err, ErrUnauthenticated):
			// RFC 9110 requires a challenge on every 401. Bearer is the scheme of API
			// keys; browser sessions ignore the header.
			w.Header().Set("WWW-Authenticate", "Bearer")
			WriteError(w, r, http.StatusUnauthorized, CodeUnauthenticated, "authentication required")
		case errors.Is(err, ErrForbidden):
			WriteError(w, r, http.StatusForbidden, CodeForbidden, "permission denied")
		case errors.Is(err, ErrSessionRequired):
			WriteError(w, r, http.StatusForbidden, CodeForbidden, "this request requires a signed-in session, not an API key")
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

// ServeHTTP dispatches the request to the matching route. http.ServeMux answers
// CONNECT requests and paths that are not clean, such as "/a//b" or "/a/../b",
// with redirects or plain-text responses of its own, before any route and its
// authorization run. Those responses identify net/http, so such requests receive
// the JSON 404 instead.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect || !canonical(r.URL.EscapedPath()) {
		NotFound(w, r)
		return
	}
	rt.mux.ServeHTTP(w, r)
}
