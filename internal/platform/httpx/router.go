// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"fmt"
	"net/http"
	"slices"
)

// Access declares who may call a route. The zero value is invalid, so a route
// cannot be registered without an explicit decision.
type Access struct {
	public bool
}

// Public allows unauthenticated calls.
var Public = Access{public: true}

func (a Access) valid() bool { return a.public }

// String describes the access requirement.
func (a Access) String() string {
	if a.public {
		return "public"
	}
	return "undeclared"
}

// Route describes a registered endpoint and its access requirement.
type Route struct {
	Method string
	Path   string
	Access Access
}

// Router dispatches requests by method and path pattern and records every route
// together with its access requirement.
type Router struct {
	mux    *http.ServeMux
	routes []Route
}

// NewRouter returns a router without routes. Requests that match no route receive
// a JSON 404, also when only the method differs. This replaces the plain-text
// responses of http.ServeMux, which identify the server as written in Go, and its
// 405 responses, whose Allow header lists the methods of a route.
func NewRouter() *Router {
	mux := http.NewServeMux()
	mux.HandleFunc("/", notFound)
	return &Router{mux: mux}
}

func notFound(w http.ResponseWriter, r *http.Request) {
	WriteError(w, r, http.StatusNotFound, CodeNotFound, "not found")
}

// Handle registers h for method and path, using the pattern syntax of
// http.ServeMux. It panics if access is not declared: the process then stops at
// startup instead of serving a route without an authorization decision.
func (rt *Router) Handle(method, path string, access Access, h http.Handler) {
	if !access.valid() {
		panic(fmt.Sprintf("httpx: route %s %s has no access declaration", method, path))
	}
	rt.mux.Handle(method+" "+path, h)
	rt.routes = append(rt.routes, Route{Method: method, Path: path, Access: access})
}

// Routes returns all registered routes in registration order.
func (rt *Router) Routes() []Route {
	return slices.Clone(rt.routes)
}

// ServeHTTP dispatches the request to the matching route.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt.mux.ServeHTTP(w, r)
}
