// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package console

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"nyktus.org/nyktus/internal/platform/httpx"
)

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

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

			h := NewHandler(slog.New(slog.DiscardHandler), fakePinger{err: tt.dbErr})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.path, nil))
			if w.Code != tt.status {
				t.Errorf("GET %s status = %d, want %d", tt.path, w.Code, tt.status)
			}
		})
	}
}

// TestRoutes_DeclareAccess lists every console route with its access requirement.
// A new route makes this test fail until it is added here, so that every change to
// the attack surface is visible in review.
func TestRoutes_DeclareAccess(t *testing.T) {
	t.Parallel()

	want := map[string]httpx.Access{
		"GET /livez":  httpx.Public,
		"GET /readyz": httpx.Public,
	}
	routes := NewRouter(slog.New(slog.DiscardHandler), fakePinger{}).Routes()
	if len(routes) != len(want) {
		t.Errorf("router has %d routes, want %d: %+v", len(routes), len(want), routes)
	}
	for _, r := range routes {
		key := r.Method + " " + r.Path
		access, ok := want[key]
		if !ok {
			t.Errorf("route %s is not listed in this test", key)
			continue
		}
		if r.Access != access {
			t.Errorf("route %s has access %v, want %v", key, r.Access, access)
		}
	}
}
