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

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/platform/apispec"
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

// TestRoutes_MatchSpecification keeps the router and the OpenAPI specification in
// sync. Every route, and the access it requires, is documented in the
// specification, so every change to the attack surface is visible in review.
func TestRoutes_MatchSpecification(t *testing.T) {
	t.Parallel()

	spec, err := apispec.Parse(api.OpenAPI())
	if err != nil {
		t.Fatalf("invalid specification: %v", err)
	}
	for _, problem := range spec.Compare(NewRouter(slog.New(slog.DiscardHandler), fakePinger{}).Routes()) {
		t.Error(problem)
	}
}
