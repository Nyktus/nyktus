// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package console serves the API and the web console.
package console

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"nyktus.org/nyktus/internal/platform/httpx"
)

const readinessTimeout = 2 * time.Second

// Pinger reports whether the database is reachable.
type Pinger interface {
	Ping(ctx context.Context) error
}

// NewRouter registers the console routes.
func NewRouter(logger *slog.Logger, db Pinger) *httpx.Router {
	rt := httpx.NewRouter()
	rt.Handle(http.MethodGet, "/livez", httpx.Public, http.HandlerFunc(live))
	rt.Handle(http.MethodGet, "/readyz", httpx.Public, ready(logger, db))
	return rt
}

// NewHandler returns the console HTTP handler with the shared middleware.
func NewHandler(logger *slog.Logger, db Pinger) http.Handler {
	return httpx.Chain(NewRouter(logger, db),
		httpx.RequestID,
		httpx.AccessLog(logger),
		httpx.Recover(logger),
	)
}

type status struct {
	Status string `json:"status"`
}

// live reports that the process is running. It deliberately checks no dependencies,
// so that an orchestrator does not restart the process because the database is down.
func live(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, status{Status: "ok"})
}

// ready reports whether the console can serve requests.
func ready(logger *slog.Logger, db Pinger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
		defer cancel()
		if err := db.Ping(ctx); err != nil {
			httpx.Unavailable(w, r, logger, "readiness: database unreachable", err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, status{Status: "ok"})
	})
}
