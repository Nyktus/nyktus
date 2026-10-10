// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"nyktus.org/nyktus/internal/platform/logging"
	"nyktus.org/nyktus/internal/platform/request"
)

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// Chain wraps h with mw. The first middleware is the outermost.
func Chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// RequestID assigns each request a random ID, returns it in the X-Request-ID header,
// stores it in the request context (see request.ID) and attaches it to every log
// record of the request. An X-Request-ID sent by the
// client is ignored, so that callers cannot forge or collide log correlation IDs.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := rand.Text()
		w.Header().Set("X-Request-ID", id)
		ctx := request.WithID(r.Context(), id)
		ctx = logging.WithAttrs(ctx, slog.String("request_id", id))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AccessLog writes one record per request. It logs the matched route pattern instead
// of the request path, so that values embedded in paths never reach the logs.
// The router must receive the same *http.Request that AccessLog passes on, which
// holds as long as no middleware between them replaces the request.
func AccessLog(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			logger.LogAttrs(r.Context(), slog.LevelInfo, "http: request",
				slog.String("method", r.Method),
				slog.String("route", r.Pattern),
				slog.Int("status", rec.Status()),
				slog.Duration("duration", time.Since(start)),
			)
		})
	}
}

// Recover turns a panic in a handler into a logged 500 response instead of a dropped
// connection. http.ErrAbortHandler is passed on, because it deliberately aborts the
// response. If the handler had already started the response, the panic is logged and
// the response aborted, so that the client cannot mistake a truncated body for a
// complete one.
func Recover(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &statusRecorder{ResponseWriter: w}
			defer handlePanic(rec, r, logger)
			next.ServeHTTP(rec, r)
		})
	}
}

// handlePanic must be deferred directly, because recover only stops a panic when it
// is called by the deferred function itself.
func handlePanic(rec *statusRecorder, r *http.Request, logger *slog.Logger) {
	v := recover()
	if v == nil {
		return
	}
	if v == http.ErrAbortHandler { //nolint:errorlint // recover returns the panic value itself, never a wrapped error.
		panic(v)
	}
	logger.ErrorContext(r.Context(), "http: handler panicked",
		slog.String("panic", fmt.Sprint(v)),
		slog.String("stack", string(debug.Stack())),
	)
	if rec.wroteHeader {
		panic(http.ErrAbortHandler)
	}
	WriteError(rec, r, http.StatusInternalServerError, CodeInternal, "internal server error")
}

// statusRecorder remembers the status code written by the wrapped handler.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(status int) {
	if !s.wroteHeader {
		s.status, s.wroteHeader = status, true
	}
	s.ResponseWriter.WriteHeader(status)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Status returns the written status code, or 200 if the handler wrote nothing.
func (s *statusRecorder) Status() int {
	if !s.wroteHeader {
		return http.StatusOK
	}
	return s.status
}
