// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package httpx contains the HTTP building blocks shared by all server roles:
// server setup, routing with mandatory access declarations, middleware, request
// decoding and the JSON response format.
package httpx

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"nyktus.org/nyktus/internal/platform/request"
)

// ErrorResponse is the body of every error response.
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail describes an error to the client. Its message never contains internal
// details; those are logged under the same request ID.
type ErrorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

// Error codes used by the shared helpers.
const (
	CodeInvalidRequest   = "invalid_request"
	CodeUnauthenticated  = "unauthenticated"
	CodeForbidden        = "forbidden"
	CodeNotFound         = "not_found"
	CodeBodyTooLarge     = "body_too_large"
	CodeUnsupportedMedia = "unsupported_media_type"
	CodeInternal         = "internal_error"
	CodeUnavailable      = "unavailable"
)

// WriteJSON writes v as a JSON response with the given status. It panics if v cannot
// be encoded, because response types are defined in code and a failure is a
// programming error; the Recover middleware turns the panic into a 500 response.
//
// Responses are marked as not cacheable, because they can describe the inventory,
// and as not sniffable, so that a browser never renders them as HTML. These headers
// are set here rather than left to the reverse proxy, so that they also hold when
// the server is reached directly.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("httpx: encode %T: %v", v, err))
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	// A failed write means the client has gone away; there is nobody left to inform.
	_, _ = w.Write(append(body, '\n'))
}

// WriteError writes an error response that carries the request ID.
func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	WriteJSON(w, status, ErrorResponse{Error: ErrorDetail{
		Code:      code,
		Message:   message,
		RequestID: request.ID(r.Context()),
	}})
}

// ServerError logs err as the failure of op and writes a generic 500 response.
// The op names the flow and the failed step, for example "create honeytoken: insert".
func ServerError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, op string, err error) {
	logger.ErrorContext(r.Context(), "http: request failed", slog.String("op", op), slog.Any("error", err))
	WriteError(w, r, http.StatusInternalServerError, CodeInternal, "internal server error")
}

// Unavailable logs err as the failure of op and writes a generic 503 response.
func Unavailable(w http.ResponseWriter, r *http.Request, logger *slog.Logger, op string, err error) {
	logger.WarnContext(r.Context(), "http: service unavailable", slog.String("op", op), slog.Any("error", err))
	WriteError(w, r, http.StatusServiceUnavailable, CodeUnavailable, "service temporarily unavailable")
}
