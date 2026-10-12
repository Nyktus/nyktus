// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package apikeyapi serves the API keys of the team to administrators.
package apikeyapi

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/auth/apikey"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/platform/httpx"
)

// maxBodyBytes bounds a request to create a key.
const maxBodyBytes = 8 << 10

// Error codes of the creation of a key.
const (
	codeWrongPassword = "wrong_password"
	// codeReauthenticationRequired asks an administrator of the identity
	// provider, who has no password, to sign in there again.
	codeReauthenticationRequired = "reauthentication_required"
	codeAccountLocked            = "account_locked"
	codeTooManyAPIKeys           = "too_many_api_keys" //nolint:gosec // An error code, not a credential.
)

// Creator issues a key that an administrator confirms with their password.
// *session.Service implements it.
type Creator interface {
	CreateAPIKey(ctx context.Context, p access.Principal, password string, spec apikey.Spec) (apikey.Key, string, error)
}

// Handler serves the API keys.
type Handler struct {
	logger  *slog.Logger
	db      apikey.DB
	creator Creator
}

// NewHandler returns the handlers of the API keys.
func NewHandler(logger *slog.Logger, d apikey.DB, creator Creator) *Handler {
	if logger == nil || d == nil || creator == nil {
		panic("apikeyapi: handler needs a logger, a database and a creator")
	}
	return &Handler{logger: logger, db: d, creator: creator}
}

type listResponse struct {
	APIKeys []apikey.Response `json:"api_keys"`
}

// List handles GET /api/v1/api-keys.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	keys, err := apikey.NewStore(h.db).List(r.Context())
	if err != nil {
		httpx.ServerError(w, r, h.logger, "apikey: list", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, listResponse{APIKeys: apikey.Responses(keys)})
}

type createRequest struct {
	Name      string             `json:"name"`
	Scopes    []httpx.Permission `json:"scopes"`
	ExpiresAt time.Time          `json:"expires_at"`
	Password  string             `json:"password"`
}

// LogValue keeps the password out of logs.
func (createRequest) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

type createResponse struct {
	apikey.Response
	// Key is shown only in this response.
	Key string `json:"key"`
}

// Create handles POST /api/v1/api-keys. The fields are checked before the
// password, because the checks cost no hash.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, ok := access.PrincipalFrom(r.Context())
	if !ok || !p.HasSession() {
		httpx.ServerError(w, r, h.logger, "apikey: create", errors.New("no session principal in the request context"))
		return
	}
	var req createRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	if _, err := apikey.ParseName(req.Name); err != nil {
		writeInvalidName(w, r)
		return
	}
	if err := apikey.ValidateScopes(req.Scopes); err != nil {
		writeInvalidScopes(w, r)
		return
	}
	// The database checks the expiry against its own clock as well.
	if now := time.Now(); !req.ExpiresAt.After(now) || req.ExpiresAt.After(now.Add(apikey.MaxLifetime)) {
		writeInvalidExpiry(w, r)
		return
	}

	spec := apikey.Spec{Name: req.Name, Scopes: req.Scopes, ExpiresAt: req.ExpiresAt}
	k, key, err := h.creator.CreateAPIKey(r.Context(), p, req.Password, spec)
	var locked *session.LockedError
	switch {
	case errors.Is(err, session.ErrWrongPassword):
		httpx.WriteError(w, r, http.StatusForbidden, codeWrongPassword, "the password is wrong")
		return
	case errors.As(err, &locked):
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(locked.RetryAfter.Seconds()))))
		httpx.WriteError(w, r, http.StatusForbidden, codeAccountLocked, "the account is locked after too many failed sign-ins; try again later")
		return
	case errors.Is(err, session.ErrNoSession):
		w.Header().Set("WWW-Authenticate", "Bearer")
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.CodeUnauthenticated, "authentication required")
		return
	case errors.Is(err, session.ErrReauthenticationRequired):
		writeReauthenticationRequired(w, r)
		return
	// The database checks the fields as well, in case its rules and those above
	// ever differ.
	case errors.Is(err, apikey.ErrInvalidExpiry):
		writeInvalidExpiry(w, r)
		return
	case errors.Is(err, apikey.ErrInvalidName):
		writeInvalidName(w, r)
		return
	case errors.Is(err, apikey.ErrInvalidScopes):
		writeInvalidScopes(w, r)
		return
	case errors.Is(err, apikey.ErrTooManyKeys):
		httpx.WriteError(w, r, http.StatusConflict, codeTooManyAPIKeys, "revoke an API key before you create another one")
		return
	case err != nil:
		httpx.ServerError(w, r, h.logger, "apikey: create", err)
		return
	}
	h.logger.InfoContext(r.Context(), "apikey: created", slog.Any("api_key", k))
	httpx.WriteJSON(w, http.StatusCreated, createResponse{Response: k.Response(), Key: key})
}

func writeInvalidName(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, "name: 1 to 64 printable characters without surrounding whitespace")
}

func writeInvalidScopes(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, "scopes: distinct permissions that API keys may carry; honeytokens:write requires honeytokens:read")
}

func writeInvalidExpiry(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, "expires_at: a time in the future, at most three years away")
}

// Revoke handles DELETE /api/v1/api-keys/{id}.
func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	p, ok := access.PrincipalFrom(r.Context())
	if !ok {
		httpx.ServerError(w, r, h.logger, "apikey: revoke", errors.New("no principal in the request context"))
		return
	}
	err := apikey.Revoke(r.Context(), h.db, p.Actor(), r.PathValue("id"))
	switch {
	case errors.Is(err, apikey.ErrNotFound):
		httpx.NotFound(w, r)
		return
	case err != nil:
		httpx.ServerError(w, r, h.logger, "apikey: revoke", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func writeReauthenticationRequired(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, http.StatusForbidden, codeReauthenticationRequired,
		"sign in at the identity provider again through GET /api/v1/oidc/reauthenticate, then repeat the request within 5 minutes")
}
