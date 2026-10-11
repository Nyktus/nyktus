// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"nyktus.org/nyktus/internal/auth/apikey"
	"nyktus.org/nyktus/internal/platform/httpx"
)

// codeTooManyAPIKeys answers a new key beyond apikey.MaxPerUser.
const codeTooManyAPIKeys = "too_many_api_keys" //nolint:gosec // An error code, not a credential.

type apiKeysResponse struct {
	APIKeys []apikey.Response `json:"api_keys"`
}

// ListAPIKeys handles GET /api/v1/session/api-keys.
func (h *Handler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	p, ok := h.sessionPrincipal(w, r, "session: list API keys")
	if !ok {
		return
	}
	keys, err := h.svc.APIKeys(r.Context(), p)
	if err != nil {
		httpx.ServerError(w, r, h.logger, "session: list API keys", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, apiKeysResponse{APIKeys: apikey.Responses(keys)})
}

type createAPIKeyRequest struct {
	Name      string             `json:"name"`
	Scopes    []httpx.Permission `json:"scopes"`
	ExpiresAt time.Time          `json:"expires_at"`
	Password  string             `json:"password"`
}

// LogValue keeps the password out of logs.
func (createAPIKeyRequest) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

type createAPIKeyResponse struct {
	apikey.Response
	// Key is shown only in this response.
	Key string `json:"key"`
}

// CreateAPIKey handles POST /api/v1/session/api-keys. The fields are checked
// before the password, because the checks cost no hash.
func (h *Handler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	p, ok := h.sessionPrincipal(w, r, "session: create API key")
	if !ok {
		return
	}
	var req createAPIKeyRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	if _, err := apikey.ParseName(req.Name); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, "name: 1 to 64 printable characters without surrounding whitespace")
		return
	}
	if err := apikey.ValidateScopes(req.Scopes, p.Role); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, "scopes: distinct permissions that API keys may carry and your role grants")
		return
	}
	// The database checks the expiry against its own clock as well.
	if now := time.Now(); !req.ExpiresAt.After(now) || req.ExpiresAt.After(now.Add(apikey.MaxLifetime)) {
		writeInvalidExpiry(w, r)
		return
	}

	spec := apikey.Spec{Name: req.Name, Scopes: req.Scopes, ExpiresAt: req.ExpiresAt}
	k, key, err := h.svc.CreateAPIKey(r.Context(), p, req.Password, spec)
	var locked *LockedError
	switch {
	case errors.Is(err, ErrWrongPassword):
		httpx.WriteError(w, r, http.StatusForbidden, codeWrongPassword, "the password is wrong")
		return
	case errors.As(err, &locked):
		writeLocked(w, r, locked)
		return
	case errors.Is(err, ErrNoSession):
		writeNoSession(w, r)
		return
	case errors.Is(err, apikey.ErrInvalidExpiry):
		writeInvalidExpiry(w, r)
		return
	case errors.Is(err, apikey.ErrInvalidName), errors.Is(err, apikey.ErrInvalidScopes):
		// The database checks the fields as well, in case its rules and those
		// above ever differ.
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, err.Error())
		return
	case errors.Is(err, apikey.ErrTooManyKeys):
		httpx.WriteError(w, r, http.StatusConflict, codeTooManyAPIKeys, "revoke an API key before you create another one")
		return
	case err != nil:
		httpx.ServerError(w, r, h.logger, "session: create API key", err)
		return
	}
	h.logger.InfoContext(r.Context(), "session: API key created", slog.Any("api_key", k))
	httpx.WriteJSON(w, http.StatusCreated, createAPIKeyResponse{Response: k.Response(), Key: key})
}

func writeInvalidExpiry(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, "expires_at: a time in the future, at most 365 days away")
}

// RevokeAPIKey handles DELETE /api/v1/session/api-keys/{id}.
func (h *Handler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	p, ok := h.sessionPrincipal(w, r, "session: revoke API key")
	if !ok {
		return
	}
	err := h.svc.RevokeAPIKey(r.Context(), p, r.PathValue("id"))
	switch {
	case errors.Is(err, apikey.ErrNotFound):
		httpx.NotFound(w, r)
		return
	case err != nil:
		httpx.ServerError(w, r, h.logger, "session: revoke API key", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
