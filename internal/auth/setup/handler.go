// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package setup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"nyktus.org/nyktus/internal/auth/password"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/user"
)

// maxBodyBytes bounds a setup request. Its fields are short, even with every
// character escaped in JSON.
const maxBodyBytes = 8 << 10

// service is what the handler needs from the setup. *Service implements it.
type service interface {
	Open(ctx context.Context) (bool, error)
	Valid(ctx context.Context, token string) (bool, error)
	Complete(ctx context.Context, token string, admin Admin) (user.User, error)
}

// passwordHasher validates and hashes a password. *password.Hasher implements it.
type passwordHasher interface {
	Hash(ctx context.Context, password string) (string, error)
}

type handler struct {
	logger *slog.Logger
	svc    service
	hasher passwordHasher
}

// NewHandler returns the handler that creates the first administrator. It panics
// if a dependency is missing.
//
// Once an administrator exists, it answers every request with the same response
// as a route that does not exist. While the setup is open, a well-formed request with an
// unknown, expired or used token receives the same answer. Fields are validated
// and the password is hashed only for a valid token, so that a caller without
// one learns no validation rules and cannot make the server do expensive work.
// A body that cannot be decoded is rejected before the token is known, so it
// reveals that the setup is still open; without a token, that is of no use. The
// response time is not equalized: the route is public and documented, and its
// database lookups only show what a malformed body shows as well.
func NewHandler(logger *slog.Logger, svc service, hasher passwordHasher) http.Handler {
	if logger == nil || svc == nil || hasher == nil {
		panic("setup: handler needs a logger, a service and a password hasher")
	}
	return &handler{logger: logger, svc: svc, hasher: hasher}
}

type request struct {
	Token       string `json:"token"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

// LogValue keeps the token, the password and the address out of logs.
func (request) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Before anything else, so that a closed setup answers every request, even a
	// malformed one, with the response of an unknown route.
	open, err := h.svc.Open(ctx)
	if err != nil {
		httpx.ServerError(w, r, h.logger, "setup: check for administrator", err)
		return
	}
	if !open {
		httpx.NotFound(w, r)
		return
	}

	var req request
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	valid, err := h.svc.Valid(ctx, req.Token)
	if err != nil {
		httpx.ServerError(w, r, h.logger, "setup: look up token", err)
		return
	}
	if !valid {
		httpx.NotFound(w, r)
		return
	}

	email, err := user.ParseEmail(req.Email)
	if err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest,
			"email must be a single address such as name@example.com")
		return
	}
	name, err := user.ParseDisplayName(req.DisplayName)
	if err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest,
			fmt.Sprintf("display_name must have 1 to %d printable characters without leading or trailing spaces", user.MaxDisplayNameLength))
		return
	}
	hash, err := h.hasher.Hash(ctx, req.Password)
	switch {
	case errors.Is(err, password.ErrTooShort), errors.Is(err, password.ErrTooLong), errors.Is(err, password.ErrInvalidUTF8):
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, err.Error())
		return
	case err != nil:
		httpx.ServerError(w, r, h.logger, "setup: hash password", err)
		return
	}

	created, err := h.svc.Complete(ctx, req.Token, Admin{Email: email, DisplayName: name, PasswordHash: hash})
	switch {
	case errors.Is(err, ErrClosed), errors.Is(err, ErrInvalidToken):
		// A concurrent request has completed the setup, or the token has expired
		// since it was checked.
		httpx.NotFound(w, r)
		return
	case errors.Is(err, user.ErrEmailTaken):
		// Only possible if an account without the role admin exists, for example
		// one created directly in the database. The caller holds a valid token.
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, "email is already in use")
		return
	case err != nil:
		httpx.ServerError(w, r, h.logger, "setup: create administrator", err)
		return
	}

	h.logger.InfoContext(ctx, "setup: first administrator created", slog.Any("user", created))
	httpx.WriteJSON(w, http.StatusCreated, created.Response())
}
