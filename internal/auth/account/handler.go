// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/auth/password"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/user"
)

// Error codes of the management of accounts. Each names a conflict with the
// state of the accounts that the client can resolve.
const (
	CodeEmailTaken      = "email_taken"
	CodeLastActiveAdmin = "last_active_admin"
	CodeOwnAccount      = "own_account"
	CodeInvalidState    = "invalid_state"
)

// defaultPageSize is the page size if the request names none.
const defaultPageSize = 50

// maxBodyBytes bounds the requests. Their fields are short, even with every
// character escaped in JSON.
const maxBodyBytes = 8 << 10

// PasswordHasher validates and hashes a password. *password.Hasher implements
// it.
type PasswordHasher interface {
	Hash(ctx context.Context, password string) (string, error)
}

// Handler serves the management of accounts and their activation. The routes
// of the management must require the permissions users:read and users:write;
// the activation is public.
type Handler struct {
	logger *slog.Logger
	svc    *Service
	hasher PasswordHasher
}

// NewHandler returns a Handler. It panics if a dependency is missing.
func NewHandler(logger *slog.Logger, svc *Service, hasher PasswordHasher) *Handler {
	if logger == nil || svc == nil || hasher == nil {
		panic("account: handler needs a logger, a service and a password hasher")
	}
	return &Handler{logger: logger, svc: svc, hasher: hasher}
}

type listResponse struct {
	Users      []user.Response `json:"users"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

type linkResponse struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

type createResponse struct {
	User       user.Response `json:"user"`
	Activation linkResponse  `json:"activation"`
}

// List serves GET /api/v1/users.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q, ok := httpx.DecodeListQuery(w, r, defaultPageSize, user.MaxPageSize)
	if !ok {
		return
	}
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var after *user.Cursor
	if q.After != nil {
		after = &user.Cursor{CreatedAt: q.After.Time, ID: q.After.ID}
	}
	users, next, err := h.svc.List(r.Context(), p, q.Limit, after)
	if err != nil {
		httpx.ServerError(w, r, h.logger, "account: list users", err)
		return
	}
	resp := listResponse{Users: make([]user.Response, 0, len(users))}
	for _, u := range users {
		resp.Users = append(resp.Users, u.Response())
	}
	if next != nil {
		resp.NextCursor = httpx.EncodeCursor(httpx.Cursor{Time: next.CreatedAt, ID: next.ID})
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// Get serves GET /api/v1/users/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	u, err := h.svc.Get(r.Context(), p, r.PathValue("id"))
	if err != nil {
		h.writeError(w, r, "account: get user", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u.Response())
}

type createRequest struct {
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Role        user.Role `json:"role"`
}

// Create serves POST /api/v1/users. The response contains the activation link,
// which no later response repeats.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var req createRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	email, err := user.ParseEmail(req.Email)
	if err != nil {
		invalid(w, r, "email must be a single address such as name@example.com")
		return
	}
	name, err := user.ParseDisplayName(req.DisplayName)
	if err != nil {
		invalid(w, r, displayNameRule)
		return
	}
	if !req.Role.Valid() {
		invalid(w, r, roleRule)
		return
	}
	created, link, err := h.svc.Create(r.Context(), p, NewAccount{Email: email, DisplayName: name, Role: req.Role})
	if err != nil {
		h.writeError(w, r, "account: create user", err)
		return
	}
	h.logger.InfoContext(r.Context(), "account: user created", slog.Any("user", created))
	httpx.WriteJSON(w, http.StatusCreated, createResponse{User: created.Response(), Activation: newLinkResponse(link)})
}

// field is a member of a request that may be left out but, if present, must
// not be null. A null would otherwise be indistinguishable from an absent
// member and silently change nothing.
type field[T any] struct {
	set   bool
	value T
}

var errNull = errors.New("null is not allowed")

func (f *field[T]) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return errNull
	}
	f.set = true
	return json.Unmarshal(b, &f.value)
}

func (f field[T]) ptr() *T {
	if !f.set {
		return nil
	}
	return &f.value
}

// updateRequest lists every field that a change may contain. Each field is
// validated on its own and has the same consequences as a dedicated operation
// would have, so the request is not a generic update.
type updateRequest struct {
	DisplayName field[string]      `json:"display_name"`
	Role        field[user.Role]   `json:"role"`
	Status      field[user.Status] `json:"status"`
}

// Update serves PATCH /api/v1/users/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var req updateRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	c := user.Change{DisplayName: req.DisplayName.ptr(), Role: req.Role.ptr(), Status: req.Status.ptr()}
	switch {
	case c.DisplayName == nil && c.Role == nil && c.Status == nil:
		invalid(w, r, "request must change display_name, role or status")
		return
	case c.DisplayName != nil && !validDisplayName(*c.DisplayName):
		invalid(w, r, displayNameRule)
		return
	case c.Role != nil && !c.Role.Valid():
		invalid(w, r, roleRule)
		return
	case c.Status != nil && *c.Status != user.StatusActive && *c.Status != user.StatusDeactivated:
		invalid(w, r, "status must be active or deactivated")
		return
	}
	u, err := h.svc.Update(r.Context(), p, r.PathValue("id"), c)
	if err != nil {
		h.writeError(w, r, "account: update user", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u.Response())
}

// Delete serves DELETE /api/v1/users/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	if err := h.svc.Delete(r.Context(), p, r.PathValue("id")); err != nil {
		h.writeError(w, r, "account: delete user", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// IssueLink serves POST /api/v1/users/{id}/activation-link.
func (h *Handler) IssueLink(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	link, err := h.svc.IssueLink(r.Context(), p, r.PathValue("id"))
	if err != nil {
		h.writeError(w, r, "account: issue activation link", err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, newLinkResponse(link))
}

type activateRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// LogValue keeps the token and the password out of logs.
func (activateRequest) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

// Activate serves POST /api/v1/activation.
//
// An unknown, expired or used token receives the same response as a route that
// does not exist, and is not recorded in the audit log, so that anonymous clients
// cannot fill it. The password is validated and hashed only for a valid token, so
// that a caller without one learns no validation rules and cannot make the server
// do expensive work.
func (h *Handler) Activate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req activateRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	valid, err := h.svc.Valid(ctx, req.Token)
	if err != nil {
		httpx.ServerError(w, r, h.logger, "account: look up activation token", err)
		return
	}
	if !valid {
		httpx.NotFound(w, r)
		return
	}
	hash, err := h.hasher.Hash(ctx, req.Password)
	switch {
	case errors.Is(err, password.ErrTooShort), errors.Is(err, password.ErrTooLong), errors.Is(err, password.ErrInvalidUTF8):
		invalid(w, r, err.Error())
		return
	case err != nil:
		httpx.ServerError(w, r, h.logger, "account: hash password", err)
		return
	}
	activated, err := h.svc.Activate(ctx, req.Token, hash)
	if errors.Is(err, ErrInvalidToken) {
		// The token has been used or has expired since it was checked.
		httpx.NotFound(w, r)
		return
	}
	if err != nil {
		httpx.ServerError(w, r, h.logger, "account: activate user", err)
		return
	}
	h.logger.InfoContext(ctx, "account: user activated", slog.Any("user", activated))
	httpx.WriteJSON(w, http.StatusOK, activated.Response())
}

var (
	displayNameRule = fmt.Sprintf("display_name must have 1 to %d printable characters without leading or trailing spaces", user.MaxDisplayNameLength)
	roleRule        = "role must be admin, editor or viewer"
)

func validDisplayName(s string) bool {
	_, err := user.ParseDisplayName(s)
	return err == nil
}

func invalid(w http.ResponseWriter, r *http.Request, message string) {
	httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, message)
}

// principal returns the principal that the authorizer attached to the request.
// Without one, the route was registered without authentication, which is a
// wiring mistake.
func (h *Handler) principal(w http.ResponseWriter, r *http.Request) (access.Principal, bool) {
	p, ok := access.PrincipalFrom(r.Context())
	if !ok {
		httpx.ServerError(w, r, h.logger, "account: read principal", errors.New("no principal in the request context"))
	}
	return p, ok
}

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, user.ErrNotFound):
		httpx.NotFound(w, r)
	case errors.Is(err, user.ErrEmailTaken):
		httpx.WriteError(w, r, http.StatusConflict, CodeEmailTaken, "email is already in use")
	case errors.Is(err, user.ErrLastActiveAdmin):
		httpx.WriteError(w, r, http.StatusConflict, CodeLastActiveAdmin, "at least one active administrator must remain")
	case errors.Is(err, ErrOwnAccount):
		httpx.WriteError(w, r, http.StatusConflict, CodeOwnAccount, "administrators cannot demote, deactivate or delete their own account")
	case errors.Is(err, user.ErrInvalidTransition):
		httpx.WriteError(w, r, http.StatusConflict, CodeInvalidState, "a pending account becomes active through its activation link")
	case errors.Is(err, ErrNotPending):
		httpx.WriteError(w, r, http.StatusConflict, CodeInvalidState, "only a pending account can receive an activation link")
	default:
		httpx.ServerError(w, r, h.logger, op, err)
	}
}

func newLinkResponse(l Link) linkResponse {
	return linkResponse(l)
}
