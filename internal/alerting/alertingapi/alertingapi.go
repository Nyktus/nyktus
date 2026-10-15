// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package alertingapi serves the alert channels to administrators. The routes
// must require the permissions alert_channels:read and alert_channels:write,
// and the routes that create or change a channel must admit sessions only,
// because a change that redirects or stops alerts is confirmed with a password.
package alertingapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/alerting"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/platform/secretbox"
	"nyktus.org/nyktus/internal/platform/ssrf"
)

// maxBodyBytes bounds the requests: a URL of 2048 characters and a header of
// 1024, even with every character escaped in JSON, fit with room to spare.
const maxBodyBytes = 32 << 10

// Error codes of the channels.
const (
	codeTargetNotAllowed  = "target_not_allowed"
	codeNameTaken         = "name_taken"
	codeTooManyChannels   = "too_many_alert_channels"
	codeChannelEnabled    = "alert_channel_enabled"
	codeHeaderNotAllowed  = "header_not_allowed"
	headerNotAllowedRule  = "header is only allowed for a channel of the type webhook"
	targetNotAllowedRule  = "the target of url is not allowed: it is internal or does not resolve"
	channelEnabledMessage = "disable the alert channel before you delete it"
)

// Confirmer runs a change once the administrator of the session has confirmed
// it with their password. *session.Service implements it.
type Confirmer interface {
	Confirm(ctx context.Context, p access.Principal, password string, action audit.Action,
		change func(ctx context.Context, tx pgx.Tx) error) error
}

// URLChecker checks that a URL may be requested. *ssrf.Guard implements it.
type URLChecker interface {
	CheckURL(ctx context.Context, s string) (*url.URL, error)
}

// Handler serves the alert channels.
type Handler struct {
	logger    *slog.Logger
	db        alerting.DB
	keys      *secretbox.Keyring
	confirmer Confirmer
	urls      URLChecker
}

// NewHandler returns the handlers of the alert channels.
func NewHandler(logger *slog.Logger, d alerting.DB, keys *secretbox.Keyring, confirmer Confirmer, urls URLChecker) *Handler {
	if logger == nil || d == nil || keys == nil || confirmer == nil || urls == nil {
		panic("alertingapi: handler needs a logger, a database, keys, a confirmer and a URL checker")
	}
	return &Handler{logger: logger, db: d, keys: keys, confirmer: confirmer, urls: urls}
}

// response is the representation of a channel. Its URL and the value of its
// header are never part of it, also not in the response that creates it: the
// administrator entered them.
type response struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Type       alerting.Type `json:"type"`
	Enabled    bool          `json:"enabled"`
	Target     string        `json:"target"`
	HeaderName *string       `json:"header_name"`
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  time.Time     `json:"updated_at"`
}

func newResponse(c alerting.Channel) response {
	return response{
		ID: c.ID, Name: c.Name, Type: c.Type, Enabled: c.Enabled, Target: c.Target, HeaderName: c.HeaderName,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
}

type listResponse struct {
	AlertChannels []response `json:"alert_channels"`
}

// List handles GET /api/v1/alert-channels.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	list, err := alerting.NewStore(h.db, nil).List(r.Context())
	if err != nil {
		httpx.ServerError(w, r, h.logger, "alerting: list channels", err)
		return
	}
	resp := listResponse{AlertChannels: make([]response, 0, len(list))}
	for _, c := range list {
		resp.AlertChannels = append(resp.AlertChannels, newResponse(c))
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/alert-channels/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	c, err := alerting.NewStore(h.db, nil).Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeError(w, r, "alerting: get channel", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, newResponse(c))
}

// headerRequest is the header of a webhook.
type headerRequest struct {
	Name  string          `json:"name"`
	Value alerting.Secret `json:"value"`
}

type createRequest struct {
	Name     string                        `json:"name"`
	Type     alerting.Type                 `json:"type"`
	Enabled  httpx.Optional[bool]          `json:"enabled"`
	URL      alerting.Secret               `json:"url"`
	Header   httpx.Optional[headerRequest] `json:"header"`
	Password string                        `json:"password"`
}

// LogValue keeps the URL, the header and the password out of logs.
func (createRequest) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// Create handles POST /api/v1/alert-channels. The fields and the target are
// checked before the password, because the checks cost no hash.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, ok := h.sessionPrincipal(w, r, "alerting: create channel")
	if !ok {
		return
	}
	var req createRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	spec := alerting.Spec{
		Name:    req.Name,
		Type:    req.Type,
		Enabled: !req.Enabled.Set || req.Enabled.Value,
		URL:     req.URL,
	}
	if req.Header.Set {
		spec.Header = &alerting.Header{Name: req.Header.Value.Name, Value: req.Header.Value.Value}
	}
	if err := spec.Validate(); err != nil {
		h.writeError(w, r, "alerting: create channel", err)
		return
	}
	if !h.checkURL(w, r, req.URL) {
		return
	}

	var c alerting.Channel
	err := h.confirmer.Confirm(r.Context(), p, req.Password, audit.ActionAlertChannelCreate, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		c, err = alerting.Create(ctx, tx, h.keys, p.Actor(), spec)
		return err
	})
	if session.WriteConfirmationError(w, r, err) {
		return
	}
	if err != nil {
		h.writeError(w, r, "alerting: create channel", err)
		return
	}
	h.logger.InfoContext(r.Context(), "alerting: channel created", slog.Any("channel", c))
	httpx.WriteJSON(w, http.StatusCreated, newResponse(c))
}

// updateRequest lists every field that a change may contain. The type is not
// among them: the URL of one type is no URL of another.
type updateRequest struct {
	Name     httpx.Optional[string]          `json:"name"`
	Enabled  httpx.Optional[bool]            `json:"enabled"`
	URL      httpx.Optional[alerting.Secret] `json:"url"`
	Header   httpx.Nullable[headerRequest]   `json:"header"`
	Password httpx.Optional[string]          `json:"password"`
}

// LogValue keeps the URL, the header and the password out of logs.
func (updateRequest) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// Update handles PATCH /api/v1/alert-channels/{id}. Every change other than a
// new name must be confirmed with the password of the administrator.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p, ok := h.sessionPrincipal(w, r, "alerting: update channel")
	if !ok {
		return
	}
	var req updateRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	c := alerting.Change{Name: req.Name.Ptr(), Enabled: req.Enabled.Ptr(), URL: req.URL.Ptr()}
	switch {
	case req.Header.Null:
		c.RemoveHeader = true
	case req.Header.Set:
		c.Header = &alerting.Header{Name: req.Header.Value.Name, Value: req.Header.Value.Value}
	}
	if c.IsEmpty() {
		invalid(w, r, "request must change name, enabled, url or header")
		return
	}
	if err := c.Validate(); err != nil {
		h.writeError(w, r, "alerting: update channel", err)
		return
	}
	if c.URL != nil && !h.checkURL(w, r, *c.URL) {
		return
	}

	id := r.PathValue("id")
	var ch alerting.Channel
	change := func(ctx context.Context, tx pgx.Tx) error {
		var err error
		ch, err = alerting.Update(ctx, tx, h.keys, p.Actor(), id, c)
		return err
	}
	var err error
	if c.NeedsConfirmation() {
		// A missing password is a wrong one for an account with a password;
		// an administrator of the identity provider has none and confirms
		// there.
		err = h.confirmer.Confirm(r.Context(), p, req.Password.Value, audit.ActionAlertChannelUpdate, change)
		if session.WriteConfirmationError(w, r, err) {
			return
		}
	} else {
		err = inTx(r.Context(), h.db, change)
	}
	if err != nil {
		h.writeError(w, r, "alerting: update channel", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, newResponse(ch))
}

// Delete handles DELETE /api/v1/alert-channels/{id}. Only a disabled channel
// can be deleted, because disabling is the change that stops alerts, and it is
// confirmed with a password.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p, ok := access.PrincipalFrom(r.Context())
	if !ok {
		httpx.ServerError(w, r, h.logger, "alerting: delete channel", errors.New("no principal in the request context"))
		return
	}
	if err := alerting.Delete(r.Context(), h.db, p.Actor(), r.PathValue("id")); err != nil {
		h.writeError(w, r, "alerting: delete channel", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// inTx runs change in a transaction of d, for a change that needs no
// confirmation, with the same signature as a confirmed change.
func inTx(ctx context.Context, d alerting.DB, change func(ctx context.Context, tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error { return change(ctx, tx) })
}

// checkURL checks the target of u with the SSRF guard and writes the response
// if it is not allowed. The response does not tell an internal target from one
// that does not resolve.
func (h *Handler) checkURL(w http.ResponseWriter, r *http.Request, u alerting.Secret) bool {
	_, err := h.urls.CheckURL(r.Context(), string(u))
	switch {
	case err == nil:
		return true
	case errors.Is(err, ssrf.ErrInvalidURL):
		invalid(w, r, urlRule)
	case errors.Is(err, ssrf.ErrBlocked):
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, codeTargetNotAllowed, targetNotAllowedRule)
	default:
		httpx.ServerError(w, r, h.logger, "alerting: check URL", err)
	}
	return false
}

// sessionPrincipal returns the principal of the session that the authorizer
// attached to the request. Without one, the route was registered without the
// restriction to sessions, which is a wiring mistake.
func (h *Handler) sessionPrincipal(w http.ResponseWriter, r *http.Request, op string) (access.Principal, bool) {
	p, ok := access.PrincipalFrom(r.Context())
	if !ok || !p.HasSession() {
		httpx.ServerError(w, r, h.logger, op, errors.New("no session principal in the request context"))
		return access.Principal{}, false
	}
	return p, true
}

// Rules of the fields, as the error responses state them.
var (
	typeRule        = "type must be " + strings.Join(typeNames(), ", ")
	nameRule        = fmt.Sprintf("name must have 1 to %d printable characters without leading or trailing spaces", alerting.MaxNameLength)
	urlRule         = fmt.Sprintf("url must be an https URL of at most %d printable ASCII characters with a host and without user information or fragment", alerting.MaxURLLength)
	headerNameRule  = fmt.Sprintf("header.name must be a header name of 1 to %d characters, other than Host, Content-*, Transfer-Encoding, Connection, Keep-Alive, TE, Trailer, Upgrade, Expect or Proxy-*", alerting.MaxHeaderNameLength)
	headerValueRule = fmt.Sprintf("header.value must have 1 to %d printable ASCII characters without leading or trailing spaces", alerting.MaxHeaderValueLength)
)

func typeNames() []string {
	names := make([]string, len(alerting.Types))
	for i, t := range alerting.Types {
		names[i] = string(t)
	}
	return names
}

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, alerting.ErrNotFound):
		httpx.NotFound(w, r)
	case errors.Is(err, alerting.ErrInvalidType):
		invalid(w, r, typeRule)
	case errors.Is(err, alerting.ErrInvalidName):
		invalid(w, r, nameRule)
	case errors.Is(err, alerting.ErrInvalidURL):
		invalid(w, r, urlRule)
	case errors.Is(err, alerting.ErrInvalidHeaderName):
		invalid(w, r, headerNameRule)
	case errors.Is(err, alerting.ErrInvalidHeaderValue):
		invalid(w, r, headerValueRule)
	case errors.Is(err, alerting.ErrHeaderNotAllowed):
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, codeHeaderNotAllowed, headerNotAllowedRule)
	case errors.Is(err, alerting.ErrNameTaken):
		httpx.WriteError(w, r, http.StatusConflict, codeNameTaken, "another alert channel has this name")
	case errors.Is(err, alerting.ErrTooManyChannels):
		httpx.WriteError(w, r, http.StatusConflict, codeTooManyChannels,
			fmt.Sprintf("an installation has at most %d alert channels; delete one first", alerting.MaxChannels))
	case errors.Is(err, alerting.ErrEnabled):
		httpx.WriteError(w, r, http.StatusConflict, codeChannelEnabled, channelEnabledMessage)
	default:
		httpx.ServerError(w, r, h.logger, op, err)
	}
}

func invalid(w http.ResponseWriter, r *http.Request, message string) {
	httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, message)
}
