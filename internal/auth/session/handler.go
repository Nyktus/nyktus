// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"nyktus.org/nyktus/internal/auth/password"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/user"
)

// CookieName names the session cookie. The __Host- prefix makes browsers accept
// the cookie only with Secure, Path=/ and without Domain, so that a page on
// another subdomain can neither set nor replace it.
const CookieName = "__Host-nyktus_session"

// maxBodyBytes bounds a sign-in request.
const maxBodyBytes = 8 << 10

// ChallengeCookieName names the cookie that carries the challenge of a sign-in
// that waits for its second factor. Like the session cookie, it is out of reach
// of scripts and of other subdomains.
const ChallengeCookieName = "__Host-nyktus_challenge"

// Error codes of the sign-in, the change of password and the second factor.
const (
	codeRejected         = "invalid_credentials"
	codeAccountLocked    = "account_locked"
	codeWrongPassword    = "wrong_password"
	codeInvalidChallenge = "invalid_challenge"
	codeInvalidCode      = "invalid_code"
	codeWrongCode        = "wrong_code"
	codeTOTPEnabled      = "totp_enabled"
	codeTOTPNotEnabled   = "totp_not_enabled"
	codeNoTOTPSetup      = "no_totp_setup"
	codeOIDCAccount      = "oidc_account"
)

type sessionKey struct{}

// NewContext returns a copy of ctx that carries the session sess, which
// authenticated the request.
func NewContext(ctx context.Context, sess Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, sess)
}

// FromContext returns the session that authenticated the request of ctx. ok is
// false if the request was authenticated otherwise, or not at all.
func FromContext(ctx context.Context) (sess Session, ok bool) {
	sess, ok = ctx.Value(sessionKey{}).(Session)
	return sess, ok
}

// Handler serves sign-in, the current session and sign-out.
type Handler struct {
	logger *slog.Logger
	svc    *Service
}

// NewHandler returns the handlers of the session routes.
func NewHandler(logger *slog.Logger, svc *Service) *Handler {
	if logger == nil || svc == nil {
		panic("session: handler needs a logger and a service")
	}
	return &Handler{logger: logger, svc: svc}
}

type signInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LogValue keeps the address and the password out of logs.
func (signInRequest) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

type sessionResponse struct {
	User          user.Response `json:"user"`
	IdleExpiresAt time.Time     `json:"idle_expires_at"`
	ExpiresAt     time.Time     `json:"expires_at"`
}

func newSessionResponse(s Session) sessionResponse {
	return sessionResponse{User: s.User.Response(), IdleExpiresAt: s.IdleExpiresAt, ExpiresAt: s.ExpiresAt}
}

// challengeResponse tells the client that the sign-in waits for the second
// factor. The challenge itself travels in a cookie.
type challengeResponse struct {
	SecondFactor string    `json:"second_factor"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// SignIn handles POST /api/v1/session. Every rejected sign-in, except one with
// the correct password for a locked account, receives the same status, headers
// and body. For an account with a second factor, the correct password yields
// 202 and a challenge cookie instead of a session.
func (h *Handler) SignIn(w http.ResponseWriter, r *http.Request) {
	var req signInRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	var previous string
	if c, err := r.Cookie(CookieName); err == nil {
		previous = c.Value
	}

	result, err := h.svc.SignIn(r.Context(), req.Email, req.Password, previous)
	var locked *LockedError
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		// RFC 9110 requires a challenge on every 401, as the router sends it.
		w.Header().Set("WWW-Authenticate", "Bearer")
		httpx.WriteError(w, r, http.StatusUnauthorized, codeRejected, "invalid email address or password")
		return
	case errors.As(err, &locked):
		writeLocked(w, r, locked)
		return
	case err != nil:
		httpx.ServerError(w, r, h.logger, "session: sign in", err)
		return
	}

	if c := result.Challenge; c != nil {
		setChallengeCookie(w, c.Token)
		httpx.WriteJSON(w, http.StatusAccepted, challengeResponse{SecondFactor: "totp", ExpiresAt: c.ExpiresAt})
		return
	}
	h.setCookie(w, result.Token)
	h.logger.InfoContext(r.Context(), "session: signed in", slog.Any("session", result.Session))
	httpx.WriteJSON(w, http.StatusOK, newSessionResponse(result.Session))
}

// writeOIDCAccount rejects a change that needs the password of an account of
// the identity provider, which has none. Its password and second factor are
// managed by the provider.
func writeOIDCAccount(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, http.StatusConflict, codeOIDCAccount,
		"the account signs in through the identity provider and has no password")
}

// SetCookie sets the session cookie of tok, for a session that another way of
// signing in started.
func (h *Handler) SetCookie(w http.ResponseWriter, tok string) {
	h.setCookie(w, tok)
}

func (h *Handler) setCookie(w http.ResponseWriter, tok string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    tok,
		Path:     "/",
		MaxAge:   int(h.svc.cfg.MaxAge.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func writeLocked(w http.ResponseWriter, r *http.Request, locked *LockedError) {
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(locked.RetryAfter.Seconds()))))
	httpx.WriteError(w, r, http.StatusForbidden, codeAccountLocked, "the account is locked after too many failed sign-ins; try again later")
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// LogValue keeps the passwords out of logs.
func (changePasswordRequest) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

// ChangePassword handles PUT /api/v1/session/password. The route admits only
// sessions, so that a leaked API key cannot take over the account. The response
// replaces the session cookie.
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	p, ok := h.sessionPrincipal(w, r, "session: change password")
	if !ok {
		return
	}
	var req changePasswordRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	// The new password is checked first, because the check costs no hash.
	if err := password.Validate(req.NewPassword); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, "new_password: "+err.Error())
		return
	}
	sess, tok, err := h.svc.ChangePassword(r.Context(), p, req.CurrentPassword, req.NewPassword)
	var locked *LockedError
	switch {
	case errors.Is(err, ErrWrongPassword):
		httpx.WriteError(w, r, http.StatusForbidden, codeWrongPassword, "the current password is wrong")
		return
	case errors.As(err, &locked):
		writeLocked(w, r, locked)
		return
	case errors.Is(err, ErrNoSession):
		writeNoSession(w, r)
		return
	case errors.Is(err, user.ErrOIDCAccount):
		writeOIDCAccount(w, r)
		return
	case err != nil:
		httpx.ServerError(w, r, h.logger, "session: change password", err)
		return
	}
	h.setCookie(w, tok)
	h.logger.InfoContext(r.Context(), "session: password changed", slog.Any("session", sess))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// Current handles GET /api/v1/session.
func (h *Handler) Current(w http.ResponseWriter, r *http.Request) {
	sess, ok := FromContext(r.Context())
	if !ok {
		httpx.ServerError(w, r, h.logger, "session: current", errors.New("no session in the request context"))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, newSessionResponse(sess))
}

// SignOut handles DELETE /api/v1/session.
func (h *Handler) SignOut(w http.ResponseWriter, r *http.Request) {
	p, ok := h.sessionPrincipal(w, r, "session: sign out")
	if !ok {
		return
	}
	if err := h.svc.SignOut(r.Context(), p); err != nil {
		httpx.ServerError(w, r, h.logger, "session: sign out", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
