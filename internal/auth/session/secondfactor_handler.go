// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/auth/secondfactor"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/user"
)

// proofRequest carries a proof of the second factor: a code of the
// authenticator app or a recovery code.
type proofRequest struct {
	Code         string `json:"code"`
	RecoveryCode string `json:"recovery_code"`
}

// LogValue keeps the codes out of logs.
func (proofRequest) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

func (p proofRequest) proof() secondfactor.Proof {
	return secondfactor.Proof{Code: p.Code, RecoveryCode: p.RecoveryCode}
}

// secondFactorRequest carries the password and a proof of the second factor,
// for changes that need both.
type secondFactorRequest struct {
	Password string `json:"password"`
	proofRequest
}

// LogValue keeps the password and the codes out of logs.
func (secondFactorRequest) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

type passwordRequest struct {
	Password string `json:"password"`
}

// LogValue keeps the password out of logs.
func (passwordRequest) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

type codeRequest struct {
	Code string `json:"code"`
}

// LogValue keeps the code out of logs.
func (codeRequest) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

const proofRule = "exactly one of code and recovery_code is required"

// CompleteSignIn handles POST /api/v1/session/second-factor. The challenge
// comes from the cookie that the sign-in set. Without a valid challenge, the
// request is rejected without an audit entry, as any request without valid
// credentials.
func (h *Handler) CompleteSignIn(w http.ResponseWriter, r *http.Request) {
	var req proofRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	c, err := r.Cookie(ChallengeCookieName)
	if err != nil || c.Value == "" {
		writeInvalidChallenge(w, r)
		return
	}
	if !req.proof().Valid() {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, proofRule)
		return
	}
	var previous string
	if c, err := r.Cookie(CookieName); err == nil {
		previous = c.Value
	}

	sess, tok, err := h.svc.CompleteSignIn(r.Context(), c.Value, req.proof(), previous)
	var locked *LockedError
	switch {
	case errors.Is(err, ErrInvalidChallenge):
		writeInvalidChallenge(w, r)
		return
	case errors.Is(err, ErrWrongCode):
		w.Header().Set("WWW-Authenticate", "Bearer")
		httpx.WriteError(w, r, http.StatusUnauthorized, codeInvalidCode, "the code is wrong")
		return
	case errors.As(err, &locked):
		clearChallengeCookie(w)
		writeLocked(w, r, locked)
		return
	case err != nil:
		httpx.ServerError(w, r, h.logger, "session: complete sign-in", err)
		return
	}
	clearChallengeCookie(w)
	h.setCookie(w, tok)
	h.logger.InfoContext(r.Context(), "session: signed in", slog.Any("session", sess))
	httpx.WriteJSON(w, http.StatusOK, newSessionResponse(sess))
}

type totpSetupResponse struct {
	Secret    string    `json:"secret"`
	URI       string    `json:"uri"`
	ExpiresAt time.Time `json:"expires_at"`
}

// BeginTOTP handles POST /api/v1/session/totp.
func (h *Handler) BeginTOTP(w http.ResponseWriter, r *http.Request) {
	p, ok := h.sessionPrincipal(w, r, "session: begin TOTP setup")
	if !ok {
		return
	}
	var req passwordRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	setup, err := h.svc.BeginTOTP(r.Context(), p, req.Password)
	if h.writeSecondFactorError(w, r, "session: begin TOTP setup", err) {
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, totpSetupResponse(setup))
}

type recoveryCodesResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

// ConfirmTOTP handles POST /api/v1/session/totp/confirmation. The response
// replaces the session cookie.
func (h *Handler) ConfirmTOTP(w http.ResponseWriter, r *http.Request) {
	p, ok := h.sessionPrincipal(w, r, "session: confirm TOTP factor")
	if !ok {
		return
	}
	var req codeRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	codes, sess, tok, err := h.svc.ConfirmTOTP(r.Context(), p, req.Code)
	if h.writeSecondFactorError(w, r, "session: confirm TOTP factor", err) {
		return
	}
	h.setCookie(w, tok)
	h.logger.InfoContext(r.Context(), "session: TOTP factor enabled", slog.Any("session", sess))
	httpx.WriteJSON(w, http.StatusOK, recoveryCodesResponse{RecoveryCodes: codes})
}

// ReplaceRecoveryCodes handles POST /api/v1/session/totp/recovery-codes.
func (h *Handler) ReplaceRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	p, ok := h.sessionPrincipal(w, r, "session: replace recovery codes")
	if !ok {
		return
	}
	var req secondFactorRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	if !req.proof().Valid() {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, proofRule)
		return
	}
	codes, err := h.svc.ReplaceRecoveryCodes(r.Context(), p, req.Password, req.proof())
	if h.writeSecondFactorError(w, r, "session: replace recovery codes", err) {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, recoveryCodesResponse{RecoveryCodes: codes})
}

// RemoveTOTP handles DELETE /api/v1/session/totp. The response replaces the
// session cookie.
func (h *Handler) RemoveTOTP(w http.ResponseWriter, r *http.Request) {
	p, ok := h.sessionPrincipal(w, r, "session: remove TOTP factor")
	if !ok {
		return
	}
	var req secondFactorRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	if !req.proof().Valid() {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, proofRule)
		return
	}
	sess, tok, err := h.svc.RemoveTOTP(r.Context(), p, req.Password, req.proof())
	if h.writeSecondFactorError(w, r, "session: remove TOTP factor", err) {
		return
	}
	h.setCookie(w, tok)
	h.logger.InfoContext(r.Context(), "session: TOTP factor removed", slog.Any("session", sess))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// sessionPrincipal returns the principal of a request to a route that admits
// only sessions, so that a leaked API key cannot change how the account signs
// in. The authorizer enforces that; a principal without a session here means
// that the route was registered without the restriction.
func (h *Handler) sessionPrincipal(w http.ResponseWriter, r *http.Request, op string) (access.Principal, bool) {
	p, ok := access.PrincipalFrom(r.Context())
	if !ok || !p.HasSession() {
		httpx.ServerError(w, r, h.logger, op, errors.New("no session principal in the request context"))
		return access.Principal{}, false
	}
	return p, true
}

// writeSecondFactorError writes the response for an error of the management of
// the second factor and reports whether there was one.
func (h *Handler) writeSecondFactorError(w http.ResponseWriter, r *http.Request, op string, err error) bool {
	var locked *LockedError
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrWrongPassword):
		httpx.WriteError(w, r, http.StatusForbidden, codeWrongPassword, "the password is wrong")
	case errors.Is(err, ErrWrongCode):
		httpx.WriteError(w, r, http.StatusForbidden, codeWrongCode, "the code is wrong")
	case errors.As(err, &locked):
		writeLocked(w, r, locked)
	case errors.Is(err, ErrNoSession):
		writeNoSession(w, r)
	case errors.Is(err, user.ErrOIDCAccount):
		writeOIDCAccount(w, r)
	case errors.Is(err, secondfactor.ErrEnabled):
		httpx.WriteError(w, r, http.StatusConflict, codeTOTPEnabled, "a TOTP factor is already enabled; remove it first")
	case errors.Is(err, secondfactor.ErrNotEnabled):
		httpx.WriteError(w, r, http.StatusConflict, codeTOTPNotEnabled, "no TOTP factor is enabled")
	case errors.Is(err, secondfactor.ErrNoEnrollment):
		httpx.WriteError(w, r, http.StatusConflict, codeNoTOTPSetup, "no TOTP setup is in progress, or it expired; start it again")
	default:
		httpx.ServerError(w, r, h.logger, op, err)
	}
	return true
}

func writeNoSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	httpx.WriteError(w, r, http.StatusUnauthorized, httpx.CodeUnauthenticated, "authentication required")
}

func writeInvalidChallenge(w http.ResponseWriter, r *http.Request) {
	clearChallengeCookie(w)
	w.Header().Set("WWW-Authenticate", "Bearer")
	httpx.WriteError(w, r, http.StatusUnauthorized, codeInvalidChallenge, "the sign-in expired; sign in again")
}

// challengeLifetime is the lifetime of a challenge that the schema sets; a test
// keeps both equal. The cookie uses it rather than the expiry from the
// database, whose clock may differ from the clock of the console.
const challengeLifetime = 5 * time.Minute

func setChallengeCookie(w http.ResponseWriter, tok string) {
	http.SetCookie(w, &http.Cookie{
		Name:     ChallengeCookieName,
		Value:    tok,
		Path:     "/",
		MaxAge:   int(challengeLifetime.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearChallengeCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     ChallengeCookieName,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}
