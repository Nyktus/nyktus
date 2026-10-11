// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc

import (
	"errors"
	"log/slog"
	"net/http"

	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/platform/httpx"
)

// CookieName names the cookie that binds a sign-in to the browser that started
// it. It is sent with SameSite=Lax, because the provider sends the browser back
// to the callback from another site, where a Strict cookie would stay behind.
// The __Host- prefix keeps other subdomains from setting it.
const CookieName = "__Host-nyktus_oidc"

// CallbackPath is the path of the callback. The provider must have registered
// it, behind the address of the console, as a redirect URI of the client.
const CallbackPath = "/api/v1/oidc/callback"

// cookieMaxAge matches the lifetime of a sign-in in the database.
const cookieMaxAge = 10 * 60

// Pages of the console that a sign-in ends on. The reason of a failure goes to
// the log and the audit log, never to the browser. A reauthentication returns
// to the page that started it, with reauthenticationFailed appended if it
// failed.
const (
	successPage            = "/"
	failurePage            = "/sign-in#error=oidc"
	reauthenticationFailed = "#error=reauthentication"
)

// codeNotOIDCAccount rejects a reauthentication of an account that confirms
// sensitive actions with its password.
const codeNotOIDCAccount = "not_oidc_account"

// CookieSetter sets the session cookie. *session.Handler implements it.
type CookieSetter interface {
	SetCookie(w http.ResponseWriter, tok string)
}

// Handler serves the routes of the sign-in through the provider.
type Handler struct {
	logger  *slog.Logger
	svc     *Service
	cookies CookieSetter
}

// NewHandler returns the handlers of the routes of the sign-in.
func NewHandler(logger *slog.Logger, svc *Service, cookies CookieSetter) *Handler {
	if logger == nil || svc == nil || cookies == nil {
		panic("oidc: handler needs a logger, a service and a session cookie setter")
	}
	return &Handler{logger: logger, svc: svc, cookies: cookies}
}

// Authorize handles GET /api/v1/oidc/authorize. It starts a sign-in and sends
// the browser to the provider.
//
// The browser comes from a page of the console, so it sends its session
// cookie, if any. That session ends when the sign-in completes.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	var previous string
	if c, err := r.Cookie(session.CookieName); err == nil {
		previous = c.Value
	}
	redirect, browser, err := h.svc.Begin(r.Context(), previous)
	switch {
	case errors.Is(err, ErrUnavailable):
		httpx.Unavailable(w, r, h.logger, "oidc: authorize", err)
		return
	case err != nil:
		httpx.ServerError(w, r, h.logger, "oidc: authorize", err)
		return
	}
	setCookie(w, browser, cookieMaxAge)
	w.Header().Set("Cache-Control", "no-store")
	// The authorization endpoint comes from the discovery of the configured
	// provider; nothing of the request enters the URL but the state that the
	// console generated.
	http.Redirect(w, r, redirect, http.StatusFound) //nolint:gosec // Not an open redirect, see above.
}

// Reauthenticate handles GET /api/v1/oidc/reauthenticate. It sends the browser
// of a signed-in user of the provider to the provider, which asks for the
// credentials again, so that the session may perform sensitive actions for a
// few minutes. The browser returns to the path return_to, or to the start
// page.
func (h *Handler) Reauthenticate(w http.ResponseWriter, r *http.Request) {
	sess, ok := session.FromContext(r.Context())
	if !ok {
		httpx.ServerError(w, r, h.logger, "oidc: reauthenticate", errors.New("no session in the request context"))
		return
	}
	if sess.User.Identity == nil {
		httpx.WriteError(w, r, http.StatusConflict, codeNotOIDCAccount,
			"the account confirms sensitive actions with its password, not through the identity provider")
		return
	}
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = successPage
	}
	if !ValidReturnTo(returnTo) {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest,
			"return_to must be a path of the console, such as /settings, without a fragment")
		return
	}
	redirect, browser, err := h.svc.BeginReauthentication(r.Context(), sess, returnTo)
	switch {
	case errors.Is(err, ErrUnavailable):
		httpx.Unavailable(w, r, h.logger, "oidc: reauthenticate", err)
		return
	case err != nil:
		httpx.ServerError(w, r, h.logger, "oidc: reauthenticate", err)
		return
	}
	setCookie(w, browser, cookieMaxAge)
	w.Header().Set("Cache-Control", "no-store")
	// The authorization endpoint comes from the discovery of the configured
	// provider; nothing of the request enters the URL but the state that the
	// console generated.
	http.Redirect(w, r, redirect, http.StatusFound) //nolint:gosec // Not an open redirect, see above.
}

// Callback handles GET /api/v1/oidc/callback, to which the provider sends the
// browser back. It starts a session and sends the browser to the console, or
// to the sign-in page with an error. A reauthentication returns to its page.
//
// The request is a GET that changes state, which the check of the origin does
// not cover. A forged request cannot sign a browser in to the account of the
// forger: the sign-in must have been started by the same browser, which holds
// the token of its cookie.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	// The cookie has served its purpose whatever the outcome.
	setCookie(w, "", -1)
	w.Header().Set("Cache-Control", "no-store")

	q := r.URL.Query()
	var browser string
	if c, err := r.Cookie(CookieName); err == nil {
		browser = c.Value
	}
	if e := q.Get("error"); e != "" {
		// The user declined, or the provider refused. The description comes
		// from the provider, but travels through the browser, so only the
		// registered code is logged.
		h.logger.InfoContext(r.Context(), "oidc: the identity provider returned an error", slog.String("error", errorCode(e)))
		h.fail(w, r, "")
		return
	}
	state, code := q.Get("state"), q.Get("code")
	if state == "" || code == "" || browser == "" {
		h.logger.InfoContext(r.Context(), "oidc: callback without state, code or cookie")
		h.fail(w, r, "")
		return
	}

	res, err := h.svc.Complete(r.Context(), state, browser, code)
	var rejected *RejectedError
	switch {
	case errors.As(err, &rejected):
		h.logger.WarnContext(r.Context(), "oidc: sign-in rejected", slog.Any("rejection", rejected))
		h.fail(w, r, res.ReturnTo)
		return
	case errors.Is(err, ErrInvalidSignIn):
		h.logger.InfoContext(r.Context(), "oidc: invalid sign-in", slog.Any("error", err))
		h.fail(w, r, res.ReturnTo)
		return
	case errors.Is(err, ErrUnavailable):
		h.logger.WarnContext(r.Context(), "oidc: sign-in while the identity provider is not discovered", slog.Any("error", err))
		h.fail(w, r, res.ReturnTo)
		return
	case err != nil:
		h.logger.ErrorContext(r.Context(), "http: request failed", slog.String("op", "oidc: callback"), slog.Any("error", err))
		h.fail(w, r, res.ReturnTo)
		return
	}
	if res.ReturnTo != "" {
		h.logger.InfoContext(r.Context(), "oidc: reauthenticated", slog.Any("session", res.Session))
		http.Redirect(w, r, res.ReturnTo, http.StatusSeeOther)
		return
	}
	h.cookies.SetCookie(w, res.Token)
	h.logger.InfoContext(r.Context(), "session: signed in", slog.Any("session", res.Session))
	http.Redirect(w, r, successPage, http.StatusSeeOther)
}

// fail sends the browser to the sign-in page, or back to returnTo with an
// error if a reauthentication failed.
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, returnTo string) {
	if returnTo != "" {
		http.Redirect(w, r, returnTo+reauthenticationFailed, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, failurePage, http.StatusSeeOther)
}

func setCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// errorCode returns the error code of an authorization response if it is one
// that RFC 6749 (section 4.1.2.1) or OpenID Connect Core 1.0 (section 3.1.2.6)
// registers. Anything else is reported as such, so that the log does not take
// arbitrary input.
func errorCode(code string) string {
	switch code {
	case "invalid_request", "unauthorized_client", "access_denied", "unsupported_response_type", "invalid_scope",
		"server_error", "temporarily_unavailable", "interaction_required", "login_required", "account_selection_required",
		"consent_required", "invalid_request_uri", "invalid_request_object", "request_not_supported",
		"request_uri_not_supported", "registration_not_supported":
		return code
	default:
		return "unregistered"
	}
}
