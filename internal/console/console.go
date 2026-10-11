// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package console serves the API and the web console.
package console

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"nyktus.org/nyktus/internal/platform/httpx"
)

const readinessTimeout = 2 * time.Second

// hashDeadline bounds requests that hash a password. They wait for a free hashing
// slot, which takes long only while the server is overloaded.
const hashDeadline = 10 * time.Second

// Pinger reports whether the database is reachable.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Deps are the dependencies of the console.
type Deps struct {
	Logger *slog.Logger
	DB     Pinger
	// Setup creates the first administrator.
	Setup http.Handler
	// Authorizer authenticates requests to routes that are not public.
	Authorizer httpx.Authorizer
	// SignIn, Session and SignOut serve the session of the caller, and
	// ChangePassword the password of its account.
	SignIn, Session, SignOut, ChangePassword http.Handler
	// SecondFactor completes sign-ins and manages the second factor.
	SecondFactor SecondFactor
	// AuditEntries lists the audit log.
	AuditEntries http.Handler
	// Accounts manages accounts and activates them.
	Accounts Accounts
	// Origin is the origin under which users reach the console, such as
	// "https://nyktus.example.com". Requests that change state must come from it.
	Origin string
	// TrustedProxies are the address ranges of reverse proxies whose
	// X-Forwarded-For header determines the client address.
	TrustedProxies []netip.Prefix
}

// Accounts are the handlers of the management and activation of accounts and
// of the reset of passwords.
type Accounts struct {
	List, Get, Create, Update, Delete, IssueLink, Activate, IssueResetLink, ResetPassword http.Handler
}

// SecondFactor are the handlers of the second step of a sign-in and of the
// management of the TOTP factor of the caller.
type SecondFactor struct {
	CompleteSignIn, Begin, Confirm, ReplaceRecoveryCodes, Remove http.Handler
}

func (f SecondFactor) complete() bool {
	return f.CompleteSignIn != nil && f.Begin != nil && f.Confirm != nil && f.ReplaceRecoveryCodes != nil && f.Remove != nil
}

func (a Accounts) complete() bool {
	return a.List != nil && a.Get != nil && a.Create != nil && a.Update != nil &&
		a.Delete != nil && a.IssueLink != nil && a.Activate != nil && a.IssueResetLink != nil && a.ResetPassword != nil
}

// NewRouter registers the console routes. It panics if a dependency is missing,
// so that a wiring mistake stops the process at startup.
func NewRouter(d Deps) *httpx.Router {
	if d.Logger == nil || d.DB == nil || d.Setup == nil || d.Authorizer == nil ||
		d.SignIn == nil || d.Session == nil || d.SignOut == nil || d.ChangePassword == nil || !d.SecondFactor.complete() || d.AuditEntries == nil || !d.Accounts.complete() {
		panic("console: router needs a logger, a database, an authorizer and the setup, session, audit and account handlers")
	}
	rt := httpx.NewRouter(d.Logger, d.Authorizer)
	rt.Handle(http.MethodGet, "/livez", httpx.Public, http.HandlerFunc(live))
	rt.Handle(http.MethodGet, "/readyz", httpx.Public, ready(d.Logger, d.DB))
	rt.Handle(http.MethodPost, "/api/v1/setup", httpx.Public, httpx.Deadline(hashDeadline)(d.Setup))
	rt.Handle(http.MethodPost, "/api/v1/session", httpx.Public, httpx.Deadline(hashDeadline)(d.SignIn))
	rt.Handle(http.MethodGet, "/api/v1/session", httpx.Authenticated, d.Session)
	rt.Handle(http.MethodDelete, "/api/v1/session", httpx.Authenticated, d.SignOut)
	rt.Handle(http.MethodPut, "/api/v1/session/password", httpx.Authenticated, httpx.Deadline(hashDeadline)(d.ChangePassword))
	rt.Handle(http.MethodPost, "/api/v1/session/second-factor", httpx.Public, d.SecondFactor.CompleteSignIn)
	rt.Handle(http.MethodPost, "/api/v1/session/totp", httpx.Authenticated, httpx.Deadline(hashDeadline)(d.SecondFactor.Begin))
	rt.Handle(http.MethodDelete, "/api/v1/session/totp", httpx.Authenticated, httpx.Deadline(hashDeadline)(d.SecondFactor.Remove))
	rt.Handle(http.MethodPost, "/api/v1/session/totp/confirmation", httpx.Authenticated, d.SecondFactor.Confirm)
	rt.Handle(http.MethodPost, "/api/v1/session/totp/recovery-codes", httpx.Authenticated,
		httpx.Deadline(hashDeadline)(d.SecondFactor.ReplaceRecoveryCodes))
	rt.Handle(http.MethodGet, "/api/v1/audit-entries", httpx.Require("audit:read"), d.AuditEntries)
	rt.Handle(http.MethodGet, "/api/v1/users", httpx.Require("users:read"), d.Accounts.List)
	rt.Handle(http.MethodPost, "/api/v1/users", httpx.Require("users:write"), d.Accounts.Create)
	rt.Handle(http.MethodGet, "/api/v1/users/{id}", httpx.Require("users:read"), d.Accounts.Get)
	rt.Handle(http.MethodPatch, "/api/v1/users/{id}", httpx.Require("users:write"), d.Accounts.Update)
	rt.Handle(http.MethodDelete, "/api/v1/users/{id}", httpx.Require("users:write"), d.Accounts.Delete)
	rt.Handle(http.MethodPost, "/api/v1/users/{id}/activation-link", httpx.Require("users:write"), d.Accounts.IssueLink)
	rt.Handle(http.MethodPost, "/api/v1/activation", httpx.Public, httpx.Deadline(hashDeadline)(d.Accounts.Activate))
	rt.Handle(http.MethodPost, "/api/v1/users/{id}/password-reset-link", httpx.Require("users:write"), d.Accounts.IssueResetLink)
	rt.Handle(http.MethodPost, "/api/v1/password-reset", httpx.Public, httpx.Deadline(hashDeadline)(d.Accounts.ResetPassword))
	return rt
}

// NewHandler returns the console HTTP handler with the shared middleware.
func NewHandler(d Deps) http.Handler {
	return httpx.Chain(NewRouter(d),
		httpx.RequestID,
		httpx.ClientIP(d.TrustedProxies),
		httpx.AccessLog(d.Logger),
		httpx.Recover(d.Logger),
		httpx.SameOrigin(d.Origin),
	)
}

type status struct {
	Status string `json:"status"`
}

// live reports that the process is running. It deliberately checks no dependencies,
// so that an orchestrator does not restart the process because the database is down.
func live(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, status{Status: "ok"})
}

// ready reports whether the console can serve requests.
func ready(logger *slog.Logger, db Pinger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
		defer cancel()
		if err := db.Ping(ctx); err != nil {
			httpx.Unavailable(w, r, logger, "readiness: database unreachable", err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, status{Status: "ok"})
	})
}
