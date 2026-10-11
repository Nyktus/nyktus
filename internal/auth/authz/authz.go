// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authz authenticates the requests of the console and decides whether
// their principal may call the route. It is the httpx.Authorizer of the console
// router, so every route that is not public passes through it before its
// handler runs.
package authz

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/platform/logging"
)

// Authorizer authenticates requests with the session cookie and checks the
// access of the route. It implements httpx.Authorizer.
type Authorizer struct {
	db       db.Querier
	sessions *session.Service
}

// New returns an Authorizer that resolves sessions with sessions and records
// denied requests in the audit log through d.
func New(d db.Querier, sessions *session.Service) *Authorizer {
	if d == nil || sessions == nil {
		panic("authz: authorizer needs a database and a session service")
	}
	return &Authorizer{db: d, sessions: sessions}
}

// Authorize implements httpx.Authorizer. A request denied for a missing
// permission is recorded in the audit log, at most once per user, permission and
// audit.RepeatWindow, so that a signed-in user cannot fill the log by repeating
// it. A request without valid credentials is not recorded, so that anonymous
// clients cannot fill the audit log either. The access log records both.
func (a *Authorizer) Authorize(r *http.Request, acc httpx.Access) (*http.Request, error) {
	c, err := r.Cookie(session.CookieName)
	if err != nil || c.Value == "" {
		return nil, httpx.ErrUnauthenticated
	}
	ctx := r.Context()
	sess, err := a.sessions.Authenticate(ctx, c.Value)
	if errors.Is(err, session.ErrNoSession) {
		return nil, httpx.ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	p := access.Principal{UserID: sess.User.ID, Role: sess.User.Role, Method: audit.AuthSession, SessionID: sess.ID}
	ctx = session.NewContext(ctx, sess)

	logging.AddToScope(ctx, slog.String("user_id", p.UserID), slog.String("auth_method", string(p.Method)))
	if err := a.check(ctx, p, acc); err != nil {
		return nil, err
	}
	return r.WithContext(access.WithPrincipal(ctx, p)), nil
}

// check decides whether p may call a route with the access acc. A route that
// admits only sessions rejects every other credential before its permission is
// checked; such a request is not recorded, because it lacks no permission that
// the audit log could name.
func (a *Authorizer) check(ctx context.Context, p access.Principal, acc httpx.Access) error {
	if acc.RequiresSession() && !p.HasSession() {
		return httpx.ErrForbidden
	}
	perm, ok := acc.Permission()
	if !ok || p.Allowed(perm) {
		return nil
	}
	err := audit.NewStore(a.db).RecordUnlessRepeated(ctx, audit.Entry{
		Action:  access.DeniedAction(perm),
		Outcome: audit.OutcomeDenied,
		Actor:   p.Actor(),
	}.WithRequest(ctx))
	if err != nil {
		return err
	}
	return httpx.ErrForbidden
}
