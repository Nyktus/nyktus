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
	"strings"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/auth/apikey"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/platform/logging"
)

// Authorizer authenticates requests with an API key or the session cookie and
// checks the access of the route. It implements httpx.Authorizer.
type Authorizer struct {
	db       db.Querier
	sessions *session.Service
}

// New returns an Authorizer that resolves sessions with sessions, and API keys
// and denied requests through d.
func New(d db.Querier, sessions *session.Service) *Authorizer {
	if d == nil || sessions == nil {
		panic("authz: authorizer needs a database and a session service")
	}
	return &Authorizer{db: d, sessions: sessions}
}

// Authorize implements httpx.Authorizer. A request denied for a missing
// permission is recorded in the audit log, at most once per user, API key,
// permission and audit.RepeatWindow, so that a signed-in user cannot fill the
// log by repeating it. A request without valid credentials is not recorded, so that anonymous
// clients cannot fill the audit log either. The access log records both.
func (a *Authorizer) Authorize(r *http.Request, acc httpx.Access) (*http.Request, error) {
	ctx := r.Context()
	var (
		p   access.Principal
		err error
	)
	// A request with an API key authenticates with it alone. The session cookie
	// is then ignored, so that a request has one principal. Other credentials,
	// such as Basic credentials or the bearer token of an identity-aware proxy
	// in front of the console, are not meant for it and are ignored.
	if key, ok := bearerToken(r.Header.Values("Authorization")); ok {
		p, err = a.authenticateKey(ctx, key)
	} else {
		p, ctx, err = a.authenticateSession(ctx, r)
	}
	if err != nil {
		return nil, err
	}

	attrs := []slog.Attr{slog.String("user_id", p.UserID), slog.String("auth_method", string(p.Method))}
	if p.APIKeyID != "" {
		attrs = append(attrs, slog.String("api_key_id", p.APIKeyID))
	}
	logging.AddToScope(ctx, attrs...)
	if err := a.check(ctx, p, acc); err != nil {
		return nil, err
	}
	return r.WithContext(access.WithPrincipal(ctx, p)), nil
}

func (a *Authorizer) authenticateSession(ctx context.Context, r *http.Request) (access.Principal, context.Context, error) {
	c, err := r.Cookie(session.CookieName)
	if err != nil || c.Value == "" {
		return access.Principal{}, ctx, httpx.ErrUnauthenticated
	}
	sess, err := a.sessions.Authenticate(ctx, c.Value)
	if errors.Is(err, session.ErrNoSession) {
		return access.Principal{}, ctx, httpx.ErrUnauthenticated
	}
	if err != nil {
		return access.Principal{}, ctx, err
	}
	p := access.Principal{UserID: sess.User.ID, Role: sess.User.Role, Method: audit.AuthSession, SessionID: sess.ID}
	return p, session.NewContext(ctx, sess), nil
}

// bearerToken returns the API key among the values of the Authorization
// header: a bearer token (RFC 6750) with the prefix of a key. ok reports
// whether there is one; key is empty if the header is ambiguous, with more than
// one value.
func bearerToken(values []string) (key string, ok bool) {
	for _, v := range values {
		scheme, token, _ := strings.Cut(v, " ")
		token = strings.TrimLeft(token, " ")
		if strings.EqualFold(scheme, "Bearer") && strings.HasPrefix(token, apikey.Prefix) {
			ok = true
			key = token
		}
	}
	if len(values) != 1 {
		key = ""
	}
	return key, ok
}

// authenticateKey authenticates the API key key. Every failure is the same
// ErrUnauthenticated, without an audit entry.
func (a *Authorizer) authenticateKey(ctx context.Context, key string) (access.Principal, error) {
	if key == "" {
		return access.Principal{}, httpx.ErrUnauthenticated
	}
	k, u, err := apikey.NewStore(a.db).Authenticate(ctx, key)
	if errors.Is(err, apikey.ErrInvalidKey) {
		return access.Principal{}, httpx.ErrUnauthenticated
	}
	if err != nil {
		return access.Principal{}, err
	}
	return access.Principal{UserID: u.ID, Role: u.Role, Method: audit.AuthAPIKey, APIKeyID: k.ID, Scopes: k.Scopes}, nil
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
