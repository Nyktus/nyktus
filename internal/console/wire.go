// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package console

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/audit/auditapi"
	"nyktus.org/nyktus/internal/auth/password"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/auth/setup"
)

// Options configure the console.
type Options struct {
	Logger *slog.Logger
	DB     *pgxpool.Pool
	// Setup issues setup tokens and creates the first administrator.
	Setup *setup.Service
	// Hasher hashes and verifies passwords. One hasher serves the process, so
	// that its limit on concurrent hash operations bounds every path together.
	Hasher   *password.Hasher
	Sessions session.Config
	// Origin is the origin under which users reach the console.
	Origin         string
	TrustedProxies []netip.Prefix
}

// New wires the console and returns its HTTP handler. It computes the dummy
// password hash of the sign-in, so it takes as long as one password hash.
func New(ctx context.Context, o Options) (http.Handler, error) {
	sessions, err := session.NewService(ctx, o.DB, o.Hasher, o.Sessions)
	if err != nil {
		return nil, err
	}
	h := session.NewHandler(o.Logger, sessions)
	return NewHandler(Deps{
		Logger:         o.Logger,
		DB:             o.DB,
		Setup:          setup.NewHandler(o.Logger, o.Setup, o.Hasher),
		Authorizer:     session.NewAuthorizer(sessions),
		SignIn:         http.HandlerFunc(h.SignIn),
		Session:        http.HandlerFunc(h.Current),
		SignOut:        http.HandlerFunc(h.SignOut),
		AuditEntries:   auditapi.NewHandler(o.Logger, o.DB),
		Origin:         o.Origin,
		TrustedProxies: o.TrustedProxies,
	}), nil
}
