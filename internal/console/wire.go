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
	"nyktus.org/nyktus/internal/auth/account"
	"nyktus.org/nyktus/internal/auth/authz"
	"nyktus.org/nyktus/internal/auth/password"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/auth/setup"
	"nyktus.org/nyktus/internal/platform/secretbox"
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
	// Keys encrypt the secrets of second factors.
	Keys *secretbox.Keyring
	// ConsoleURL is the address under which users reach the console, such as
	// "https://nyktus.example.com". Requests that change state must come from
	// this origin, and activation and password reset links start with it.
	ConsoleURL     string
	TrustedProxies []netip.Prefix
}

// New wires the console and returns its HTTP handler. It computes the dummy
// password hash of the sign-in, so it takes as long as one password hash.
func New(ctx context.Context, o Options) (http.Handler, error) {
	sessions, err := session.NewService(ctx, o.DB, o.Hasher, o.Keys, o.Sessions)
	if err != nil {
		return nil, err
	}
	h := session.NewHandler(o.Logger, sessions)
	a := account.NewHandler(o.Logger, account.NewService(o.DB, o.ConsoleURL, o.Hasher), o.Hasher)
	return NewHandler(Deps{
		Logger:         o.Logger,
		DB:             o.DB,
		Setup:          setup.NewHandler(o.Logger, o.Setup, o.Hasher),
		Authorizer:     authz.New(o.DB, sessions),
		SignIn:         http.HandlerFunc(h.SignIn),
		Session:        http.HandlerFunc(h.Current),
		SignOut:        http.HandlerFunc(h.SignOut),
		ChangePassword: http.HandlerFunc(h.ChangePassword),
		SecondFactor: SecondFactor{
			CompleteSignIn:       http.HandlerFunc(h.CompleteSignIn),
			Begin:                http.HandlerFunc(h.BeginTOTP),
			Confirm:              http.HandlerFunc(h.ConfirmTOTP),
			ReplaceRecoveryCodes: http.HandlerFunc(h.ReplaceRecoveryCodes),
			Remove:               http.HandlerFunc(h.RemoveTOTP),
		},
		AuditEntries: auditapi.NewHandler(o.Logger, o.DB),
		Accounts: Accounts{
			List:           http.HandlerFunc(a.List),
			Get:            http.HandlerFunc(a.Get),
			Create:         http.HandlerFunc(a.Create),
			Update:         http.HandlerFunc(a.Update),
			Delete:         http.HandlerFunc(a.Delete),
			IssueLink:      http.HandlerFunc(a.IssueLink),
			Activate:       http.HandlerFunc(a.Activate),
			IssueResetLink: http.HandlerFunc(a.IssueResetLink),
			ResetPassword:  http.HandlerFunc(a.ResetPassword),
		},
		Origin:         o.ConsoleURL,
		TrustedProxies: o.TrustedProxies,
	}), nil
}
