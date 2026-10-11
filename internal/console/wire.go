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
	"nyktus.org/nyktus/internal/auth/apikey/apikeyapi"
	"nyktus.org/nyktus/internal/auth/authz"
	"nyktus.org/nyktus/internal/auth/oidc"
	"nyktus.org/nyktus/internal/auth/password"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/auth/setup"
	"nyktus.org/nyktus/internal/platform/httpx"
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
	// OIDC is the identity provider, or nil if users do not sign in through
	// one. OIDCGroups map its groups to roles.
	OIDC       *oidc.Provider
	OIDCGroups oidc.Groups
}

// New wires the console and returns its HTTP handler. It computes the dummy
// password hash of the sign-in, so it takes as long as one password hash.
func New(ctx context.Context, o Options) (http.Handler, error) {
	sessions, err := session.NewService(ctx, o.DB, o.Hasher, o.Keys, o.Sessions)
	if err != nil {
		return nil, err
	}
	h := session.NewHandler(o.Logger, sessions)
	k := apikeyapi.NewHandler(o.Logger, o.DB, sessions)
	// The routes exist without a provider as well, so that the API is the same
	// in every configuration; they answer that there is nothing to sign in to.
	notFound := http.HandlerFunc(httpx.NotFound)
	signInThroughProvider := OIDC{Authorize: notFound, Reauthenticate: notFound, Callback: notFound}
	if o.OIDC != nil {
		p := oidc.NewHandler(o.Logger, oidc.NewService(o.DB, o.OIDC, sessions, o.OIDCGroups), h)
		signInThroughProvider = OIDC{
			Authorize:      http.HandlerFunc(p.Authorize),
			Reauthenticate: http.HandlerFunc(p.Reauthenticate),
			Callback:       http.HandlerFunc(p.Callback),
		}
	}
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
		OIDC: signInThroughProvider,
		APIKeys: APIKeys{
			List:   http.HandlerFunc(k.List),
			Create: http.HandlerFunc(k.Create),
			Revoke: http.HandlerFunc(k.Revoke),
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
