// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/auth/apikey"
	"nyktus.org/nyktus/internal/user"
)

// CreateAPIKey issues an API key that the signed-in administrator p creates for
// the team, confirmed with their password, and returns it with the key itself.
// A key outlives the session, so a taken-over session must not be able to issue
// one without the password. An administrator of the identity provider, who has
// no password, confirms by signing in there again within
// ReauthenticationWindow, and receives ErrReauthenticationRequired otherwise.
// The caller validates the name and the scopes of spec; the router has checked
// the permission.
//
// As with a change of password, a wrong password counts as a failed sign-in and
// returns ErrWrongPassword, and a lock is revealed only with the correct
// password as a *LockedError. Both are recorded in the audit log, as is every
// new key; a request rejected for its fields or the limit of keys is not,
// because it proves nothing about the credentials. It returns
// ErrNoSession if the session of p ended since the request was authenticated.
func (s *Service) CreateAPIKey(ctx context.Context, p access.Principal, password string, spec apikey.Spec) (apikey.Key, string, error) {
	u, err := s.verifyCurrentPassword(ctx, p, password, audit.ActionAPIKeyCreate)
	if errors.Is(err, user.ErrOIDCAccount) {
		u, err = s.account(ctx, p)
	}
	if err != nil {
		return apikey.Key{}, "", err
	}
	var (
		k       apikey.Key
		key     string
		outcome error
	)
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// Only administrators create keys. Their lock serializes the creations,
		// so that the count of keys holds against the limit, and it is taken
		// before the account, as every transaction takes them.
		admins, err := user.NewStore(tx).LockActiveAdmins(ctx)
		if err != nil {
			return err
		}
		if !slices.Contains(admins, u.ID) {
			// The administrator was demoted or deactivated since the request
			// was authenticated.
			outcome = ErrNoSession
			return nil
		}
		if u.Identity != nil {
			outcome, err = lockReauthenticated(ctx, tx, u, p)
		} else {
			outcome, err = lockVerified(ctx, tx, u, p, audit.ActionAPIKeyCreate)
		}
		if err != nil || outcome != nil {
			return err
		}
		// A session that ended, for example by a change of password elsewhere,
		// must not leave a key behind.
		var exists bool
		err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT FROM sessions WHERE id = $1 AND user_id = $2)`, p.SessionID, u.ID).Scan(&exists)
		if err != nil {
			return fmt.Errorf("look up session: %w", err)
		}
		if !exists {
			outcome = ErrNoSession
			return nil
		}
		k, key, err = apikey.NewStore(tx).Create(ctx, u.ID, spec)
		if err != nil {
			return err
		}
		return audit.NewStore(tx).Record(ctx, audit.Entry{
			Action:   audit.ActionAPIKeyCreate,
			Outcome:  audit.OutcomeSuccess,
			Actor:    p.Actor(),
			Resource: audit.Resource{Type: "api_key", ID: k.ID},
		}.WithRequest(ctx))
	})
	if err != nil {
		return apikey.Key{}, "", fmt.Errorf("create API key: %w", err)
	}
	if outcome != nil {
		return apikey.Key{}, "", outcome
	}
	return k, key, nil
}

// lockReauthenticated locks the account u of the identity provider and checks
// under the lock that it is still active and that the session of p signed in at
// the provider again within ReauthenticationWindow. It returns the reason if
// not: ErrNoSession if the account or the session ended, and
// ErrReauthenticationRequired if the sign-in is missing or too old.
func lockReauthenticated(ctx context.Context, tx pgx.Tx, u user.User, p access.Principal) (outcome, err error) {
	state, err := user.NewStore(tx).LockForSignIn(ctx, u.ID)
	if errors.Is(err, user.ErrNotFound) || (err == nil && state.Status != user.StatusActive) {
		return ErrNoSession, nil
	}
	if err != nil {
		return nil, err
	}
	fresh, err := Reauthenticated(ctx, tx, p.SessionID, u.ID)
	switch {
	case errors.Is(err, ErrNoSession):
		return ErrNoSession, nil
	case err != nil:
		return nil, err
	case !fresh:
		return ErrReauthenticationRequired, nil
	}
	return nil, nil
}
