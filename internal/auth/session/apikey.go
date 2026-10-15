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
// one without the password. The confirmation works as Confirm describes. The
// caller validates the name and the scopes of spec; the router has checked the
// permission. A request rejected for its fields or the limit of keys is not
// recorded in the audit log, because it proves nothing about the credentials.
func (s *Service) CreateAPIKey(ctx context.Context, p access.Principal, password string, spec apikey.Spec) (apikey.Key, string, error) {
	var (
		k   apikey.Key
		key string
	)
	err := s.Confirm(ctx, p, password, audit.ActionAPIKeyCreate, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		if k, key, err = apikey.NewStore(tx).Create(ctx, p.UserID, spec); err != nil {
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
		return apikey.Key{}, "", err
	}
	return k, key, nil
}

// Confirm runs change in a transaction once the signed-in administrator p has
// confirmed it with their password, for a change that a taken-over session must
// not be able to make alone, such as issuing a key or redirecting alerts. An
// administrator of the identity provider, who has no password, confirms by
// signing in there again within ReauthenticationWindow, and receives
// ErrReauthenticationRequired otherwise.
//
// As with a change of password, a wrong password counts as a failed sign-in and
// returns ErrWrongPassword, and a lock is revealed only with the correct
// password as a *LockedError; both are recorded in the audit log as failures of
// action. Change records its own success. Confirm returns ErrNoSession if the
// session of p ended or its account is no longer an active administrator. It
// holds the lock of the active administrators while change runs, so that
// changes that count against a limit are serialized.
func (s *Service) Confirm(ctx context.Context, p access.Principal, password string, action audit.Action,
	change func(ctx context.Context, tx pgx.Tx) error,
) error {
	u, err := s.verifyCurrentPassword(ctx, p, password, action)
	if errors.Is(err, user.ErrOIDCAccount) {
		u, err = s.account(ctx, p)
	}
	if err != nil {
		return err
	}
	var outcome error
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// The lock of the active administrators is taken before the account,
		// as every transaction takes them.
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
			outcome, err = lockVerified(ctx, tx, u, p, action)
		}
		if err != nil || outcome != nil {
			return err
		}
		// A session that ended, for example by a change of password elsewhere,
		// must not leave a change behind.
		var exists bool
		err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT FROM sessions WHERE id = $1 AND user_id = $2)`, p.SessionID, u.ID).Scan(&exists)
		if err != nil {
			return fmt.Errorf("look up session: %w", err)
		}
		if !exists {
			outcome = ErrNoSession
			return nil
		}
		return change(ctx, tx)
	})
	if err != nil {
		return fmt.Errorf("confirm %s: %w", action, err)
	}
	return outcome
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
