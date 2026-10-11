// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"context"
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
// one without the password. The caller validates the name and the scopes of
// spec; the router has checked the permission.
//
// As with a change of password, a wrong password counts as a failed sign-in and
// returns ErrWrongPassword, and a lock is revealed only with the correct
// password as a *LockedError. Both are recorded in the audit log, as is every
// new key; a request rejected for its fields or the limit of keys is not,
// because it proves nothing about the credentials. It returns
// ErrNoSession if the session of p ended since the request was authenticated.
func (s *Service) CreateAPIKey(ctx context.Context, p access.Principal, password string, spec apikey.Spec) (apikey.Key, string, error) {
	u, err := s.verifyCurrentPassword(ctx, p, password, audit.ActionAPIKeyCreate)
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
		outcome, err = lockVerified(ctx, tx, u, p, audit.ActionAPIKeyCreate)
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
