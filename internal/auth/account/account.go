// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package account lets administrators manage the accounts of the console and
// lets new users activate theirs.
//
// An administrator creates an account with an address, a display name and a
// role. The account has no password: the administrator receives an activation
// link, once, and passes it on. Whoever opens the link sets the password, which
// the administrator therefore never knows. A link expires and works once.
//
// At least one active administrator always remains. Changes that would remove
// the last one are rejected, and administrators cannot demote, deactivate or
// delete their own account.
package account

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/auth/token"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/user"
)

// Errors of the service.
var (
	// ErrOwnAccount means that an administrator tried to demote, deactivate or
	// delete their own account.
	ErrOwnAccount = errors.New("administrators cannot demote, deactivate or delete their own account")
	// ErrNotPending means that an activation link was requested for an account
	// that is not pending.
	ErrNotPending = errors.New("account is not pending")
	// ErrInvalidToken means that an activation token is unknown, expired or
	// already used.
	ErrInvalidToken = errors.New("invalid activation token")
)

// resourceType names accounts in the audit log.
const resourceType = "user"

// DB runs queries and starts transactions. A connection pool and a transaction
// implement it; in a transaction, Begin starts a savepoint.
type DB interface {
	db.Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Service manages accounts. It is safe for concurrent use.
type Service struct {
	db         DB
	consoleURL string
}

// NewService returns a Service that works on d. Activation links start with
// consoleURL, the address under which users reach the console.
func NewService(d DB, consoleURL string) *Service {
	if d == nil || consoleURL == "" {
		panic("account: service needs a database and the console URL")
	}
	return &Service{db: d, consoleURL: consoleURL}
}

// Link is an activation link.
type Link struct {
	// URL contains the activation token. It is shown once, to the administrator
	// who requested it, and never stored.
	URL       string
	ExpiresAt time.Time
}

// LogValue keeps the URL, which contains the token, out of logs.
func (l Link) LogValue() slog.Value {
	return slog.GroupValue(slog.Time("expires_at", l.ExpiresAt))
}

// String keeps the URL out of formatted output, such as an error message.
func (l Link) String() string {
	return "activation link expiring at " + l.ExpiresAt.UTC().Format(time.RFC3339)
}

// GoString keeps the URL out of %#v.
func (l Link) GoString() string { return l.String() }

// List returns a page of accounts, as user.Store.List does, and records the read
// in the audit log, at most once per administrator and audit.RepeatWindow.
// Accounts contain personal data.
func (s *Service) List(ctx context.Context, p access.Principal, size int, after *user.Cursor) ([]user.User, *user.Cursor, error) {
	users, next, err := user.NewStore(s.db).List(ctx, size, after)
	if err != nil {
		return nil, nil, err
	}
	if err := s.recordRead(ctx, p); err != nil {
		return nil, nil, err
	}
	return users, next, nil
}

// Get returns the account id and records the read like List.
func (s *Service) Get(ctx context.Context, p access.Principal, id string) (user.User, error) {
	u, err := user.NewStore(s.db).Get(ctx, id)
	if err != nil {
		return user.User{}, err
	}
	if err := s.recordRead(ctx, p); err != nil {
		return user.User{}, err
	}
	return u, nil
}

func (s *Service) recordRead(ctx context.Context, p access.Principal) error {
	return audit.NewStore(s.db).RecordUnlessRepeated(ctx, audit.Entry{
		Action:  audit.ActionUsersRead,
		Outcome: audit.OutcomeSuccess,
		Actor:   p.Actor(),
	}.WithRequest(ctx))
}

// NewAccount describes an account to create.
type NewAccount struct {
	Email       string
	DisplayName string
	Role        user.Role
}

// Create creates a pending account and an activation link for it. It returns
// user.ErrEmailTaken if another account uses the address.
func (s *Service) Create(ctx context.Context, p access.Principal, na NewAccount) (user.User, Link, error) {
	var (
		created user.User
		link    Link
	)
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var err error
		created, err = user.NewStore(tx).Create(ctx, user.NewUser{Email: na.Email, DisplayName: na.DisplayName, Role: na.Role})
		if err != nil {
			return err
		}
		if err := record(ctx, tx, p, audit.ActionUserCreate, created.ID, nil); err != nil {
			return err
		}
		link, err = s.issue(ctx, tx, p, created.ID)
		return err
	})
	if err != nil {
		return user.User{}, Link{}, wrap("create user", err)
	}
	return created, link, nil
}

// Update applies c to the account id, as user.Store.Update does, and records
// the changed fields. A change of role or status ends the sessions of the
// account, and a change of status removes its activation link. It returns
// ErrOwnAccount if an administrator demotes or deactivates their own account.
func (s *Service) Update(ctx context.Context, p access.Principal, id string, c user.Change) (user.User, error) {
	// The principal is an active administrator, as the permission to manage
	// accounts requires, so any other role or status removes one.
	if id == p.UserID && ((c.Role != nil && *c.Role != user.RoleAdmin) || (c.Status != nil && *c.Status != user.StatusActive)) {
		return user.User{}, ErrOwnAccount
	}
	var updated user.User
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var (
			changed []string
			err     error
		)
		updated, changed, err = user.NewStore(tx).Update(ctx, id, c)
		if err != nil || len(changed) == 0 {
			return err
		}
		if slices.Contains(changed, user.FieldRole) || slices.Contains(changed, user.FieldStatus) {
			if err := session.RevokeAll(ctx, tx, id); err != nil {
				return err
			}
		}
		if slices.Contains(changed, user.FieldStatus) {
			if err := deleteLink(ctx, tx, id); err != nil {
				return err
			}
		}
		return record(ctx, tx, p, audit.ActionUserUpdate, id, changed)
	})
	if err != nil {
		return user.User{}, wrap("update user", err)
	}
	return updated, nil
}

// Delete deletes the account id with its sessions and activation link. It
// returns ErrOwnAccount if an administrator deletes their own account.
func (s *Service) Delete(ctx context.Context, p access.Principal, id string) error {
	if id == p.UserID {
		return ErrOwnAccount
	}
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if err := user.NewStore(tx).Delete(ctx, id); err != nil {
			return err
		}
		return record(ctx, tx, p, audit.ActionUserDelete, id, nil)
	})
	return wrap("delete user", err)
}

// IssueLink issues a new activation link for the pending account id. The
// previous link of the account stops working. It returns ErrNotPending if the
// account is not pending.
func (s *Service) IssueLink(ctx context.Context, p access.Principal, id string) (Link, error) {
	var link Link
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// The lock keeps the account pending until the link exists. A concurrent
		// deactivation, which removes the link, waits until then.
		u, err := user.NewStore(tx).Lock(ctx, id)
		if err != nil {
			return err
		}
		if u.Status != user.StatusPending {
			return ErrNotPending
		}
		link, err = s.issue(ctx, tx, p, id)
		return err
	})
	if err != nil {
		return Link{}, wrap("issue activation link", err)
	}
	return link, nil
}

// issue replaces the activation link of the account id and records it.
func (s *Service) issue(ctx context.Context, tx pgx.Tx, p access.Principal, id string) (Link, error) {
	if err := deleteLink(ctx, tx, id); err != nil {
		return Link{}, err
	}
	value, err := token.New()
	if err != nil {
		return Link{}, err
	}
	var expiresAt time.Time
	// The database sets the expiry.
	err = tx.QueryRow(ctx, `INSERT INTO activation_tokens (user_id, token_hash) VALUES ($1, $2) RETURNING expires_at`,
		id, token.Hash(value)).Scan(&expiresAt)
	if err != nil {
		return Link{}, fmt.Errorf("insert activation token: %w", err)
	}
	if err := record(ctx, tx, p, audit.ActionActivationLinkCreate, id, nil); err != nil {
		return Link{}, err
	}
	return Link{URL: URL(s.consoleURL, value), ExpiresAt: expiresAt.UTC()}, nil
}

// URL returns the address of the activation page for tok. The token is placed
// in the fragment, which browsers never send to a server, so that it does not
// reach the access logs of the console or of a reverse proxy, nor a Referer
// header.
func URL(consoleURL, tok string) string {
	return consoleURL + "/activate#token=" + tok
}

// Valid reports whether tok is a valid activation token, without consuming it.
// It lets a caller reject a request before hashing a password. Activate checks
// the token again.
func (s *Service) Valid(ctx context.Context, tok string) (bool, error) {
	var valid bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS (SELECT FROM activation_tokens WHERE token_hash = $1 AND expires_at > clock_timestamp())`,
		token.Hash(tok)).Scan(&valid)
	if err != nil {
		return false, fmt.Errorf("look up activation token: %w", err)
	}
	return valid, nil
}

// Activate consumes tok and sets the password of its pending account, which
// becomes active. The holder of the token acts as the user of the account. It
// returns ErrInvalidToken if the token is not valid.
func (s *Service) Activate(ctx context.Context, tok, passwordHash string) (user.User, error) {
	var activated user.User
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx,
			`DELETE FROM activation_tokens WHERE token_hash = $1 AND expires_at > clock_timestamp() RETURNING user_id`,
			token.Hash(tok)).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidToken
		}
		if err != nil {
			return fmt.Errorf("consume activation token: %w", err)
		}
		activated, err = user.NewStore(tx).Activate(ctx, id, passwordHash)
		if errors.Is(err, user.ErrNotFound) {
			// A link exists only for pending accounts, so this means a bug.
			return ErrInvalidToken
		}
		if err != nil {
			return err
		}
		return audit.NewStore(tx).Record(ctx, audit.Entry{
			Action:   audit.ActionUserActivate,
			Outcome:  audit.OutcomeSuccess,
			Actor:    audit.Actor{Kind: audit.ActorUser, Method: audit.AuthActivationToken, UserID: id},
			Resource: audit.Resource{Type: resourceType, ID: id},
		}.WithRequest(ctx))
	})
	if err != nil {
		return user.User{}, wrap("activate user", err)
	}
	return activated, nil
}

func deleteLink(ctx context.Context, q db.Querier, id string) error {
	if _, err := q.Exec(ctx, `DELETE FROM activation_tokens WHERE user_id = $1`, id); err != nil {
		return fmt.Errorf("delete activation token: %w", err)
	}
	return nil
}

func record(ctx context.Context, q db.Querier, p access.Principal, action audit.Action, id string, changed []string) error {
	return audit.NewStore(q).Record(ctx, audit.Entry{
		Action:        action,
		Outcome:       audit.OutcomeSuccess,
		Actor:         p.Actor(),
		Resource:      audit.Resource{Type: resourceType, ID: id},
		ChangedFields: changed,
	}.WithRequest(ctx))
}

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", op, err)
}
