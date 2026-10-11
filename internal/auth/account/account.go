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
// A user who forgot their password receives a password reset link the same
// way, from an administrator or, if no administrator can sign in, from the
// command line. Setting a new password through the link ends every session of
// the account and a lock after failed sign-ins.
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
	// ErrNotActive means that a password reset link was requested for an
	// account that is not active.
	ErrNotActive = errors.New("account is not active")
	// ErrNotAdmin means that the command line requested a password reset link
	// for an account that is not an administrator.
	ErrNotAdmin = errors.New("account is not an administrator")
	// ErrInvalidToken means that the token of a link is unknown, expired, used
	// or issued for another purpose.
	ErrInvalidToken = errors.New("invalid link token")
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

// Link is an activation or password reset link.
type Link struct {
	// URL contains the token. It is shown once, to the administrator
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
	return "link expiring at " + l.ExpiresAt.UTC().Format(time.RFC3339)
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
		if err := record(ctx, tx, p.Actor(), audit.ActionUserCreate, created.ID, nil); err != nil {
			return err
		}
		link, err = s.issue(ctx, tx, p.Actor(), created.ID, activation)
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
		return record(ctx, tx, p.Actor(), audit.ActionUserUpdate, id, changed)
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
		return record(ctx, tx, p.Actor(), audit.ActionUserDelete, id, nil)
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
		link, err = s.issue(ctx, tx, p.Actor(), id, activation)
		return err
	})
	if err != nil {
		return Link{}, wrap("issue activation link", err)
	}
	return link, nil
}

// purpose is what a link lets its holder do. Each public endpoint consumes only
// links issued for its purpose.
type purpose struct {
	// name is stored with the link.
	name string
	// action records the issuance of a link in the audit log.
	action audit.Action
	// page is the path of the console page that opens a link.
	page string
}

// activation lets the holder of a link set the first password of a pending
// account.
var activation = purpose{name: "activation", action: audit.ActionActivationLinkCreate, page: "/activate"}

// passwordReset lets the holder of a link set a new password for an active
// account.
var passwordReset = purpose{name: "password_reset", action: audit.ActionPasswordResetLinkCreate, page: "/reset-password"}

// IssueResetLink issues a password reset link for the active account id, which
// may be locked. The previous link of the account stops working. Issuing the
// link changes nothing else: the password and the sessions stay valid until the
// link is used. It returns ErrNotActive if the account is not active.
func (s *Service) IssueResetLink(ctx context.Context, p access.Principal, id string) (Link, error) {
	var link Link
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// The lock keeps the account active until the link exists. A concurrent
		// deactivation, which removes the link, waits until then.
		u, err := user.NewStore(tx).Lock(ctx, id)
		if err != nil {
			return err
		}
		if u.Status != user.StatusActive {
			return ErrNotActive
		}
		link, err = s.issue(ctx, tx, p.Actor(), id, passwordReset)
		return err
	})
	if err != nil {
		return Link{}, wrap("issue password reset link", err)
	}
	return link, nil
}

// IssueAdminResetLink issues a password reset link for the active administrator
// with the address email, on behalf of the command line, so that an operator
// can regain access when no administrator can sign in. Other accounts are reset
// by an administrator. It returns user.ErrNotFound if no account has the
// address, ErrNotAdmin if the account is no administrator and ErrNotActive if
// it is not active.
func (s *Service) IssueAdminResetLink(ctx context.Context, email string) (Link, error) {
	var link Link
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		users := user.NewStore(tx)
		found, err := users.GetByEmail(ctx, email)
		if err != nil {
			return err
		}
		// Role and status are checked under the lock, as in IssueResetLink.
		u, err := users.Lock(ctx, found.ID)
		if err != nil {
			return err
		}
		switch {
		case u.Role != user.RoleAdmin:
			return ErrNotAdmin
		case u.Status != user.StatusActive:
			return ErrNotActive
		}
		link, err = s.issue(ctx, tx, audit.Actor{Kind: audit.ActorSystem, Method: audit.AuthCLI}, u.ID, passwordReset)
		return err
	})
	if err != nil {
		return Link{}, wrap("issue password reset link", err)
	}
	return link, nil
}

// issue replaces the link of the account id with a new one for pu and records
// it.
func (s *Service) issue(ctx context.Context, tx pgx.Tx, actor audit.Actor, id string, pu purpose) (Link, error) {
	if err := deleteLink(ctx, tx, id); err != nil {
		return Link{}, err
	}
	value, err := token.New()
	if err != nil {
		return Link{}, err
	}
	var expiresAt time.Time
	// The database sets the expiry.
	err = tx.QueryRow(ctx, `INSERT INTO account_links (user_id, token_hash, purpose) VALUES ($1, $2, $3) RETURNING expires_at`,
		id, token.Hash(value), pu.name).Scan(&expiresAt)
	if err != nil {
		return Link{}, fmt.Errorf("insert account link: %w", err)
	}
	if err := record(ctx, tx, actor, pu.action, id, nil); err != nil {
		return Link{}, err
	}
	return Link{URL: linkURL(s.consoleURL, pu, value), ExpiresAt: expiresAt.UTC()}, nil
}

// URL returns the address of the activation page for tok.
func URL(consoleURL, tok string) string {
	return linkURL(consoleURL, activation, tok)
}

// linkURL returns the address of the page for a link. The token is placed in the
// fragment, which browsers never send to a server, so that it does not reach the
// access logs of the console or of a reverse proxy, nor a Referer header.
func linkURL(consoleURL string, pu purpose, tok string) string {
	return consoleURL + pu.page + "#token=" + tok
}

// valid reports whether tok is a valid token of a link for pu, without
// consuming it. It lets a caller reject a request before hashing a password. The
// consumption checks the token again.
func (s *Service) valid(ctx context.Context, tok string, pu purpose) (bool, error) {
	var valid bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS (SELECT FROM account_links WHERE token_hash = $1 AND purpose = $2 AND expires_at > clock_timestamp())`,
		token.Hash(tok), pu.name).Scan(&valid)
	if err != nil {
		return false, fmt.Errorf("look up account link: %w", err)
	}
	return valid, nil
}

// Activate consumes tok and sets the password of its pending account, which
// becomes active. The holder of the token acts as the user of the account. It
// returns ErrInvalidToken if the token is not valid.
func (s *Service) Activate(ctx context.Context, tok, passwordHash string) (user.User, error) {
	var activated user.User
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		id, err := consume(ctx, tx, tok, activation)
		if err != nil {
			return err
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

// ResetPassword consumes tok and replaces the password of its active account.
// Every session of the account ends, and so does a lock after failed sign-ins.
// The holder of the token acts as the user of the account. It returns
// ErrInvalidToken if the token is not valid.
func (s *Service) ResetPassword(ctx context.Context, tok, passwordHash string) (user.User, error) {
	var reset user.User
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		id, err := consume(ctx, tx, tok, passwordReset)
		if err != nil {
			return err
		}
		reset, err = user.NewStore(tx).SetPassword(ctx, id, passwordHash)
		if errors.Is(err, user.ErrNotFound) {
			// A change of status removes the link, so this means a bug.
			return ErrInvalidToken
		}
		if err != nil {
			return err
		}
		if err := session.RevokeAll(ctx, tx, id); err != nil {
			return err
		}
		return audit.NewStore(tx).Record(ctx, audit.Entry{
			Action:   audit.ActionUserPasswordReset,
			Outcome:  audit.OutcomeSuccess,
			Actor:    audit.Actor{Kind: audit.ActorUser, Method: audit.AuthPasswordResetToken, UserID: id},
			Resource: audit.Resource{Type: resourceType, ID: id},
		}.WithRequest(ctx))
	})
	if err != nil {
		return user.User{}, wrap("reset password", err)
	}
	return reset, nil
}

// consume deletes the link tok, issued for pu, and returns its account, which
// stays locked until the end of tx. It returns ErrInvalidToken if the link is
// not valid.
//
// The account is locked before its link, in the same order as every other
// change of an account takes its locks. A deactivation holds the account and
// then removes the link; locking the link first would let the two deadlock.
func consume(ctx context.Context, tx pgx.Tx, tok string, pu purpose) (string, error) {
	hash := token.Hash(tok)
	var id string
	err := tx.QueryRow(ctx,
		`SELECT user_id FROM account_links WHERE token_hash = $1 AND purpose = $2 AND expires_at > clock_timestamp()`,
		hash, pu.name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalidToken
	}
	if err != nil {
		return "", fmt.Errorf("look up account link: %w", err)
	}
	if _, err := user.NewStore(tx).Lock(ctx, id); err != nil {
		if errors.Is(err, user.ErrNotFound) {
			// The account was deleted after the lookup.
			return "", ErrInvalidToken
		}
		return "", err
	}
	// The link is consumed only now, under the lock of the account. A concurrent
	// request may have used or replaced it since the lookup.
	err = tx.QueryRow(ctx,
		`DELETE FROM account_links WHERE token_hash = $1 AND user_id = $2 AND purpose = $3 AND expires_at > clock_timestamp() RETURNING user_id`,
		hash, id, pu.name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalidToken
	}
	if err != nil {
		return "", fmt.Errorf("consume account link: %w", err)
	}
	return id, nil
}

func deleteLink(ctx context.Context, q db.Querier, id string) error {
	if _, err := q.Exec(ctx, `DELETE FROM account_links WHERE user_id = $1`, id); err != nil {
		return fmt.Errorf("delete account link: %w", err)
	}
	return nil
}

func record(ctx context.Context, q db.Querier, actor audit.Actor, action audit.Action, id string, changed []string) error {
	return audit.NewStore(q).Record(ctx, audit.Entry{
		Action:        action,
		Outcome:       audit.OutcomeSuccess,
		Actor:         actor,
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
