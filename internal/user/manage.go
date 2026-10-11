// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Errors of the management of accounts.
var (
	// ErrLastActiveAdmin means that a change would leave no active
	// administrator.
	ErrLastActiveAdmin = errors.New("the last active administrator cannot be demoted, deactivated or deleted")
	// ErrInvalidStatus is returned for a status that a change cannot set, such as
	// pending.
	ErrInvalidStatus = errors.New("invalid status")
	// ErrInvalidTransition means that the account cannot change to the requested
	// status from its current one, such as a pending account to active.
	ErrInvalidTransition = errors.New("invalid status transition")
	// ErrInvalidPageSize is returned for a page size outside [1, MaxPageSize].
	ErrInvalidPageSize = errors.New("invalid page size")
)

const checkViolation = "23514"

// MaxPageSize is the largest page that List returns.
const MaxPageSize = 200

// Cursor marks the position after the last account of a page.
type Cursor struct {
	CreatedAt time.Time
	ID        string
}

const userColumns = `id, email, display_name, role, status, password_hash, created_at, updated_at`

const (
	listNewest = `SELECT ` + userColumns + ` FROM users
ORDER BY created_at DESC, id DESC
LIMIT $1`
	listAfter = `SELECT ` + userColumns + ` FROM users
WHERE (created_at, id) < ($1, $2::uuid)
ORDER BY created_at DESC, id DESC
LIMIT $3`
)

// List returns up to size accounts, from the newest to the oldest, that come
// after the cursor after, or from the newest if after is nil. next is the cursor
// of the following page, or nil if there are no more accounts.
func (s *Store) List(ctx context.Context, size int, after *Cursor) (users []User, next *Cursor, err error) {
	if size < 1 || size > MaxPageSize {
		return nil, nil, ErrInvalidPageSize
	}
	// One more account than requested tells whether another page follows. The
	// query without a cursor is a separate statement: a condition that is only
	// sometimes active would keep a generic plan from seeking into the index.
	var rows pgx.Rows
	if after == nil {
		rows, err = s.db.Query(ctx, listNewest, size+1)
	} else {
		rows, err = s.db.Query(ctx, listAfter, after.CreatedAt, after.ID, size+1)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("list users: %w", err)
	}
	users, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (User, error) { return scan(row) })
	if err != nil {
		return nil, nil, fmt.Errorf("list users: %w", err)
	}
	if len(users) > size {
		users = users[:size]
		last := users[size-1]
		next = &Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	return users, next, nil
}

// Change describes changes to an account. A nil field stays as it is.
type Change struct {
	DisplayName *string
	Role        *Role
	// Status is StatusActive to reactivate a deactivated account or
	// StatusDeactivated to deactivate one. A reactivated account without a
	// password returns to pending.
	Status *Status
}

// Names of the fields of a change, as recorded in the audit log.
const (
	FieldDisplayName = "display_name"
	FieldRole        = "role"
	FieldStatus      = "status"
)

// Update validates c and applies it to the account id. It returns the account
// after the change and the names of the fields whose values changed, which is
// empty if c changes nothing. It returns ErrNotFound if the account does not
// exist, ErrLastActiveAdmin if no active administrator would remain, and
// ErrInvalidTransition if the account cannot take the requested status.
//
// Reactivating an account ends a lock after failed sign-ins: an administrator
// decided to let the user in again.
//
// Update must run in a transaction: it locks the active administrators and the
// account until the end of the transaction, so that concurrent changes cannot
// remove the last active administrator between the check and the change.
func (s *Store) Update(ctx context.Context, id string, c Change) (User, []string, error) {
	if c.DisplayName != nil {
		name, err := ParseDisplayName(*c.DisplayName)
		if err != nil {
			return User{}, nil, err
		}
		c.DisplayName = &name
	}
	if c.Role != nil && !c.Role.Valid() {
		return User{}, nil, ErrInvalidRole
	}
	if c.Status != nil && *c.Status != StatusActive && *c.Status != StatusDeactivated {
		return User{}, nil, ErrInvalidStatus
	}

	var admins []string
	if c.Role != nil || c.Status != nil {
		var err error
		if admins, err = s.lockActiveAdmins(ctx); err != nil {
			return User{}, nil, err
		}
	}
	current, err := s.Lock(ctx, id)
	if err != nil {
		return User{}, nil, err
	}

	updated := current
	var changed []string
	if c.DisplayName != nil && *c.DisplayName != current.DisplayName {
		updated.DisplayName = *c.DisplayName
		changed = append(changed, FieldDisplayName)
	}
	if c.Role != nil && *c.Role != current.Role {
		updated.Role = *c.Role
		changed = append(changed, FieldRole)
	}
	reactivate := false
	if c.Status != nil {
		switch {
		case *c.Status == StatusDeactivated && current.Status != StatusDeactivated:
			updated.Status = StatusDeactivated
		case *c.Status == StatusActive && current.Status == StatusDeactivated:
			reactivate = true
			updated.Status = StatusActive
			if current.PasswordHash == "" {
				updated.Status = StatusPending
			}
		case *c.Status == StatusActive && current.Status == StatusPending:
			return User{}, nil, ErrInvalidTransition
		}
		if updated.Status != current.Status {
			changed = append(changed, FieldStatus)
		}
	}
	if len(changed) == 0 {
		return current, nil, nil
	}
	if activeAdmin(current) && !activeAdmin(updated) && onlyAdmin(admins, current.ID) {
		return User{}, nil, ErrLastActiveAdmin
	}

	u, err := scan(s.db.QueryRow(ctx, `
UPDATE users SET
	display_name = $2,
	role = $3,
	status = $4,
	failed_logins = CASE WHEN $5 THEN 0 ELSE failed_logins END,
	locked_until = CASE WHEN $5 THEN NULL ELSE locked_until END,
	updated_at = clock_timestamp()
WHERE id = $1
RETURNING `+userColumns, id, updated.DisplayName, updated.Role, updated.Status, reactivate))
	if err != nil {
		return User{}, nil, mapWriteError(fmt.Errorf("update user %s: %w", id, err))
	}
	return u, changed, nil
}

// Delete deletes the account id with its sessions and activation link. It
// returns ErrNotFound if the account does not exist and ErrLastActiveAdmin if it
// is the last active administrator. Like Update, it must run in a transaction.
func (s *Store) Delete(ctx context.Context, id string) error {
	admins, err := s.lockActiveAdmins(ctx)
	if err != nil {
		return err
	}
	current, err := s.Lock(ctx, id)
	if err != nil {
		return err
	}
	if activeAdmin(current) && onlyAdmin(admins, current.ID) {
		return ErrLastActiveAdmin
	}
	if _, err := s.db.Exec(ctx, `DELETE FROM users WHERE id = $1`, id); err != nil {
		return mapWriteError(fmt.Errorf("delete user %s: %w", id, err))
	}
	return nil
}

// Activate sets the password of the pending account id and makes it active. It
// returns ErrNotFound if no pending account with that ID exists, so that a link
// can never set the password of an account that already has one.
func (s *Store) Activate(ctx context.Context, id, passwordHash string) (User, error) {
	// As in Create: a plain-text password must never reach the database.
	if !strings.HasPrefix(passwordHash, "$argon2id$") {
		return User{}, ErrInvalidPasswordHash
	}
	u, err := scan(s.db.QueryRow(ctx, `
UPDATE users SET status = $2, password_hash = $3, updated_at = clock_timestamp()
WHERE id = $1 AND status = $4
RETURNING `+userColumns, id, StatusActive, passwordHash, StatusPending))
	var pgErr *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == invalidTextRepresentation) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("activate user %s: %w", id, err)
	}
	return u, nil
}

// lockActiveAdmins locks the active administrators until the end of the
// transaction and returns their IDs. They are locked in the order of their IDs,
// so that concurrent changes wait for each other instead of deadlocking. A
// waiting transaction evaluates the condition again once the lock is free, so it
// sees an administrator that a concurrent change has removed.
func (s *Store) lockActiveAdmins(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx, `
SELECT id FROM users
WHERE role = $1 AND status = $2
ORDER BY id
FOR UPDATE`, RoleAdmin, StatusActive)
	if err != nil {
		return nil, fmt.Errorf("lock active administrators: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("lock active administrators: %w", err)
	}
	return ids, nil
}

// Lock locks the account id until the end of the transaction and returns it. It
// returns ErrNotFound if the account does not exist.
func (s *Store) Lock(ctx context.Context, id string) (User, error) {
	u, err := scan(s.db.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1 FOR UPDATE`, id))
	var pgErr *pgconn.PgError
	// An ID that is not a UUID cannot belong to an account.
	if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == invalidTextRepresentation) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("lock user %s: %w", id, err)
	}
	return u, nil
}

func activeAdmin(u User) bool {
	return u.Role == RoleAdmin && u.Status == StatusActive
}

// onlyAdmin reports whether id is the only one of the locked active
// administrators.
func onlyAdmin(admins []string, id string) bool {
	return len(admins) == 1 && slices.Contains(admins, id)
}

// mapWriteError maps the rejection by the trigger that keeps an active
// administrator. The store checks the rule itself, so the trigger fires only if
// the store missed a case.
func mapWriteError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == checkViolation && pgErr.ConstraintName == "users_active_admin_check" {
		return ErrLastActiveAdmin
	}
	return err
}
