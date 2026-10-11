// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nyktus.org/nyktus/internal/platform/db"
)

// Store errors.
var (
	ErrNotFound   = errors.New("user not found")
	ErrEmailTaken = errors.New("email address is already in use")
)

// SQLSTATE codes mapped by the store.
const (
	uniqueViolation           = "23505"
	invalidTextRepresentation = "22P02"
)

// Store persists users in PostgreSQL.
type Store struct {
	db db.Querier
}

// NewStore returns a Store that runs its queries on q, a connection pool or a
// transaction.
func NewStore(q db.Querier) *Store {
	if q == nil {
		panic("user: nil querier")
	}
	return &Store{db: q}
}

// NewUser describes an account to create.
type NewUser struct {
	Email       string
	DisplayName string
	Role        Role
	// PasswordHash, if set, creates an active account, as for the first
	// administrator. Without it, the account is pending until the user sets a
	// password.
	PasswordHash string
}

// Create validates nu and stores a new account. It returns ErrEmailTaken if
// another account uses the same address, in any spelling.
//
// Email address, display name and role are validated before the insert,
// although the schema checks the same rules, and a password hash must at least
// look like one. PostgreSQL writes the complete failing row of a constraint
// violation to its server log, which must never contain a plain-text password.
func (s *Store) Create(ctx context.Context, nu NewUser) (User, error) {
	email, err := ParseEmail(nu.Email)
	if err != nil {
		return User{}, err
	}
	name, err := ParseDisplayName(nu.DisplayName)
	if err != nil {
		return User{}, err
	}
	if !nu.Role.Valid() {
		return User{}, ErrInvalidRole
	}
	status := StatusPending
	var hash *string
	if nu.PasswordHash != "" {
		// The prefix keeps a plain-text password away from the database and its
		// log. The full format is checked by the schema; a second copy of that
		// rule here could drift from it.
		if !strings.HasPrefix(nu.PasswordHash, "$argon2id$") {
			return User{}, ErrInvalidPasswordHash
		}
		status = StatusActive
		hash = &nu.PasswordHash
	}

	u, err := scan(s.db.QueryRow(ctx, `
INSERT INTO users (email, display_name, role, status, password_hash)
VALUES ($1, $2, $3, $4, $5)
RETURNING `+userColumns,
		email, name, nu.Role, status, hash))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation && pgErr.ConstraintName == "users_email_key" {
		return User{}, ErrEmailTaken
	}
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// Get returns the account with the given ID.
func (s *Store) Get(ctx context.Context, id string) (User, error) {
	u, err := scan(s.db.QueryRow(ctx, `
SELECT `+userColumns+`
FROM users
WHERE id = $1`, id))
	var pgErr *pgconn.PgError
	// An ID that is not a UUID cannot belong to an account.
	if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == invalidTextRepresentation) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("get user %s: %w", id, err)
	}
	return u, nil
}

// GetByEmail returns the account with the given address, in any case. An
// invalid address belongs to no account and yields ErrNotFound.
func (s *Store) GetByEmail(ctx context.Context, email string) (User, error) {
	normalized, err := ParseEmail(email)
	if err != nil {
		return User{}, ErrNotFound
	}
	u, err := scan(s.db.QueryRow(ctx, `
SELECT `+userColumns+`
FROM users
WHERE email = $1`, normalized))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		// The address is not logged: it may be input from an unauthenticated
		// sign-in attempt.
		return User{}, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

// AdminExists reports whether an account with the role admin exists, in any
// status. A deactivated administrator counts as well: otherwise deactivating the
// last one would open the setup of a first administrator again.
func (s *Store) AdminExists(ctx context.Context) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT FROM users WHERE role = $1)`, RoleAdmin).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check for administrator: %w", err)
	}
	return exists, nil
}

// Lockout of accounts after failed sign-ins. The schema allows at most
// MaxFailedLogins-1 counted failures, because the last one locks the account and
// starts the count again.
const (
	MaxFailedLogins = 5
	LockDuration    = 15 * time.Minute
)

// RecordFailedLogin counts a failed sign-in of the account id. The failure that
// reaches MaxFailedLogins locks the account for LockDuration and starts the count
// again. Failures while the account is locked neither count nor extend the lock,
// so that an attacker cannot keep an account locked for longer than LockDuration
// after the last lock.
//
// The count is updated in one statement, which holds the row lock, so concurrent
// failures are never lost.
func (s *Store) RecordFailedLogin(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `
UPDATE users SET
	failed_logins = CASE
		WHEN locked_until > clock_timestamp() THEN failed_logins
		WHEN failed_logins + 1 >= $2 THEN 0
		ELSE failed_logins + 1
	END,
	locked_until = CASE
		WHEN locked_until > clock_timestamp() THEN locked_until
		WHEN failed_logins + 1 >= $2 THEN clock_timestamp() + $3::interval
		ELSE locked_until
	END
WHERE id = $1`, id, MaxFailedLogins, LockDuration)
	if err != nil {
		return fmt.Errorf("record failed login of user %s: %w", id, err)
	}
	return nil
}

// SignInState is what a sign-in needs to know about an account.
type SignInState struct {
	Status Status
	// PasswordHash is the current hash. A caller that verified a password
	// before taking the lock compares it with the hash it verified against, so
	// that a password replaced in the meantime no longer counts.
	PasswordHash string
	// RetryAfter is the time until the lock of the account ends, or zero if the
	// account is not locked.
	RetryAfter time.Duration
}

// LockForSignIn locks the row of the account id until the end of the
// transaction and returns its state, so that a sign-in decides on the current
// state and no concurrent failure can lock the account in between.
func (s *Store) LockForSignIn(ctx context.Context, id string) (SignInState, error) {
	var (
		state   SignInState
		seconds float64
	)
	err := s.db.QueryRow(ctx, `
SELECT status, coalesce(password_hash, ''), coalesce(greatest(extract(epoch FROM locked_until - clock_timestamp()), 0), 0)
FROM users
WHERE id = $1
FOR UPDATE`, id).Scan(&state.Status, &state.PasswordHash, &seconds)
	var pgErr *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == invalidTextRepresentation) {
		return SignInState{}, ErrNotFound
	}
	if err != nil {
		return SignInState{}, fmt.Errorf("lock user %s for sign-in: %w", id, err)
	}
	state.RetryAfter = time.Duration(seconds * float64(time.Second))
	return state, nil
}

// CompleteSignIn records a successful sign-in of the account id: the count of
// failures starts again. If passwordHash is set, it replaces the stored hash, for
// example after the hashing parameters were raised.
func (s *Store) CompleteSignIn(ctx context.Context, id, passwordHash string) error {
	var hash *string
	if passwordHash != "" {
		// As in Create: a plain-text password must never reach the database.
		if !strings.HasPrefix(passwordHash, "$argon2id$") {
			return ErrInvalidPasswordHash
		}
		hash = &passwordHash
	}
	_, err := s.db.Exec(ctx, `
UPDATE users SET
	failed_logins = 0,
	locked_until = NULL,
	password_hash = coalesce($2, password_hash),
	updated_at = CASE WHEN $2::text IS NULL THEN updated_at ELSE clock_timestamp() END
WHERE id = $1`, id, hash)
	if err != nil {
		return fmt.Errorf("complete sign-in of user %s: %w", id, err)
	}
	return nil
}

// RehashPassword replaces the hash of the account id with passwordHash, which
// hashes the same password with raised parameters. Unlike CompleteSignIn, it
// leaves the count of failed sign-ins alone, for a sign-in that still waits for
// its second factor.
func (s *Store) RehashPassword(ctx context.Context, id, passwordHash string) error {
	// As in Create: a plain-text password must never reach the database.
	if !strings.HasPrefix(passwordHash, "$argon2id$") {
		return ErrInvalidPasswordHash
	}
	_, err := s.db.Exec(ctx, `UPDATE users SET password_hash = $2, updated_at = clock_timestamp() WHERE id = $1`, id, passwordHash)
	if err != nil {
		return fmt.Errorf("rehash password of user %s: %w", id, err)
	}
	return nil
}

func scan(row pgx.Row) (User, error) {
	var (
		u    User
		hash *string
	)
	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.Status, &hash, &u.CreatedAt, &u.UpdatedAt, &u.TOTPEnabled)
	if err != nil {
		return User{}, err
	}
	if hash != nil {
		u.PasswordHash = *hash
	}
	u.CreatedAt = u.CreatedAt.UTC()
	u.UpdatedAt = u.UpdatedAt.UTC()
	return u, nil
}
