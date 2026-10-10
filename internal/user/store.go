// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
RETURNING id, email, display_name, role, status, password_hash, created_at, updated_at`,
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
SELECT id, email, display_name, role, status, password_hash, created_at, updated_at
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
SELECT id, email, display_name, role, status, password_hash, created_at, updated_at
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

func scan(row pgx.Row) (User, error) {
	var (
		u    User
		hash *string
	)
	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.Status, &hash, &u.CreatedAt, &u.UpdatedAt)
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
