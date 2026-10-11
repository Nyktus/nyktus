// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package apikey issues API keys and authenticates requests with them.
//
// A key consists of a fixed prefix, a non-secret identifier, a secret of 256
// bits from crypto/rand and a checksum. The database stores only the SHA-256
// hash of the secret. A key is looked up by its identifier, and the secret is
// compared in constant time. A key acts for its user with the intersection of
// its scopes and the current role of the user, expires within a year, and is
// deleted when it is revoked.
package apikey

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/user"
)

// Limits of keys.
const (
	// MaxPerUser bounds the keys of a user that have not expired.
	MaxPerUser = 20
	// MaxLifetime bounds the time from the creation of a key to its expiry. The
	// database enforces it as well.
	MaxLifetime = 365 * 24 * time.Hour
	// MaxNameLength bounds the name of a key, in characters.
	MaxNameLength = 64
	// MaxScopes bounds the scopes of a key.
	MaxScopes = 16
)

// touchInterval limits how often a key records that it was used, so that a
// request does not cost a write.
const touchInterval = time.Minute

// Errors of the store.
var (
	// ErrInvalidKey covers every key that does not authenticate: a malformed,
	// unknown, expired or revoked key, a wrong secret and a key of an account
	// that is not active.
	ErrInvalidKey = errors.New("invalid API key")
	// ErrNotFound means that the user has no key with the identifier.
	ErrNotFound      = errors.New("API key not found")
	ErrInvalidName   = errors.New("invalid API key name")
	ErrInvalidScopes = errors.New("invalid API key scopes")
	ErrInvalidExpiry = errors.New("invalid API key expiry")
	// ErrTooManyKeys means that the user has MaxPerUser keys that have not
	// expired.
	ErrTooManyKeys = errors.New("too many API keys")
)

// SQLSTATE codes mapped by the store.
const (
	checkViolation            = "23514"
	invalidTextRepresentation = "22P02"
)

// Key describes an API key without its secret.
type Key struct {
	ID        string
	UserID    string
	Name      string
	Scopes    []httpx.Permission
	CreatedAt time.Time
	ExpiresAt time.Time
	// LastUsedAt is nil if the key was never used. It is exact to touchInterval.
	LastUsedAt *time.Time
}

// LogValue names the key and its user without its name, which the user chose.
func (k Key) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", k.ID), slog.String("user_id", k.UserID))
}

// Spec describes a key to create.
type Spec struct {
	Name      string
	Scopes    []httpx.Permission
	ExpiresAt time.Time
}

// ParseName accepts a name of 1 to MaxNameLength characters under the rules of
// a display name and returns it unchanged.
func ParseName(s string) (string, error) {
	if _, err := user.ParseDisplayName(s); err != nil || len([]rune(s)) > MaxNameLength {
		return "", ErrInvalidName
	}
	return s, nil
}

// ValidateScopes checks the scopes of a new key of a user with role: one to
// MaxScopes distinct permissions that keys may carry and that role grants. A
// key would not hold a scope beyond the role anyway, but it would gain it
// silently if the user were promoted later.
func ValidateScopes(scopes []httpx.Permission, role user.Role) error {
	if len(scopes) == 0 || len(scopes) > MaxScopes {
		return ErrInvalidScopes
	}
	keyScopes := access.KeyScopes()
	for i, s := range scopes {
		if !slices.Contains(keyScopes, s) || !access.Allowed(role, s) || slices.Contains(scopes[:i], s) {
			return ErrInvalidScopes
		}
	}
	return nil
}

// Store persists API keys in PostgreSQL.
type Store struct {
	db db.Querier
}

// NewStore returns a Store that runs its queries on q, a connection pool or a
// transaction.
func NewStore(q db.Querier) *Store {
	if q == nil {
		panic("apikey: nil querier")
	}
	return &Store{db: q}
}

const keyColumns = `id, user_id, name, scopes, created_at, expires_at, last_used_at`

func scanKey(row pgx.Row, extra ...any) (Key, error) {
	var (
		k      Key
		scopes []string
	)
	dest := append([]any{&k.ID, &k.UserID, &k.Name, &scopes, &k.CreatedAt, &k.ExpiresAt, &k.LastUsedAt}, extra...)
	if err := row.Scan(dest...); err != nil {
		return Key{}, err
	}
	k.Scopes = make([]httpx.Permission, len(scopes))
	for i, s := range scopes {
		k.Scopes[i] = httpx.Permission(s)
	}
	return k, nil
}

// Create issues a key of the user userID and returns it with the key itself,
// which only the user receives. It deletes the expired keys of the user and
// returns ErrTooManyKeys if the user has MaxPerUser keys left. The caller holds
// the lock of the account, so that concurrent requests cannot exceed the limit,
// and has validated the name and the scopes; the database rejects an expiry
// that is not in the future or more than MaxLifetime away with ErrInvalidExpiry.
func (s *Store) Create(ctx context.Context, userID string, spec Spec) (Key, string, error) {
	if _, err := s.db.Exec(ctx, `DELETE FROM api_keys WHERE user_id = $1 AND expires_at <= clock_timestamp()`, userID); err != nil {
		return Key{}, "", fmt.Errorf("delete expired API keys: %w", err)
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE user_id = $1`, userID).Scan(&n); err != nil {
		return Key{}, "", fmt.Errorf("count API keys: %w", err)
	}
	if n >= MaxPerUser {
		return Key{}, "", ErrTooManyKeys
	}

	secret, err := newSecret()
	if err != nil {
		return Key{}, "", err
	}
	scopes := make([]string, len(spec.Scopes))
	for i, p := range spec.Scopes {
		scopes[i] = string(p)
	}
	k, err := scanKey(s.db.QueryRow(ctx, `
INSERT INTO api_keys (user_id, name, secret_hash, scopes, expires_at) VALUES ($1, $2, $3, $4, $5)
RETURNING `+keyColumns, userID, spec.Name, hashSecret(secret), scopes, spec.ExpiresAt))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == checkViolation {
		switch pgErr.ConstraintName {
		case "api_keys_expires_at_check":
			return Key{}, "", ErrInvalidExpiry
		case "api_keys_name_check":
			return Key{}, "", ErrInvalidName
		case "api_keys_scopes_check":
			return Key{}, "", ErrInvalidScopes
		}
	}
	if err != nil {
		return Key{}, "", fmt.Errorf("insert API key: %w", err)
	}
	key, err := format(k.ID, secret)
	if err != nil {
		return Key{}, "", err
	}
	return k, key, nil
}

// List returns the keys of the user userID, the newest first. There are at most
// MaxPerUser keys that have not expired, so the list has no pages.
func (s *Store) List(ctx context.Context, userID string) ([]Key, error) {
	rows, err := s.db.Query(ctx, `
SELECT `+keyColumns+`
FROM api_keys
WHERE user_id = $1
ORDER BY created_at DESC, id DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list API keys: %w", err)
	}
	keys, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Key, error) { return scanKey(row) })
	if err != nil {
		return nil, fmt.Errorf("list API keys: %w", err)
	}
	return keys, nil
}

// Delete revokes the key id of the user userID. It returns ErrNotFound if the
// user has no such key.
func (s *Store) Delete(ctx context.Context, userID, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM api_keys WHERE id = $1 AND user_id = $2`, id, userID)
	var pgErr *pgconn.PgError
	// An identifier that is not a UUID cannot belong to a key or a user.
	if errors.As(err, &pgErr) && pgErr.Code == invalidTextRepresentation {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("delete API key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DB runs queries and starts transactions. A connection pool and a transaction
// implement it; in a transaction, Begin starts a savepoint.
type DB interface {
	db.Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Revoke revokes the key id of the user userID on behalf of actor, the user or
// an administrator, and records it in the audit log. It returns ErrNotFound if
// the user has no such key.
func Revoke(ctx context.Context, d DB, actor audit.Actor, userID, id string) error {
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		if err := NewStore(tx).Delete(ctx, userID, id); err != nil {
			return err
		}
		return audit.NewStore(tx).Record(ctx, audit.Entry{
			Action:   audit.ActionAPIKeyRevoke,
			Outcome:  audit.OutcomeSuccess,
			Actor:    actor,
			Resource: audit.Resource{Type: "api_key", ID: id},
		}.WithRequest(ctx))
	})
	if err != nil {
		return fmt.Errorf("revoke API key: %w", err)
	}
	return nil
}

// DeleteAll revokes every key of the user userID. It runs on q, so that a change
// that requires it, such as deactivating the account, revokes the keys in its
// own transaction.
func DeleteAll(ctx context.Context, q db.Querier, userID string) error {
	if _, err := q.Exec(ctx, `DELETE FROM api_keys WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("revoke API keys of user %s: %w", userID, err)
	}
	return nil
}

// Authenticate returns the key and the account of key. It returns ErrInvalidKey
// if the key is malformed, unknown, revoked or expired, if its secret is wrong,
// or if its account is not active. The account is read with every request, so a
// changed role or a deactivation applies with the next request.
func (s *Store) Authenticate(ctx context.Context, key string) (Key, user.User, error) {
	id, secret, ok := parse(key)
	if !ok {
		return Key{}, user.User{}, ErrInvalidKey
	}
	var (
		u      user.User
		stored []byte
	)
	// The key is looked up by its identifier, never by its hash, so that the
	// secret is compared below in constant time and not by an index.
	k, err := scanKey(s.db.QueryRow(ctx, `
SELECT k.id, k.user_id, k.name, k.scopes, k.created_at, k.expires_at, k.last_used_at, k.secret_hash,
	u.id, u.email, u.display_name, u.role, u.status
FROM api_keys AS k
JOIN users AS u ON u.id = k.user_id
WHERE k.id = $1
	AND k.expires_at > clock_timestamp()
	AND u.status = $2`, id, user.StatusActive),
		&stored, &u.ID, &u.Email, &u.DisplayName, &u.Role, &u.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return Key{}, user.User{}, ErrInvalidKey
	}
	if err != nil {
		return Key{}, user.User{}, fmt.Errorf("look up API key: %w", err)
	}
	if subtle.ConstantTimeCompare(hashSecret(secret), stored) != 1 {
		return Key{}, user.User{}, ErrInvalidKey
	}

	var used time.Time
	err = s.db.QueryRow(ctx, `
UPDATE api_keys SET last_used_at = clock_timestamp()
WHERE id = $1 AND (last_used_at IS NULL OR last_used_at <= clock_timestamp() - $2::interval)
RETURNING last_used_at`, k.ID, touchInterval).Scan(&used)
	switch {
	case err == nil:
		k.LastUsedAt = &used
	case !errors.Is(err, pgx.ErrNoRows):
		return Key{}, user.User{}, fmt.Errorf("record use of API key: %w", err)
	}
	return k, u, nil
}

// Response is the representation of a key in API responses, without its secret.
type Response struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Scopes     []httpx.Permission `json:"scopes"`
	CreatedAt  time.Time          `json:"created_at"`
	ExpiresAt  time.Time          `json:"expires_at"`
	LastUsedAt *time.Time         `json:"last_used_at"`
}

// Response returns the representation of k in API responses.
func (k Key) Response() Response {
	return Response{ID: k.ID, Name: k.Name, Scopes: k.Scopes, CreatedAt: k.CreatedAt, ExpiresAt: k.ExpiresAt, LastUsedAt: k.LastUsedAt}
}

// Responses returns the representations of keys, an empty list if there are
// none.
func Responses(keys []Key) []Response {
	resp := make([]Response, 0, len(keys))
	for _, k := range keys {
		resp = append(resp, k.Response())
	}
	return resp
}
