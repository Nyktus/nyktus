// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package apikey issues API keys and authenticates requests with them.
//
// Keys belong to the team, not to the administrator who created them, and act
// with their scopes alone. A key consists of a fixed prefix, a non-secret
// identifier, a secret of 256 bits from crypto/rand and a checksum. The database
// stores only the SHA-256 hash of the secret. A key is looked up by its
// identifier, and the secret is compared in constant time. A key expires within
// three years and is deleted when it is revoked.
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

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/platform/text"
)

// Limits of keys.
const (
	// MaxKeys bounds the keys of the installation that have not expired.
	MaxKeys = 50
	// MaxLifetime bounds the time from the creation of a key to its expiry,
	// three years with a leap day. The database enforces it as well.
	MaxLifetime = 1096 * 24 * time.Hour
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
	// unknown, expired or revoked key and a wrong secret.
	ErrInvalidKey = errors.New("invalid API key")
	// ErrNotFound means that there is no key with the identifier.
	ErrNotFound      = errors.New("API key not found")
	ErrInvalidName   = errors.New("invalid API key name")
	ErrInvalidScopes = errors.New("invalid API key scopes")
	ErrInvalidExpiry = errors.New("invalid API key expiry")
	// ErrTooManyKeys means that the installation has MaxKeys keys that have not
	// expired.
	ErrTooManyKeys = errors.New("too many API keys")
)

// Key describes an API key without its secret.
type Key struct {
	ID   string
	Name string
	// CreatedBy is the administrator who created the key, or nil if the
	// account was deleted since.
	CreatedBy *string
	Scopes    []httpx.Permission
	CreatedAt time.Time
	ExpiresAt time.Time
	// LastUsedAt is nil if the key was never used. It is exact to touchInterval.
	LastUsedAt *time.Time
}

// LogValue names the key by its identifier.
func (k Key) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", k.ID))
}

// Spec describes a key to create.
type Spec struct {
	Name      string
	Scopes    []httpx.Permission
	ExpiresAt time.Time
}

// ParseName accepts a name of 1 to MaxNameLength characters, as
// text.ValidName describes, and returns it unchanged.
func ParseName(s string) (string, error) {
	if !text.ValidName(s, MaxNameLength) {
		return "", ErrInvalidName
	}
	return s, nil
}

// ValidateScopes checks the scopes of a new key: one to MaxScopes distinct
// permissions that keys may carry, each with the scopes it requires.
func ValidateScopes(scopes []httpx.Permission) error {
	if len(scopes) == 0 || len(scopes) > MaxScopes {
		return ErrInvalidScopes
	}
	keyScopes := access.KeyScopes()
	for i, s := range scopes {
		if !slices.Contains(keyScopes, s) || slices.Contains(scopes[:i], s) {
			return ErrInvalidScopes
		}
		if required, ok := access.KeyScopeRequires(s); ok && !slices.Contains(scopes, required) {
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

const keyColumns = `id, name, created_by, scopes, created_at, expires_at, last_used_at`

func scanKey(row pgx.Row, extra ...any) (Key, error) {
	var (
		k      Key
		scopes []string
	)
	dest := append([]any{&k.ID, &k.Name, &k.CreatedBy, &scopes, &k.CreatedAt, &k.ExpiresAt, &k.LastUsedAt}, extra...)
	if err := row.Scan(dest...); err != nil {
		return Key{}, err
	}
	k.Scopes = make([]httpx.Permission, len(scopes))
	for i, s := range scopes {
		k.Scopes[i] = httpx.Permission(s)
	}
	return k, nil
}

// Create issues a key that the administrator createdBy creates and returns it
// with the key itself, which only the administrator receives. It deletes the
// expired keys and returns ErrTooManyKeys if MaxKeys keys are left. Only
// administrators create keys, and the caller holds the lock of the active
// administrators (user.Store.LockActiveAdmins), so that concurrent creations
// cannot exceed the limit together; a lock of the table would also stop keys
// from recording their use. The caller has validated the name and the scopes;
// the database rejects an expiry that is not in the future or more than
// MaxLifetime away with ErrInvalidExpiry.
func (s *Store) Create(ctx context.Context, createdBy string, spec Spec) (Key, string, error) {
	if _, err := s.db.Exec(ctx, `DELETE FROM api_keys WHERE expires_at <= clock_timestamp()`); err != nil {
		return Key{}, "", fmt.Errorf("delete expired API keys: %w", err)
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_keys`).Scan(&n); err != nil {
		return Key{}, "", fmt.Errorf("count API keys: %w", err)
	}
	if n >= MaxKeys {
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
INSERT INTO api_keys (created_by, name, secret_hash, scopes, expires_at) VALUES ($1, $2, $3, $4, $5)
RETURNING `+keyColumns, createdBy, spec.Name, hashSecret(secret), scopes, spec.ExpiresAt))
	switch db.Violation(err, db.CheckViolation) {
	case "api_keys_expires_at_check":
		return Key{}, "", ErrInvalidExpiry
	case "api_keys_name_check":
		return Key{}, "", ErrInvalidName
	case "api_keys_scopes_check":
		return Key{}, "", ErrInvalidScopes
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

// List returns the keys of the installation, the newest first. There are at
// most MaxKeys keys that have not expired, so the list has no pages.
func (s *Store) List(ctx context.Context) ([]Key, error) {
	rows, err := s.db.Query(ctx, `
SELECT `+keyColumns+`
FROM api_keys
ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list API keys: %w", err)
	}
	keys, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Key, error) { return scanKey(row) })
	if err != nil {
		return nil, fmt.Errorf("list API keys: %w", err)
	}
	return keys, nil
}

// Delete revokes the key id. It returns ErrNotFound if there is no such key.
func (s *Store) Delete(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM api_keys WHERE id = $1`, id)
	if db.NotFound(err) {
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

// Revoke revokes the key id on behalf of actor and records it in the audit log.
// It returns ErrNotFound if there is no such key.
func Revoke(ctx context.Context, d DB, actor audit.Actor, id string) error {
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		if err := NewStore(tx).Delete(ctx, id); err != nil {
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

// Authenticate returns the key of key. It returns ErrInvalidKey if the key is
// malformed, unknown, revoked or expired, or if its secret is wrong.
func (s *Store) Authenticate(ctx context.Context, key string) (Key, error) {
	id, secret, ok := parse(key)
	if !ok {
		return Key{}, ErrInvalidKey
	}
	var stored []byte
	// The key is looked up by its identifier, never by its hash, so that the
	// secret is compared below in constant time and not by an index.
	k, err := scanKey(s.db.QueryRow(ctx, `
SELECT `+keyColumns+`, secret_hash
FROM api_keys
WHERE id = $1 AND expires_at > clock_timestamp()`, id), &stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return Key{}, ErrInvalidKey
	}
	if err != nil {
		return Key{}, fmt.Errorf("look up API key: %w", err)
	}
	if subtle.ConstantTimeCompare(hashSecret(secret), stored) != 1 {
		return Key{}, ErrInvalidKey
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
		return Key{}, fmt.Errorf("record use of API key: %w", err)
	}
	return k, nil
}

// Response is the representation of a key in API responses, without its secret.
type Response struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	CreatedBy  *string            `json:"created_by"`
	Scopes     []httpx.Permission `json:"scopes"`
	CreatedAt  time.Time          `json:"created_at"`
	ExpiresAt  time.Time          `json:"expires_at"`
	LastUsedAt *time.Time         `json:"last_used_at"`
}

// Response returns the representation of k in API responses.
func (k Key) Response() Response {
	return Response(k)
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
