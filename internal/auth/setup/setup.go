// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package setup creates the first administrator of an installation.
//
// While no administrator exists, every console process issues a setup token when
// it starts and prints a URL that contains it. Whoever holds a valid token can
// create the first administrator, once. Without the token, whoever reached a fresh
// installation first could claim it. Once an administrator exists, the setup is
// closed for good, also after a restart.
package setup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/user"
)

// tokenBytes is the amount of randomness in a setup token.
const tokenBytes = 32

// Errors of Complete.
var (
	// ErrClosed means that an administrator exists, so the setup is closed.
	ErrClosed = errors.New("setup is closed")
	// ErrInvalidToken means that the token is unknown, expired or already used.
	ErrInvalidToken = errors.New("invalid setup token")
)

// DB runs queries and starts transactions. A connection pool and a transaction
// implement it; in a transaction, Begin starts a savepoint.
type DB interface {
	db.Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Service issues setup tokens and creates the first administrator.
type Service struct {
	db DB
}

// NewService returns a Service that works on d.
func NewService(d DB) *Service {
	if d == nil {
		panic("setup: nil database")
	}
	return &Service{db: d}
}

// Token is an issued setup token.
type Token struct {
	// Value is the token in clear text. It is shown once, in the setup URL, and
	// never stored.
	Value     string
	ExpiresAt time.Time
}

// LogValue keeps the token itself out of logs.
func (t Token) LogValue() slog.Value {
	return slog.GroupValue(slog.Time("expires_at", t.ExpiresAt))
}

// Issue issues a new setup token if no administrator exists. ok is false if one
// exists. Expired tokens are removed. Tokens issued by other console processes
// stay valid until they expire, so that a setup request can reach any of them.
func (s *Service) Issue(ctx context.Context) (t Token, ok bool, err error) {
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// The lock orders the issue after a concurrent setup: once the first
		// administrator has been created, no new token can appear.
		if err := lock(ctx, tx); err != nil {
			return err
		}
		exists, err := user.NewStore(tx).AdminExists(ctx)
		if err != nil || exists {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM setup_tokens WHERE expires_at <= clock_timestamp()`); err != nil {
			return fmt.Errorf("delete expired setup tokens: %w", err)
		}

		value, err := newToken()
		if err != nil {
			return err
		}
		// The database sets the expiry.
		err = tx.QueryRow(ctx, `INSERT INTO setup_tokens (token_hash) VALUES ($1) RETURNING expires_at`,
			hash(value)).Scan(&t.ExpiresAt)
		if err != nil {
			return fmt.Errorf("insert setup token: %w", err)
		}
		t.Value, t.ExpiresAt, ok = value, t.ExpiresAt.UTC(), true
		return nil
	})
	if err != nil {
		return Token{}, false, fmt.Errorf("issue setup token: %w", err)
	}
	return t, ok, nil
}

// Open reports whether the setup is open, which it is as long as no
// administrator exists.
func (s *Service) Open(ctx context.Context) (bool, error) {
	exists, err := user.NewStore(s.db).AdminExists(ctx)
	return !exists, err
}

// Valid reports whether token is a valid setup token, without consuming it. It
// lets a caller reject a request before doing expensive work, such as hashing a
// password. Complete checks the token again.
func (s *Service) Valid(ctx context.Context, token string) (bool, error) {
	var valid bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS (SELECT FROM setup_tokens WHERE token_hash = $1 AND expires_at > clock_timestamp())`,
		hash(token)).Scan(&valid)
	if err != nil {
		return false, fmt.Errorf("look up setup token: %w", err)
	}
	return valid, nil
}

// Admin describes the first administrator.
type Admin struct {
	Email       string
	DisplayName string
	// PasswordHash is the encoded Argon2id hash of the password.
	PasswordHash string
}

// Complete consumes token and creates the first administrator, active and with
// the given password hash, together with its audit entry. It returns ErrClosed if
// an administrator exists and ErrInvalidToken if the token is not valid. All
// remaining setup tokens are removed.
//
// Concurrent calls are serialized by a lock on the setup tokens, which is taken
// before the check for an administrator. Two requests with tokens of different
// console processes therefore never create two administrators.
func (s *Service) Complete(ctx context.Context, token string, admin Admin) (user.User, error) {
	var created user.User
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if err := lock(ctx, tx); err != nil {
			return err
		}
		exists, err := user.NewStore(tx).AdminExists(ctx)
		if err != nil {
			return err
		}
		if exists {
			return ErrClosed
		}

		var consumed []byte
		err = tx.QueryRow(ctx,
			`DELETE FROM setup_tokens WHERE token_hash = $1 AND expires_at > clock_timestamp() RETURNING token_hash`,
			hash(token)).Scan(&consumed)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidToken
		}
		if err != nil {
			return fmt.Errorf("consume setup token: %w", err)
		}

		created, err = user.NewStore(tx).Create(ctx, user.NewUser{
			Email:        admin.Email,
			DisplayName:  admin.DisplayName,
			Role:         user.RoleAdmin,
			PasswordHash: admin.PasswordHash,
		})
		if err != nil {
			return err
		}
		err = audit.NewStore(tx).Record(ctx, audit.Entry{
			Action:   audit.ActionUserCreate,
			Outcome:  audit.OutcomeSuccess,
			Actor:    audit.Actor{Kind: audit.ActorSetup, Method: audit.AuthSetupToken},
			Resource: audit.Resource{Type: "user", ID: created.ID},
		}.WithRequest(ctx))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM setup_tokens`); err != nil {
			return fmt.Errorf("delete setup tokens: %w", err)
		}
		return nil
	})
	switch {
	case errors.Is(err, ErrClosed), errors.Is(err, ErrInvalidToken):
		return user.User{}, err
	case err != nil:
		return user.User{}, fmt.Errorf("complete setup: %w", err)
	}
	return created, nil
}

// lock serializes the setup. Plain reads of the tokens are not blocked.
func lock(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `LOCK TABLE setup_tokens IN EXCLUSIVE MODE`); err != nil {
		return fmt.Errorf("lock setup tokens: %w", err)
	}
	return nil
}

func newToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate setup token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hash returns the SHA-256 hash under which a token is stored. A fast hash is
// enough, because a token carries 256 bits of randomness and cannot be guessed.
func hash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// URL returns the address of the setup page for t. The token is placed in the
// fragment, which browsers never send to a server, so that it does not reach
// the access logs of the console or of a reverse proxy, nor a Referer header.
func URL(consoleURL string, t Token) string {
	return consoleURL + "/setup#token=" + t.Value
}

// WriteInstructions writes the setup URL for t with a short explanation to w. It
// is meant for standard output, which is separate from the log.
func WriteInstructions(w io.Writer, consoleURL string, t Token) error {
	_, err := fmt.Fprintf(w, `
Nyktus has no administrator yet. Open the following URL to create the first one.
It is valid until %s. Restart Nyktus to get a new one.

    %s

`, t.ExpiresAt.UTC().Format(time.RFC3339), URL(consoleURL, t))
	return err
}
