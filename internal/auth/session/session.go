// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package session signs users in with their email address and password and keeps
// them signed in with server-side sessions.
//
// The browser holds an opaque token in a cookie; the database stores only its
// SHA-256 hash. A session ends after a period without requests, after an absolute
// lifetime and when the user signs out. Times are those of the database, so that
// every console process applies the same clock.
package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/auth/token"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/user"
)

// touchInterval limits how often a session records that it was used. The idle
// timeout is therefore exact to this interval, and a request does not cost a
// write.
const touchInterval = time.Minute

// Errors of the service.
var (
	// ErrInvalidCredentials covers every rejected sign-in except a locked account:
	// an unknown address, a wrong password and an account that may not sign in.
	ErrInvalidCredentials = errors.New("invalid email address or password")
	// ErrNoSession means that a token belongs to no valid session.
	ErrNoSession = errors.New("no valid session")
	// ErrWrongPassword means that the current password given for a change of
	// password is wrong.
	ErrWrongPassword = errors.New("current password is wrong")
)

// LockedError means that the password was correct, but the account is locked
// after too many failed sign-ins.
type LockedError struct {
	RetryAfter time.Duration
}

func (e *LockedError) Error() string {
	return fmt.Sprintf("account is locked for %v", e.RetryAfter)
}

// DB runs queries and starts transactions. A connection pool and a transaction
// implement it; in a transaction, Begin starts a savepoint.
type DB interface {
	db.Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

// PasswordHasher verifies and hashes passwords. *password.Hasher implements it.
type PasswordHasher interface {
	Hash(ctx context.Context, password string) (string, error)
	Verify(ctx context.Context, password, encoded string) (bool, error)
	NeedsRehash(encoded string) bool
}

// Config sets the lifetime of sessions.
type Config struct {
	// IdleTimeout ends a session after this long without a request.
	IdleTimeout time.Duration
	// MaxAge ends a session this long after sign-in.
	MaxAge time.Duration
}

// Service signs users in and out and resolves sessions.
type Service struct {
	db     DB
	hasher PasswordHasher
	cfg    Config
	// dummyHash is verified when no account or no password hash exists, so that a
	// sign-in takes the same time whether or not the account exists.
	dummyHash string
}

// NewService returns a Service. It computes the dummy hash with hasher, so it
// takes as long as one password hash.
func NewService(ctx context.Context, d DB, hasher PasswordHasher, cfg Config) (*Service, error) {
	if d == nil || hasher == nil {
		panic("session: service needs a database and a password hasher")
	}
	if cfg.IdleTimeout <= 0 || cfg.MaxAge < cfg.IdleTimeout {
		panic("session: idle timeout must be positive and at most the maximum age")
	}
	random, err := token.New()
	if err != nil {
		return nil, err
	}
	dummy, err := hasher.Hash(ctx, random)
	if err != nil {
		return nil, fmt.Errorf("compute dummy password hash: %w", err)
	}
	return &Service{db: d, hasher: hasher, cfg: cfg, dummyHash: dummy}, nil
}

// Session is a valid session.
type Session struct {
	ID   string
	User user.User
	// IdleExpiresAt is when the session ends unless it is used before.
	IdleExpiresAt time.Time
	// ExpiresAt is when the session ends at the latest.
	ExpiresAt time.Time
}

// LogValue names the session and its user without their personal data.
func (s Session) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", s.ID), slog.String("user_id", s.User.ID))
}

func (s *Service) expiries(createdAt, lastSeenAt time.Time) (idle, absolute time.Time) {
	absolute = createdAt.Add(s.cfg.MaxAge).UTC()
	idle = lastSeenAt.Add(s.cfg.IdleTimeout).UTC()
	if idle.After(absolute) {
		idle = absolute
	}
	return idle, absolute
}

// SignIn verifies the address and password and starts a new session. It returns
// the session and its token, which only the client keeps. previous is the token
// of a session the client still holds; that session ends, so that no session is
// left behind and a token set before sign-in is never carried over.
//
// It returns ErrInvalidCredentials for an unknown address, a wrong password and
// an account that is not active, and a *LockedError only if the password is
// correct. The password is verified in every case, against a dummy hash if there
// is no account, so the time of the answer does not reveal whether the account
// exists. Every attempt is recorded in the audit log; a failure for an unknown
// address does not record the address, which may be a mistyped password.
func (s *Service) SignIn(ctx context.Context, email, password, previous string) (Session, string, error) {
	users := user.NewStore(s.db)
	u, err := users.GetByEmail(ctx, email)
	known := err == nil
	if err != nil && !errors.Is(err, user.ErrNotFound) {
		return Session{}, "", err
	}
	encoded := s.dummyHash
	if known && u.PasswordHash != "" {
		encoded = u.PasswordHash
	}
	ok, err := s.hasher.Verify(ctx, password, encoded)
	if err != nil {
		return Session{}, "", fmt.Errorf("verify password: %w", err)
	}

	if !known {
		err := audit.NewStore(s.db).Record(ctx, signInEntry(ctx, audit.OutcomeFailure,
			audit.Actor{Kind: audit.ActorAnonymous, Method: audit.AuthPassword}, ""))
		if err != nil {
			return Session{}, "", err
		}
		return Session{}, "", ErrInvalidCredentials
	}
	actor := audit.Actor{Kind: audit.ActorUser, Method: audit.AuthPassword, UserID: u.ID}
	if !ok {
		err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
			if err := user.NewStore(tx).RecordFailedLogin(ctx, u.ID); err != nil {
				return err
			}
			return audit.NewStore(tx).Record(ctx, signInEntry(ctx, audit.OutcomeFailure, actor, ""))
		})
		if err != nil {
			return Session{}, "", fmt.Errorf("record failed sign-in: %w", err)
		}
		return Session{}, "", ErrInvalidCredentials
	}

	// Raised hashing parameters reach an account when it signs in, because only
	// then is the password known. A password that no longer meets the length
	// rules keeps its hash.
	var rehash string
	if s.hasher.NeedsRehash(u.PasswordHash) {
		rehash, err = s.hasher.Hash(ctx, password)
		if err != nil {
			rehash = ""
			if ctx.Err() != nil {
				return Session{}, "", fmt.Errorf("rehash password: %w", err)
			}
		}
	}
	tok, err := token.New()
	if err != nil {
		return Session{}, "", err
	}

	var (
		sess    Session
		outcome error
	)
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		users := user.NewStore(tx)
		// The state is read again under the row lock, so that a lock set by a
		// concurrent failure since the password was checked is respected, and
		// a password replaced in the meantime, such as by a reset, no longer
		// signs in.
		state, err := users.LockForSignIn(ctx, u.ID)
		if err != nil {
			return err
		}
		switch {
		case state.PasswordHash != u.PasswordHash:
			outcome = ErrInvalidCredentials
		case state.RetryAfter > 0:
			outcome = &LockedError{RetryAfter: state.RetryAfter}
		case state.Status != user.StatusActive:
			outcome = ErrInvalidCredentials
		}
		if outcome != nil {
			return audit.NewStore(tx).Record(ctx, signInEntry(ctx, audit.OutcomeFailure, actor, ""))
		}

		if err := users.CompleteSignIn(ctx, u.ID, rehash); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
DELETE FROM sessions
WHERE token_hash = $1
	OR (user_id = $2 AND (last_seen_at <= clock_timestamp() - $3::interval OR created_at <= clock_timestamp() - $4::interval))`,
			token.Hash(previous), u.ID, s.cfg.IdleTimeout, s.cfg.MaxAge); err != nil {
			return fmt.Errorf("delete previous and expired sessions: %w", err)
		}
		var createdAt, lastSeenAt time.Time
		err = tx.QueryRow(ctx, `
INSERT INTO sessions (token_hash, user_id) VALUES ($1, $2)
RETURNING id, created_at, last_seen_at`, token.Hash(tok), u.ID).Scan(&sess.ID, &createdAt, &lastSeenAt)
		if err != nil {
			return fmt.Errorf("insert session: %w", err)
		}
		sess.User = u
		sess.IdleExpiresAt, sess.ExpiresAt = s.expiries(createdAt, lastSeenAt)
		return audit.NewStore(tx).Record(ctx, signInEntry(ctx, audit.OutcomeSuccess, actor, sess.ID))
	})
	if err != nil {
		return Session{}, "", fmt.Errorf("sign in: %w", err)
	}
	if outcome != nil {
		return Session{}, "", outcome
	}
	return sess, tok, nil
}

func signInEntry(ctx context.Context, outcome audit.Outcome, actor audit.Actor, sessionID string) audit.Entry {
	e := audit.Entry{Action: audit.ActionSessionCreate, Outcome: outcome, Actor: actor}
	if sessionID != "" {
		e.Resource = audit.Resource{Type: "session", ID: sessionID}
	}
	return e.WithRequest(ctx)
}

// Authenticate returns the session of tok. It returns ErrNoSession if there is
// none, if it has expired, or if its account is not active: deactivating an
// account takes effect with the next request. Account and role are read with
// every request, so a changed role applies immediately as well.
func (s *Service) Authenticate(ctx context.Context, tok string) (Session, error) {
	var (
		sess                  Session
		createdAt, lastSeenAt time.Time
	)
	err := s.db.QueryRow(ctx, `
SELECT s.id, s.created_at, s.last_seen_at, u.id, u.email, u.display_name, u.role, u.status
FROM sessions AS s
JOIN users AS u ON u.id = s.user_id
WHERE s.token_hash = $1
	AND s.last_seen_at > clock_timestamp() - $2::interval
	AND s.created_at > clock_timestamp() - $3::interval
	AND u.status = $4`, token.Hash(tok), s.cfg.IdleTimeout, s.cfg.MaxAge, user.StatusActive).
		Scan(&sess.ID, &createdAt, &lastSeenAt, &sess.User.ID, &sess.User.Email, &sess.User.DisplayName, &sess.User.Role, &sess.User.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNoSession
	}
	if err != nil {
		return Session{}, fmt.Errorf("look up session: %w", err)
	}

	err = s.db.QueryRow(ctx, `
UPDATE sessions SET last_seen_at = clock_timestamp()
WHERE id = $1 AND last_seen_at <= clock_timestamp() - $2::interval
RETURNING last_seen_at`, sess.ID, touchInterval).Scan(&lastSeenAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Session{}, fmt.Errorf("record use of session: %w", err)
	}
	sess.IdleExpiresAt, sess.ExpiresAt = s.expiries(createdAt, lastSeenAt)
	return sess, nil
}

// SignOut ends the session of p and records the sign-out.
func (s *Service) SignOut(ctx context.Context, p access.Principal) error {
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, p.SessionID); err != nil {
			return fmt.Errorf("delete session: %w", err)
		}
		return audit.NewStore(tx).Record(ctx, audit.Entry{
			Action:   audit.ActionSessionDelete,
			Outcome:  audit.OutcomeSuccess,
			Actor:    p.Actor(),
			Resource: audit.Resource{Type: "session", ID: p.SessionID},
		}.WithRequest(ctx))
	})
	if err != nil {
		return fmt.Errorf("sign out: %w", err)
	}
	return nil
}

// ChangePassword replaces the password of the signed-in principal p, who must
// give the current password, with next. The caller validates next with
// password.Validate; it is hashed only after the current password is verified.
// It ends every session of the account and returns a new session that replaces
// the session of p, with its token, so that the user stays signed in while the
// old token stops working. An open password reset link of the account stops
// working as well.
//
// A wrong current password counts as a failed sign-in and returns
// ErrWrongPassword, so that a taken-over session cannot guess the password more
// often than the sign-in can. As with a sign-in, a lock after failed sign-ins is
// revealed only with the correct password, as a *LockedError. Every attempt is
// recorded in the audit log.
func (s *Service) ChangePassword(ctx context.Context, p access.Principal, current, next string) (Session, string, error) {
	u, err := user.NewStore(s.db).Get(ctx, p.UserID)
	if errors.Is(err, user.ErrNotFound) {
		// The account was deleted since the request was authenticated.
		return Session{}, "", ErrNoSession
	}
	if err != nil {
		return Session{}, "", err
	}
	ok, err := s.hasher.Verify(ctx, current, u.PasswordHash)
	if err != nil {
		return Session{}, "", fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
			if err := user.NewStore(tx).RecordFailedLogin(ctx, u.ID); err != nil {
				return err
			}
			return audit.NewStore(tx).Record(ctx, passwordChangeEntry(ctx, audit.OutcomeFailure, p))
		})
		if err != nil {
			return Session{}, "", fmt.Errorf("record failed change of password: %w", err)
		}
		return Session{}, "", ErrWrongPassword
	}

	newHash, err := s.hasher.Hash(ctx, next)
	if err != nil {
		return Session{}, "", fmt.Errorf("hash password: %w", err)
	}
	tok, err := token.New()
	if err != nil {
		return Session{}, "", err
	}
	var (
		sess    Session
		outcome error
	)
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		users := user.NewStore(tx)
		// As in SignIn, the state is read again under the row lock. A password
		// replaced since it was verified is no longer the current password.
		state, err := users.LockForSignIn(ctx, u.ID)
		if err != nil {
			return err
		}
		switch {
		case state.Status != user.StatusActive:
			// The account was deactivated since the request was authenticated.
			outcome = ErrNoSession
			return nil
		case state.PasswordHash != u.PasswordHash:
			outcome = ErrWrongPassword
			return audit.NewStore(tx).Record(ctx, passwordChangeEntry(ctx, audit.OutcomeFailure, p))
		case state.RetryAfter > 0:
			outcome = &LockedError{RetryAfter: state.RetryAfter}
			return audit.NewStore(tx).Record(ctx, passwordChangeEntry(ctx, audit.OutcomeFailure, p))
		}
		changed, err := users.SetPassword(ctx, u.ID, newHash)
		if err != nil {
			return err
		}
		if err := RevokeAll(ctx, tx, u.ID); err != nil {
			return err
		}
		var createdAt, lastSeenAt time.Time
		err = tx.QueryRow(ctx, `
INSERT INTO sessions (token_hash, user_id) VALUES ($1, $2)
RETURNING id, created_at, last_seen_at`, token.Hash(tok), u.ID).Scan(&sess.ID, &createdAt, &lastSeenAt)
		if err != nil {
			return fmt.Errorf("insert session: %w", err)
		}
		sess.User = changed
		sess.IdleExpiresAt, sess.ExpiresAt = s.expiries(createdAt, lastSeenAt)
		return audit.NewStore(tx).Record(ctx, passwordChangeEntry(ctx, audit.OutcomeSuccess, p))
	})
	if err != nil {
		return Session{}, "", fmt.Errorf("change password: %w", err)
	}
	if outcome != nil {
		return Session{}, "", outcome
	}
	return sess, tok, nil
}

func passwordChangeEntry(ctx context.Context, outcome audit.Outcome, p access.Principal) audit.Entry {
	return audit.Entry{
		Action:   audit.ActionUserPasswordChange,
		Outcome:  outcome,
		Actor:    p.Actor(),
		Resource: audit.Resource{Type: "user", ID: p.UserID},
	}.WithRequest(ctx)
}

// RevokeAll ends every session of the account userID. It runs on q, so that a
// change that requires it, such as deactivating the account or changing its
// role, ends the sessions in its own transaction.
func RevokeAll(ctx context.Context, q db.Querier, userID string) error {
	if _, err := q.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("revoke sessions of user %s: %w", userID, err)
	}
	return nil
}
