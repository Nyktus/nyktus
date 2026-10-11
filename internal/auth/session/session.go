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
	"nyktus.org/nyktus/internal/auth/secondfactor"
	"nyktus.org/nyktus/internal/auth/token"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/secretbox"
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
	// ErrReauthenticationRequired means that a user of the identity provider
	// must sign in there again to confirm an action, which a local account
	// confirms with its password.
	ErrReauthenticationRequired = errors.New("the action requires signing in at the identity provider again")
)

// ReauthenticationWindow is how long a sign-in at the identity provider
// confirms the sensitive actions of a session. It is short, so that a session
// taken over later cannot use it, and long enough for several actions in a row.
const ReauthenticationWindow = 5 * time.Minute

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

// Config sets the lifetime of sessions and who signs in with a password.
type Config struct {
	// IdleTimeout ends a session after this long without a request.
	IdleTimeout time.Duration
	// MaxAge ends a session this long after sign-in.
	MaxAge time.Duration
	// LocalLogin says which accounts sign in with a password.
	LocalLogin LocalLogin
}

// LocalLogin says which accounts sign in with a password, while the other
// users sign in through the identity provider.
type LocalLogin int

// Policies of the sign-in with a password.
const (
	// LocalLoginAll lets every account with a password sign in with it.
	LocalLoginAll LocalLogin = iota
	// LocalLoginAdmins lets only administrators sign in with a password, as
	// emergency access while the identity provider is unreachable.
	LocalLoginAdmins
	// LocalLoginOff lets no account sign in with a password.
	LocalLoginOff
)

// allows reports whether an account with role may sign in with a password.
func (l LocalLogin) allows(role user.Role) bool {
	return l == LocalLoginAll || (l == LocalLoginAdmins && role == user.RoleAdmin)
}

// Service signs users in and out and resolves sessions.
type Service struct {
	db     DB
	hasher PasswordHasher
	keys   *secretbox.Keyring
	cfg    Config
	// dummyHash is verified when no account or no password hash exists, so that a
	// sign-in takes the same time whether or not the account exists.
	dummyHash string
}

// NewService returns a Service. keys encrypt the secrets of second factors. It
// computes the dummy hash with hasher, so it takes as long as one password hash.
func NewService(ctx context.Context, d DB, hasher PasswordHasher, keys *secretbox.Keyring, cfg Config) (*Service, error) {
	if d == nil || hasher == nil || keys == nil {
		panic("session: service needs a database, a password hasher and encryption keys")
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
	return &Service{db: d, hasher: hasher, keys: keys, cfg: cfg, dummyHash: dummy}, nil
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

// SignInResult is the outcome of a correct password: either a session with its
// token, which only the client keeps, or, for an account with a second factor,
// a challenge that a code of the second factor turns into a session.
type SignInResult struct {
	Session Session
	Token   string
	// Challenge is set instead of Session and Token if the account has a
	// second factor.
	Challenge *Challenge
}

// SignIn verifies the address and password and starts a new session, or a
// challenge for the second factor if the account has one. previous is the token
// of a session the client still holds; that session ends when the new one
// starts, so that no session is left behind and a token set before sign-in is
// never carried over.
//
// It returns ErrInvalidCredentials for an unknown address, a wrong password, an
// account that is not active and an account that may not sign in with a
// password, and a *LockedError only if the password is correct. The password is
// verified in every case, against a dummy hash if there is no account, so the
// time of the answer does not reveal whether the account exists. Every attempt
// is recorded in the audit log; a failure for an unknown address does not
// record the address, which may be a mistyped password.
func (s *Service) SignIn(ctx context.Context, email, password, previous string) (SignInResult, error) {
	users := user.NewStore(s.db)
	u, err := users.GetByEmail(ctx, email)
	known := err == nil
	if err != nil && !errors.Is(err, user.ErrNotFound) {
		return SignInResult{}, err
	}
	encoded := s.dummyHash
	if known && u.PasswordHash != "" {
		encoded = u.PasswordHash
	}
	ok, err := s.hasher.Verify(ctx, password, encoded)
	if err != nil {
		return SignInResult{}, fmt.Errorf("verify password: %w", err)
	}

	if !known {
		err := audit.NewStore(s.db).Record(ctx, signInEntry(ctx, audit.OutcomeFailure,
			audit.Actor{Kind: audit.ActorAnonymous, Method: audit.AuthPassword}, ""))
		if err != nil {
			return SignInResult{}, err
		}
		return SignInResult{}, ErrInvalidCredentials
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
			return SignInResult{}, fmt.Errorf("record failed sign-in: %w", err)
		}
		return SignInResult{}, ErrInvalidCredentials
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
				return SignInResult{}, fmt.Errorf("rehash password: %w", err)
			}
		}
	}
	var (
		result  SignInResult
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
		// An account that may not sign in with a password is rejected like a
		// wrong password, after the same work, so that the answer reveals
		// neither the password nor the role. It is checked before the lock,
		// which only the correct password of an account that may sign in
		// learns.
		case !s.cfg.LocalLogin.allows(state.Role):
			outcome = ErrInvalidCredentials
		case state.RetryAfter > 0:
			outcome = &LockedError{RetryAfter: state.RetryAfter}
		case state.Status != user.StatusActive:
			outcome = ErrInvalidCredentials
		}
		if outcome != nil {
			return audit.NewStore(tx).Record(ctx, signInEntry(ctx, audit.OutcomeFailure, actor, ""))
		}

		enabled, err := secondfactor.NewStore(tx, s.keys).Enabled(ctx, u.ID)
		if err != nil {
			return err
		}
		if enabled {
			// The count of failures starts again only after the second factor.
			// Otherwise whoever knows the password could reset it between
			// guesses of the code and guess without limit.
			if rehash != "" {
				if err := users.RehashPassword(ctx, u.ID, rehash); err != nil {
					return err
				}
			}
			result.Challenge, err = issueChallenge(ctx, tx, u.ID)
			if err != nil {
				return err
			}
			return audit.NewStore(tx).Record(ctx, audit.Entry{
				Action: audit.ActionSignInChallengeCreate, Outcome: audit.OutcomeSuccess, Actor: actor,
			}.WithRequest(ctx))
		}

		if err := users.CompleteSignIn(ctx, u.ID, rehash); err != nil {
			return err
		}
		result.Session, result.Token, err = s.Start(ctx, tx, u, token.Hash(previous))
		if err != nil {
			return err
		}
		return audit.NewStore(tx).Record(ctx, signInEntry(ctx, audit.OutcomeSuccess, actor, result.Session.ID))
	})
	if err != nil {
		return SignInResult{}, fmt.Errorf("sign in: %w", err)
	}
	if outcome != nil {
		return SignInResult{}, outcome
	}
	return result, nil
}

// Start starts a new session of u in tx and ends the session whose token has
// the hash previous, which the client still holds, and the expired sessions of
// u. previous may be nil. The caller has authenticated u and records the
// sign-in.
func (s *Service) Start(ctx context.Context, tx pgx.Tx, u user.User, previous []byte) (Session, string, error) {
	if _, err := tx.Exec(ctx, `
DELETE FROM sessions
WHERE token_hash = $1
	OR (user_id = $2 AND (last_seen_at <= clock_timestamp() - $3::interval OR created_at <= clock_timestamp() - $4::interval))`,
		previous, u.ID, s.cfg.IdleTimeout, s.cfg.MaxAge); err != nil {
		return Session{}, "", fmt.Errorf("delete previous and expired sessions: %w", err)
	}
	return s.insert(ctx, tx, u)
}

// insert inserts a new session of u and returns it with its token.
func (s *Service) insert(ctx context.Context, tx pgx.Tx, u user.User) (Session, string, error) {
	tok, err := token.New()
	if err != nil {
		return Session{}, "", err
	}
	sess := Session{User: u}
	var createdAt, lastSeenAt time.Time
	err = tx.QueryRow(ctx, `
INSERT INTO sessions (token_hash, user_id) VALUES ($1, $2)
RETURNING id, created_at, last_seen_at`, token.Hash(tok), u.ID).Scan(&sess.ID, &createdAt, &lastSeenAt)
	if err != nil {
		return Session{}, "", fmt.Errorf("insert session: %w", err)
	}
	sess.IdleExpiresAt, sess.ExpiresAt = s.expiries(createdAt, lastSeenAt)
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
		issuer, subject       *string
	)
	err := s.db.QueryRow(ctx, `
SELECT s.id, s.created_at, s.last_seen_at, u.id, u.email, u.display_name, u.role, u.status, u.oidc_issuer, u.oidc_subject,
	EXISTS (SELECT FROM totp_factors AS f WHERE f.user_id = u.id AND f.confirmed_at IS NOT NULL)
FROM sessions AS s
JOIN users AS u ON u.id = s.user_id
WHERE s.token_hash = $1
	AND s.last_seen_at > clock_timestamp() - $2::interval
	AND s.created_at > clock_timestamp() - $3::interval
	AND u.status = $4`, token.Hash(tok), s.cfg.IdleTimeout, s.cfg.MaxAge, user.StatusActive).
		Scan(&sess.ID, &createdAt, &lastSeenAt, &sess.User.ID, &sess.User.Email, &sess.User.DisplayName, &sess.User.Role, &sess.User.Status,
			&issuer, &subject, &sess.User.TOTPEnabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNoSession
	}
	if err != nil {
		return Session{}, fmt.Errorf("look up session: %w", err)
	}
	if issuer != nil && subject != nil {
		sess.User.Identity = &user.Identity{Issuer: *issuer, Subject: *subject}
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
	u, err := s.verifyCurrentPassword(ctx, p, current, audit.ActionUserPasswordChange)
	if err != nil {
		return Session{}, "", err
	}
	newHash, err := s.hasher.Hash(ctx, next)
	if err != nil {
		return Session{}, "", fmt.Errorf("hash password: %w", err)
	}
	var (
		sess    Session
		tok     string
		outcome error
	)
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		outcome, err = lockVerified(ctx, tx, u, p, audit.ActionUserPasswordChange)
		if err != nil || outcome != nil {
			return err
		}
		changed, err := user.NewStore(tx).SetPassword(ctx, u.ID, newHash)
		if err != nil {
			return err
		}
		sess, tok, err = s.rotate(ctx, tx, changed, p.SessionID)
		if err != nil {
			return err
		}
		return audit.NewStore(tx).Record(ctx, accountEntry(ctx, audit.ActionUserPasswordChange, audit.OutcomeSuccess, p))
	})
	if err != nil {
		return Session{}, "", fmt.Errorf("change password: %w", err)
	}
	if outcome != nil {
		return Session{}, "", outcome
	}
	return sess, tok, nil
}

// verifyCurrentPassword verifies the password that the signed-in principal p
// gave to confirm a change of their account, recorded as action. A wrong
// password counts as a failed sign-in and returns ErrWrongPassword, so that a
// taken-over session cannot guess the password more often than the sign-in
// can. It returns ErrNoSession if the account was deleted since the request was
// authenticated, and user.ErrOIDCAccount for an account of the identity
// provider, which has no password.
//
// The password is verified without a lock, because hashing must not hold one;
// the caller confirms the result under the lock with lockVerified.
func (s *Service) verifyCurrentPassword(ctx context.Context, p access.Principal, password string, action audit.Action) (user.User, error) {
	u, err := s.account(ctx, p)
	if err != nil {
		return user.User{}, err
	}
	if u.Identity != nil {
		return user.User{}, user.ErrOIDCAccount
	}
	ok, err := s.hasher.Verify(ctx, password, u.PasswordHash)
	if err != nil {
		return user.User{}, fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
			if err := user.NewStore(tx).RecordFailedLogin(ctx, u.ID); err != nil {
				return err
			}
			return audit.NewStore(tx).Record(ctx, accountEntry(ctx, action, audit.OutcomeFailure, p))
		})
		if err != nil {
			return user.User{}, fmt.Errorf("record failed confirmation of password: %w", err)
		}
		return user.User{}, ErrWrongPassword
	}
	return u, nil
}

// account returns the account of p. It returns ErrNoSession if the account was
// deleted since the request was authenticated.
func (s *Service) account(ctx context.Context, p access.Principal) (user.User, error) {
	u, err := user.NewStore(s.db).Get(ctx, p.UserID)
	if errors.Is(err, user.ErrNotFound) {
		return user.User{}, ErrNoSession
	}
	return u, err
}

// lockVerified locks the account u, whose password verifyCurrentPassword
// verified, and checks under the lock that the change may proceed. It returns
// the reason if not: ErrNoSession if the account is no longer active,
// ErrWrongPassword if the password was replaced since it was verified, and a
// *LockedError if the account is locked after failed sign-ins, which only the
// correct password learns. The last two are recorded as failures of action.
func lockVerified(ctx context.Context, tx pgx.Tx, u user.User, p access.Principal, action audit.Action) (outcome, err error) {
	state, err := user.NewStore(tx).LockForSignIn(ctx, u.ID)
	if errors.Is(err, user.ErrNotFound) {
		return ErrNoSession, nil
	}
	if err != nil {
		return nil, err
	}
	switch {
	case state.Status != user.StatusActive:
		// The account was deactivated since the request was authenticated.
		return ErrNoSession, nil
	case state.PasswordHash != u.PasswordHash:
		outcome = ErrWrongPassword
	case state.RetryAfter > 0:
		outcome = &LockedError{RetryAfter: state.RetryAfter}
	default:
		return nil, nil
	}
	return outcome, audit.NewStore(tx).Record(ctx, accountEntry(ctx, action, audit.OutcomeFailure, p))
}

// rotate ends every session of u and starts a new one, which replaces the
// session sessionID of the caller, so that the user stays signed in while every
// other session, and every old token, stops working. The caller holds the lock
// of u. It returns ErrNoSession if the session of the caller ended since the
// request was authenticated, for example by a concurrent change of password:
// a revoked session must not obtain a new one.
func (s *Service) rotate(ctx context.Context, tx pgx.Tx, u user.User, sessionID string) (Session, string, error) {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT FROM sessions WHERE id = $1 AND user_id = $2)`, sessionID, u.ID).Scan(&exists)
	if err != nil {
		return Session{}, "", fmt.Errorf("look up session: %w", err)
	}
	if !exists {
		return Session{}, "", ErrNoSession
	}
	if err := RevokeAll(ctx, tx, u.ID); err != nil {
		return Session{}, "", err
	}
	return s.insert(ctx, tx, u)
}

// accountEntry records a change that the principal p made to their own account.
func accountEntry(ctx context.Context, action audit.Action, outcome audit.Outcome, p access.Principal) audit.Entry {
	return audit.Entry{
		Action:   action,
		Outcome:  outcome,
		Actor:    p.Actor(),
		Resource: audit.Resource{Type: "user", ID: p.UserID},
	}.WithRequest(ctx)
}

// Reauthenticated reports whether the user of the session sessionID, which
// belongs to the account userID, signed in at the identity provider again
// within ReauthenticationWindow. It returns ErrNoSession if there is no such
// session.
func Reauthenticated(ctx context.Context, q db.Querier, sessionID, userID string) (bool, error) {
	var fresh bool
	err := q.QueryRow(ctx, `
SELECT coalesce(reauthenticated_at > clock_timestamp() - $3::interval, false)
FROM sessions
WHERE id = $1 AND user_id = $2`, sessionID, userID, ReauthenticationWindow).Scan(&fresh)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNoSession
	}
	if err != nil {
		return false, fmt.Errorf("look up reauthentication of session: %w", err)
	}
	return fresh, nil
}

// MarkReauthenticated records that the user of the session sessionID, which
// belongs to the account userID, signed in at the identity provider again. It
// returns ErrNoSession if there is no such session.
func MarkReauthenticated(ctx context.Context, q db.Querier, sessionID, userID string) error {
	tag, err := q.Exec(ctx, `UPDATE sessions SET reauthenticated_at = clock_timestamp() WHERE id = $1 AND user_id = $2`,
		sessionID, userID)
	if err != nil {
		return fmt.Errorf("record reauthentication of session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSession
	}
	return nil
}

// RevokeAll ends every session of the account userID and every sign-in that
// waits for its second factor. It runs on q, so that a change that requires it,
// such as deactivating the account or changing its role or password, ends the
// sessions in its own transaction. A challenge ends with the sessions, so that a
// password that was replaced, or a second factor that was removed, cannot
// complete a sign-in that started before.
func RevokeAll(ctx context.Context, q db.Querier, userID string) error {
	if _, err := q.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("revoke sessions of user %s: %w", userID, err)
	}
	if _, err := q.Exec(ctx, `DELETE FROM sign_in_challenges WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("revoke sign-in challenges of user %s: %w", userID, err)
	}
	return nil
}
