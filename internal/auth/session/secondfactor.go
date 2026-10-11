// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/auth/secondfactor"
	"nyktus.org/nyktus/internal/auth/token"
	"nyktus.org/nyktus/internal/auth/totp"
	"nyktus.org/nyktus/internal/user"
)

// issuer names Nyktus in authenticator apps.
const issuer = "Nyktus"

// Errors of the second factor.
var (
	// ErrInvalidChallenge means that a challenge is unknown, expired or no
	// longer valid, because the password was replaced, the second factor was
	// removed or the account was locked meanwhile. The user signs in again.
	ErrInvalidChallenge = errors.New("invalid sign-in challenge")
	// ErrWrongCode means that a code or recovery code was not accepted.
	ErrWrongCode = errors.New("wrong code")
)

// Challenge lets the holder of the token complete a sign-in with the second
// factor. Only its hash is stored.
type Challenge struct {
	Token     string
	ExpiresAt time.Time
}

// issueChallenge stores a new challenge for the account userID and removes its
// expired ones.
func issueChallenge(ctx context.Context, tx pgx.Tx, userID string) (*Challenge, error) {
	if _, err := tx.Exec(ctx, `DELETE FROM sign_in_challenges WHERE user_id = $1 AND expires_at <= clock_timestamp()`, userID); err != nil {
		return nil, fmt.Errorf("delete expired sign-in challenges: %w", err)
	}
	tok, err := token.New()
	if err != nil {
		return nil, err
	}
	c := &Challenge{Token: tok}
	// The database sets the expiry.
	err = tx.QueryRow(ctx, `INSERT INTO sign_in_challenges (token_hash, user_id) VALUES ($1, $2) RETURNING expires_at`,
		token.Hash(tok), userID).Scan(&c.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("insert sign-in challenge: %w", err)
	}
	c.ExpiresAt = c.ExpiresAt.UTC()
	return c, nil
}

// CompleteSignIn completes the sign-in that the challenge tok started with a
// proof of the second factor, and starts a session. previous is the token of a
// session that the client still holds, as for SignIn.
//
// It returns ErrInvalidChallenge if the challenge is not valid, ErrWrongCode if
// the proof is wrong and a *LockedError if the account is locked; the challenge
// proves the password, so the lock may be revealed. A wrong proof counts as a
// failed sign-in, so that the codes fall under the same lock as the password.
// The challenge stays valid after a wrong proof, so that a mistyped code does
// not cost the password again; it ends with the session it starts, with the
// lock, and after its lifetime. Every attempt with a valid challenge is
// recorded in the audit log.
func (s *Service) CompleteSignIn(ctx context.Context, tok string, proof secondfactor.Proof, previous string) (Session, string, error) {
	hash := token.Hash(tok)
	var userID string
	err := s.db.QueryRow(ctx, `SELECT user_id FROM sign_in_challenges WHERE token_hash = $1 AND expires_at > clock_timestamp()`,
		hash).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, "", ErrInvalidChallenge
	}
	if err != nil {
		return Session{}, "", fmt.Errorf("look up sign-in challenge: %w", err)
	}

	actor := audit.Actor{Kind: audit.ActorUser, Method: proof.Method(), UserID: userID}
	var (
		sess    Session
		newTok  string
		outcome error
	)
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		users := user.NewStore(tx)
		// The account is locked before its challenge is checked again, in the
		// same order as every change of the account, which removes challenges
		// while it holds the account.
		state, err := users.LockForSignIn(ctx, userID)
		if errors.Is(err, user.ErrNotFound) {
			outcome = ErrInvalidChallenge
			return nil
		}
		if err != nil {
			return err
		}
		var valid bool
		err = tx.QueryRow(ctx, `
SELECT EXISTS (SELECT FROM sign_in_challenges WHERE token_hash = $1 AND user_id = $2 AND expires_at > clock_timestamp())`,
			hash, userID).Scan(&valid)
		if err != nil {
			return fmt.Errorf("look up sign-in challenge: %w", err)
		}
		if !valid || state.Status != user.StatusActive {
			outcome = ErrInvalidChallenge
			return nil
		}
		if state.RetryAfter > 0 {
			outcome = &LockedError{RetryAfter: state.RetryAfter}
			return s.failSecondFactor(ctx, tx, hash, actor)
		}

		err = secondfactor.NewStore(tx, s.keys).Verify(ctx, userID, proof)
		switch {
		case errors.Is(err, secondfactor.ErrNotEnabled):
			// Removing the factor removes the challenges as well, so this means
			// a bug. The sign-in starts again with the password.
			outcome = ErrInvalidChallenge
			_, err := tx.Exec(ctx, `DELETE FROM sign_in_challenges WHERE token_hash = $1`, hash)
			return err
		case errors.Is(err, secondfactor.ErrWrongCode):
			if err := users.RecordFailedLogin(ctx, userID); err != nil {
				return err
			}
			// The failure may have locked the account. Then the challenge ends,
			// and the response reveals the lock.
			state, err := users.LockForSignIn(ctx, userID)
			if err != nil {
				return err
			}
			if state.RetryAfter > 0 {
				outcome = &LockedError{RetryAfter: state.RetryAfter}
				return s.failSecondFactor(ctx, tx, hash, actor)
			}
			outcome = ErrWrongCode
			return audit.NewStore(tx).Record(ctx, signInEntry(ctx, audit.OutcomeFailure, actor, ""))
		case err != nil:
			return err
		}

		if err := users.CompleteSignIn(ctx, userID, ""); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM sign_in_challenges WHERE token_hash = $1`, hash); err != nil {
			return fmt.Errorf("delete sign-in challenge: %w", err)
		}
		u, err := users.Get(ctx, userID)
		if err != nil {
			return err
		}
		sess, newTok, err = s.start(ctx, tx, u, previous)
		if err != nil {
			return err
		}
		return audit.NewStore(tx).Record(ctx, signInEntry(ctx, audit.OutcomeSuccess, actor, sess.ID))
	})
	if err != nil {
		return Session{}, "", fmt.Errorf("complete sign-in: %w", err)
	}
	if outcome != nil {
		return Session{}, "", outcome
	}
	return sess, newTok, nil
}

// failSecondFactor ends the challenge hash of a locked account and records the
// failed sign-in.
func (s *Service) failSecondFactor(ctx context.Context, tx pgx.Tx, hash []byte, actor audit.Actor) error {
	if _, err := tx.Exec(ctx, `DELETE FROM sign_in_challenges WHERE token_hash = $1`, hash); err != nil {
		return fmt.Errorf("delete sign-in challenge: %w", err)
	}
	return audit.NewStore(tx).Record(ctx, signInEntry(ctx, audit.OutcomeFailure, actor, ""))
}

// TOTPSetup is a new TOTP factor that waits for its confirmation. Secret and URI
// carry the secret; they are shown to the user once.
type TOTPSetup struct {
	// Secret is the secret in base32, for typing it into an authenticator app.
	Secret string
	// URI is the otpauth URI, usually shown as a QR code.
	URI       string
	ExpiresAt time.Time
}

// String keeps the secret out of formatted output.
func (TOTPSetup) String() string { return "TOTP setup" }

// GoString keeps the secret out of %#v.
func (t TOTPSetup) GoString() string { return t.String() }

// BeginTOTP starts the setup of a TOTP factor for the signed-in principal p, who
// confirms it with their password, so that a taken-over session cannot bind the
// account to an authenticator of the attacker. An unconfirmed setup is replaced.
// It returns secondfactor.ErrEnabled if the account already has a factor, and
// fails with a wrong password or a lock as ChangePassword does.
func (s *Service) BeginTOTP(ctx context.Context, p access.Principal, password string) (TOTPSetup, error) {
	u, err := s.verifyCurrentPassword(ctx, p, password, audit.ActionUserTOTPEnroll)
	if err != nil {
		return TOTPSetup{}, err
	}
	var (
		setup   TOTPSetup
		outcome error
	)
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		outcome, err = lockVerified(ctx, tx, u, p, audit.ActionUserTOTPEnroll)
		if err != nil || outcome != nil {
			return err
		}
		enrollment, err := secondfactor.NewStore(tx, s.keys).Begin(ctx, u.ID)
		if errors.Is(err, secondfactor.ErrEnabled) {
			outcome = err
			return audit.NewStore(tx).Record(ctx, accountEntry(ctx, audit.ActionUserTOTPEnroll, audit.OutcomeFailure, p))
		}
		if err != nil {
			return err
		}
		setup = TOTPSetup{
			Secret:    totp.EncodeSecret(enrollment.Secret),
			URI:       totp.URI(issuer, u.Email, enrollment.Secret),
			ExpiresAt: enrollment.ExpiresAt,
		}
		return audit.NewStore(tx).Record(ctx, accountEntry(ctx, audit.ActionUserTOTPEnroll, audit.OutcomeSuccess, p))
	})
	if err != nil {
		return TOTPSetup{}, fmt.Errorf("begin TOTP setup: %w", err)
	}
	if outcome != nil {
		return TOTPSetup{}, outcome
	}
	return setup, nil
}

// ConfirmTOTP confirms the TOTP factor that p set up with BeginTOTP with a first
// code, which proves that the authenticator holds the secret, and returns the
// recovery codes. From then on, signing in takes a code. Every other session
// of the account ends, because it began without the second factor; the session
// of p is replaced by the returned one, as on a change of password.
//
// It returns secondfactor.ErrNoEnrollment if there is no setup to confirm and
// ErrWrongCode if the code does not match. A wrong code counts as a failed
// sign-in, and a locked account cannot confirm, so that a taken-over session
// cannot guess the code of a setup and obtain the recovery codes.
func (s *Service) ConfirmTOTP(ctx context.Context, p access.Principal, code string) ([]string, Session, string, error) {
	var (
		codes   []string
		sess    Session
		tok     string
		outcome error
	)
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		users := user.NewStore(tx)
		state, err := users.LockForSignIn(ctx, p.UserID)
		if errors.Is(err, user.ErrNotFound) || (err == nil && state.Status != user.StatusActive) {
			outcome = ErrNoSession
			return nil
		}
		if err != nil {
			return err
		}
		if state.RetryAfter > 0 {
			outcome = &LockedError{RetryAfter: state.RetryAfter}
			return audit.NewStore(tx).Record(ctx, accountEntry(ctx, audit.ActionUserTOTPEnable, audit.OutcomeFailure, p))
		}
		codes, err = secondfactor.NewStore(tx, s.keys).Confirm(ctx, p.UserID, code)
		switch {
		case errors.Is(err, secondfactor.ErrNoEnrollment):
			outcome = err
			return audit.NewStore(tx).Record(ctx, accountEntry(ctx, audit.ActionUserTOTPEnable, audit.OutcomeFailure, p))
		case errors.Is(err, secondfactor.ErrWrongCode):
			outcome = ErrWrongCode
			if err := users.RecordFailedLogin(ctx, p.UserID); err != nil {
				return err
			}
			return audit.NewStore(tx).Record(ctx, accountEntry(ctx, audit.ActionUserTOTPEnable, audit.OutcomeFailure, p))
		case err != nil:
			return err
		}
		u, err := users.Get(ctx, p.UserID)
		if err != nil {
			return err
		}
		sess, tok, err = s.rotate(ctx, tx, u, p.SessionID)
		if err != nil {
			return err
		}
		return audit.NewStore(tx).Record(ctx, accountEntry(ctx, audit.ActionUserTOTPEnable, audit.OutcomeSuccess, p))
	})
	if err != nil {
		return nil, Session{}, "", fmt.Errorf("confirm TOTP factor: %w", err)
	}
	if outcome != nil {
		return nil, Session{}, "", outcome
	}
	return codes, sess, tok, nil
}

// ReplaceRecoveryCodes replaces the recovery codes of p with new ones. p
// confirms with their password and a proof of the second factor, so that
// neither a taken-over session nor the password alone yields new codes.
//
// A wrong proof counts as a failed sign-in and returns ErrWrongCode. It returns
// secondfactor.ErrNotEnabled if the account has no factor, and fails with a
// wrong password or a lock as ChangePassword does.
func (s *Service) ReplaceRecoveryCodes(ctx context.Context, p access.Principal, password string, proof secondfactor.Proof) ([]string, error) {
	const action = audit.ActionUserRecoveryCodesCreate
	var codes []string
	err := s.withSecondFactor(ctx, p, password, proof, action, func(tx pgx.Tx, _ user.User) error {
		var err error
		codes, err = secondfactor.NewStore(tx, s.keys).ReplaceRecoveryCodes(ctx, p.UserID)
		if err != nil {
			return err
		}
		return audit.NewStore(tx).Record(ctx, accountEntry(ctx, action, audit.OutcomeSuccess, p))
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// RemoveTOTP removes the TOTP factor of p with the recovery codes, after the
// same confirmation as ReplaceRecoveryCodes. Every session of the account ends;
// the session of p is replaced by the returned one, as on a change of password.
func (s *Service) RemoveTOTP(ctx context.Context, p access.Principal, password string, proof secondfactor.Proof) (Session, string, error) {
	const action = audit.ActionUserTOTPDisable
	var (
		sess Session
		tok  string
	)
	err := s.withSecondFactor(ctx, p, password, proof, action, func(tx pgx.Tx, u user.User) error {
		if _, err := secondfactor.Remove(ctx, tx, p.UserID); err != nil {
			return err
		}
		u.TOTPEnabled = false
		var err error
		sess, tok, err = s.rotate(ctx, tx, u, p.SessionID)
		if err != nil {
			return err
		}
		return audit.NewStore(tx).Record(ctx, accountEntry(ctx, action, audit.OutcomeSuccess, p))
	})
	if err != nil {
		return Session{}, "", err
	}
	return sess, tok, nil
}

// withSecondFactor verifies the password of p and, under the lock of the
// account, the proof of the second factor, then runs change in the same
// transaction. Failures are recorded as action.
func (s *Service) withSecondFactor(ctx context.Context, p access.Principal, password string, proof secondfactor.Proof,
	action audit.Action, change func(tx pgx.Tx, u user.User) error,
) error {
	u, err := s.verifyCurrentPassword(ctx, p, password, action)
	if err != nil {
		return err
	}
	var outcome error
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		outcome, err = lockVerified(ctx, tx, u, p, action)
		if err != nil || outcome != nil {
			return err
		}
		err = secondfactor.NewStore(tx, s.keys).Verify(ctx, u.ID, proof)
		switch {
		case errors.Is(err, secondfactor.ErrNotEnabled):
			outcome = err
			return audit.NewStore(tx).Record(ctx, accountEntry(ctx, action, audit.OutcomeFailure, p))
		case errors.Is(err, secondfactor.ErrWrongCode):
			outcome = ErrWrongCode
			if err := user.NewStore(tx).RecordFailedLogin(ctx, u.ID); err != nil {
				return err
			}
			return audit.NewStore(tx).Record(ctx, accountEntry(ctx, action, audit.OutcomeFailure, p))
		case err != nil:
			return err
		}
		return change(tx, u)
	})
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	return outcome
}
