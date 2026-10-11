// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package secondfactor stores the TOTP factors and recovery codes of accounts
// and checks the codes that a user enters.
//
// A factor is set up in two steps: the user receives a new secret, adds it to an
// authenticator app and confirms it with a first code. Only a confirmed factor
// protects the sign-in. The confirmation issues recovery codes, each of which
// replaces a code once.
//
// The secret is encrypted with a key from the configuration, bound to the
// account, so that the database alone does not reveal it. Codes are checked
// against the time of the database, and a code is accepted only for a later
// time step than the last accepted one, so that it cannot be used twice.
//
// The store does not lock the account. Callers lock it first, as every change
// of an account does, so that two checks of the same code cannot both succeed.
package secondfactor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/token"
	"nyktus.org/nyktus/internal/auth/totp"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/secretbox"
)

// EnrollmentTimeout is how long an unconfirmed factor can be confirmed.
const EnrollmentTimeout = 10 * time.Minute

// Errors of the store.
var (
	// ErrEnabled means that the account already has a confirmed factor.
	ErrEnabled = errors.New("a TOTP factor is already enabled")
	// ErrNoEnrollment means that the account has no unconfirmed factor that
	// can still be confirmed.
	ErrNoEnrollment = errors.New("no TOTP setup in progress")
	// ErrNotEnabled means that the account has no confirmed factor.
	ErrNotEnabled = errors.New("no TOTP factor is enabled")
	// ErrWrongCode means that a code or recovery code was not accepted.
	ErrWrongCode = errors.New("wrong code")
)

// Proof is what a user enters to prove their second factor: a code of the
// authenticator app or a recovery code. Exactly one of them is set.
type Proof struct {
	Code         string
	RecoveryCode string
}

// Method returns the method by which the proof authenticates, for the audit
// log.
func (p Proof) Method() audit.AuthMethod {
	if p.RecoveryCode != "" {
		return audit.AuthRecoveryCode
	}
	return audit.AuthTOTP
}

// LogValue keeps the codes out of logs.
func (p Proof) LogValue() slog.Value {
	return slog.StringValue(string(p.Method()))
}

// Valid reports whether exactly one of the fields is set.
func (p Proof) Valid() bool {
	return (p.Code == "") != (p.RecoveryCode == "")
}

// Store keeps the factors in PostgreSQL.
type Store struct {
	db   db.Querier
	keys *secretbox.Keyring
}

// NewStore returns a Store that runs its queries on q and encrypts secrets with
// keys.
func NewStore(q db.Querier, keys *secretbox.Keyring) *Store {
	if q == nil || keys == nil {
		panic("secondfactor: store needs a querier and a keyring")
	}
	return &Store{db: q, keys: keys}
}

// associatedData binds an encrypted secret to its account.
func associatedData(userID string) []byte {
	return []byte("totp:" + userID)
}

// Enabled reports whether the account userID has a confirmed factor.
func (s *Store) Enabled(ctx context.Context, userID string) (bool, error) {
	var enabled bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS (SELECT FROM totp_factors WHERE user_id = $1 AND confirmed_at IS NOT NULL)`, userID).Scan(&enabled)
	if err != nil {
		return false, fmt.Errorf("check TOTP factor of user %s: %w", userID, err)
	}
	return enabled, nil
}

// Enrollment is a new, unconfirmed factor. Secret is shown to the user once.
type Enrollment struct {
	Secret    []byte
	ExpiresAt time.Time
}

// Begin replaces an unconfirmed factor of the account userID with a new one. It
// returns ErrEnabled if the account has a confirmed factor.
func (s *Store) Begin(ctx context.Context, userID string) (Enrollment, error) {
	enabled, err := s.Enabled(ctx, userID)
	if err != nil {
		return Enrollment{}, err
	}
	if enabled {
		return Enrollment{}, ErrEnabled
	}
	secret, err := totp.NewSecret()
	if err != nil {
		return Enrollment{}, err
	}
	sealed, err := s.keys.Seal(secret, associatedData(userID))
	if err != nil {
		return Enrollment{}, err
	}
	if _, err := s.db.Exec(ctx, `DELETE FROM totp_factors WHERE user_id = $1`, userID); err != nil {
		return Enrollment{}, fmt.Errorf("delete unconfirmed TOTP factor of user %s: %w", userID, err)
	}
	var createdAt time.Time
	err = s.db.QueryRow(ctx, `INSERT INTO totp_factors (user_id, secret) VALUES ($1, $2) RETURNING created_at`,
		userID, sealed).Scan(&createdAt)
	if err != nil {
		return Enrollment{}, fmt.Errorf("insert TOTP factor of user %s: %w", userID, err)
	}
	return Enrollment{Secret: secret, ExpiresAt: createdAt.Add(EnrollmentTimeout).UTC()}, nil
}

// Confirm confirms the unconfirmed factor of the account userID with code and
// returns new recovery codes, which are shown to the user once. It returns
// ErrNoEnrollment if there is no factor to confirm, or the setup expired, and
// ErrWrongCode if the code does not match.
func (s *Store) Confirm(ctx context.Context, userID, code string) ([]string, error) {
	var sealed []byte
	var step int64
	err := s.db.QueryRow(ctx, `
SELECT secret, floor(extract(epoch FROM clock_timestamp()) / $3)::bigint
FROM totp_factors
WHERE user_id = $1 AND confirmed_at IS NULL AND created_at > clock_timestamp() - $2::interval
FOR UPDATE`, userID, EnrollmentTimeout, int64(totp.Period/time.Second)).Scan(&sealed, &step)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoEnrollment
	}
	if err != nil {
		return nil, fmt.Errorf("look up TOTP setup of user %s: %w", userID, err)
	}
	secret, err := s.keys.Open(sealed, associatedData(userID))
	if err != nil {
		return nil, fmt.Errorf("decrypt TOTP secret of user %s: %w", userID, err)
	}
	matched, ok := totp.Match(secret, code, step, -1)
	if !ok {
		return nil, ErrWrongCode
	}
	_, err = s.db.Exec(ctx, `UPDATE totp_factors SET confirmed_at = clock_timestamp(), last_used_step = $2 WHERE user_id = $1`,
		userID, matched)
	if err != nil {
		return nil, fmt.Errorf("confirm TOTP factor of user %s: %w", userID, err)
	}
	return s.ReplaceRecoveryCodes(ctx, userID)
}

// ReplaceRecoveryCodes replaces the recovery codes of the confirmed factor of
// the account userID with new ones and returns them.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	codes, err := totp.NewRecoveryCodes()
	if err != nil {
		return nil, err
	}
	hashes := make([][]byte, len(codes))
	for i, c := range codes {
		normalized, ok := totp.NormalizeRecoveryCode(c)
		if !ok {
			return nil, errors.New("generated recovery code is malformed")
		}
		hashes[i] = token.Hash(normalized)
	}
	if _, err := s.db.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID); err != nil {
		return nil, fmt.Errorf("delete recovery codes of user %s: %w", userID, err)
	}
	_, err = s.db.Exec(ctx, `INSERT INTO recovery_codes (user_id, code_hash) SELECT $1, h FROM unnest($2::bytea[]) AS h`,
		userID, hashes)
	if err != nil {
		return nil, fmt.Errorf("insert recovery codes of user %s: %w", userID, err)
	}
	return codes, nil
}

// Verify checks proof against the confirmed factor of the account userID. A
// TOTP code is accepted only for a time step after the last accepted one, which
// it then becomes; a recovery code is consumed. It returns ErrNotEnabled if the
// account has no confirmed factor and ErrWrongCode if the proof does not match.
//
// The caller holds the lock of the account, so that two requests with the same
// code are checked one after the other.
func (s *Store) Verify(ctx context.Context, userID string, proof Proof) error {
	if !proof.Valid() {
		return ErrWrongCode
	}
	var (
		sealed   []byte
		lastUsed int64
		step     int64
	)
	err := s.db.QueryRow(ctx, `
SELECT secret, last_used_step, floor(extract(epoch FROM clock_timestamp()) / $2)::bigint
FROM totp_factors
WHERE user_id = $1 AND confirmed_at IS NOT NULL`, userID, int64(totp.Period/time.Second)).Scan(&sealed, &lastUsed, &step)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotEnabled
	}
	if err != nil {
		return fmt.Errorf("look up TOTP factor of user %s: %w", userID, err)
	}

	if proof.RecoveryCode != "" {
		if err := s.consumeRecoveryCode(ctx, userID, proof.RecoveryCode); err != nil {
			return err
		}
		// A recovery code does not need the secret, so it works even if the
		// secret cannot be decrypted; only the new encryption is skipped then.
		if secret, err := s.keys.Open(sealed, associatedData(userID)); err == nil {
			return s.reseal(ctx, userID, sealed, secret)
		}
		return nil
	}
	secret, err := s.keys.Open(sealed, associatedData(userID))
	if err != nil {
		return fmt.Errorf("decrypt TOTP secret of user %s: %w", userID, err)
	}
	matched, ok := totp.Match(secret, proof.Code, step, lastUsed)
	if !ok {
		return ErrWrongCode
	}
	// The row is written anyway, so a secret under a replaced key is encrypted
	// with the current key on the way, until the old key is no longer needed.
	if s.keys.NeedsReseal(sealed) {
		sealed, err = s.keys.Seal(secret, associatedData(userID))
		if err != nil {
			return err
		}
	}
	// The condition on the step makes the update the arbiter, should a caller
	// ever check without the lock of the account.
	tag, err := s.db.Exec(ctx, `UPDATE totp_factors SET last_used_step = $2, secret = $3 WHERE user_id = $1 AND last_used_step < $2`,
		userID, matched, sealed)
	if err != nil {
		return fmt.Errorf("record use of TOTP factor of user %s: %w", userID, err)
	}
	if tag.RowsAffected() != 1 {
		return ErrWrongCode
	}
	return nil
}

// reseal encrypts the secret of the account userID again with the current key
// if it was encrypted with another one, so that a user who signs in only with
// recovery codes does not keep an old key in use.
func (s *Store) reseal(ctx context.Context, userID string, sealed, secret []byte) error {
	if !s.keys.NeedsReseal(sealed) {
		return nil
	}
	resealed, err := s.keys.Seal(secret, associatedData(userID))
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(ctx, `UPDATE totp_factors SET secret = $2 WHERE user_id = $1`, userID, resealed); err != nil {
		return fmt.Errorf("encrypt TOTP secret of user %s again: %w", userID, err)
	}
	return nil
}

func (s *Store) consumeRecoveryCode(ctx context.Context, userID, code string) error {
	normalized, ok := totp.NormalizeRecoveryCode(code)
	if !ok {
		return ErrWrongCode
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1 AND code_hash = $2`, userID, token.Hash(normalized))
	if err != nil {
		return fmt.Errorf("consume recovery code of user %s: %w", userID, err)
	}
	if tag.RowsAffected() != 1 {
		return ErrWrongCode
	}
	return nil
}

// Remove removes the factor of the account userID, confirmed or not, with its
// recovery codes, on q. It reports whether a confirmed factor was removed. It
// needs no keys, so that the command line can remove a factor without them.
func Remove(ctx context.Context, q db.Querier, userID string) (bool, error) {
	var confirmed bool
	err := q.QueryRow(ctx, `DELETE FROM totp_factors WHERE user_id = $1 RETURNING confirmed_at IS NOT NULL`, userID).Scan(&confirmed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("delete TOTP factor of user %s: %w", userID, err)
	}
	return confirmed, nil
}

// CheckKeys returns an error if a stored secret was encrypted with a key that
// keys does not hold. Such a secret could never be decrypted, and its user could
// no longer sign in, so the console refuses to start until the key is listed
// again.
func CheckKeys(ctx context.Context, q db.Querier, keys *secretbox.Keyring) error {
	// A setup that expired unconfirmed can never be used and is replaced by
	// the next one, so its key does not matter.
	rows, err := q.Query(ctx, `
SELECT DISTINCT get_byte(secret, 0) FROM totp_factors
WHERE confirmed_at IS NOT NULL OR created_at > clock_timestamp() - $1::interval`, EnrollmentTimeout)
	if err != nil {
		return fmt.Errorf("list encryption keys in use: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int32])
	if err != nil {
		return fmt.Errorf("list encryption keys in use: %w", err)
	}
	for _, id := range ids {
		if id < 1 || id > 255 || !keys.Has(byte(id)) {
			return fmt.Errorf("stored TOTP secrets are encrypted with the key ID %d, which is not configured; add the key back to NYKTUS_ENCRYPTION_KEYS", id)
		}
	}
	return nil
}
