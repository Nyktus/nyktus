// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package secondfactor_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/auth/secondfactor"
	"nyktus.org/nyktus/internal/auth/totp"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/platform/secretbox"
	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
)

type env struct {
	owner, console *pgxpool.Pool
	keys           *secretbox.Keyring
}

func newEnv(t *testing.T) env {
	t.Helper()
	ownerURL, consoleURL := schematest.Console(t)
	return env{owner: schematest.Open(t, ownerURL), console: schematest.Open(t, consoleURL), keys: secretboxtest.Keyring(t)}
}

// createUser creates an account. The store does not look at the account, so a
// pending one without a password serves.
func (e env) createUser(t *testing.T, email string) string {
	t.Helper()
	var id string
	err := e.owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status) VALUES ($1, 'Test User', 'viewer', 'pending')
RETURNING id`, email).Scan(&id)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return id
}

// in runs f in a transaction of the console role, as the callers of the store do.
func (e env) in(t *testing.T, keys *secretbox.Keyring, f func(s *secondfactor.Store) error) error {
	t.Helper()
	return pgx.BeginFunc(t.Context(), e.console, func(tx pgx.Tx) error {
		return f(secondfactor.NewStore(tx, keys))
	})
}

// step returns the current time step of the database.
func (e env) step(t *testing.T) int64 {
	t.Helper()
	var step int64
	if err := e.owner.QueryRow(t.Context(), `SELECT floor(extract(epoch FROM clock_timestamp()) / 30)::bigint`).Scan(&step); err != nil {
		t.Fatalf("query step: %v", err)
	}
	return step
}

// enable sets up and confirms a factor for userID and returns its secret and
// recovery codes.
func (e env) enable(t *testing.T, userID string) ([]byte, []string) {
	t.Helper()
	var (
		enrollment secondfactor.Enrollment
		codes      []string
	)
	err := e.in(t, e.keys, func(s *secondfactor.Store) error {
		var err error
		enrollment, err = s.Begin(t.Context(), userID)
		return err
	})
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	// The confirmation uses the code of the previous step, so that the tests can
	// use the codes of the current and the next one.
	err = e.in(t, e.keys, func(s *secondfactor.Store) error {
		var err error
		codes, err = s.Confirm(t.Context(), userID, totp.Code(enrollment.Secret, e.step(t)-1))
		return err
	})
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	return enrollment.Secret, codes
}

func (e env) verify(t *testing.T, userID string, proof secondfactor.Proof) error {
	t.Helper()
	return e.in(t, e.keys, func(s *secondfactor.Store) error { return s.Verify(t.Context(), userID, proof) })
}

func TestBegin_StoresTheSecretEncrypted(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	id := e.createUser(t, "ada@example.com")
	var enrollment secondfactor.Enrollment
	err := e.in(t, e.keys, func(s *secondfactor.Store) error {
		var err error
		enrollment, err = s.Begin(t.Context(), id)
		return err
	})
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	if len(enrollment.Secret) != totp.SecretSize {
		t.Errorf("secret has %d bytes, want %d", len(enrollment.Secret), totp.SecretSize)
	}
	if d := time.Until(enrollment.ExpiresAt); d < 9*time.Minute || d > 11*time.Minute {
		t.Errorf("ExpiresAt in %v, want about %v", d, secondfactor.EnrollmentTimeout)
	}
	var stored []byte
	if err := e.owner.QueryRow(t.Context(), `SELECT secret FROM totp_factors WHERE user_id = $1`, id).Scan(&stored); err != nil {
		t.Fatalf("read secret: %v", err)
	}
	if bytes.Contains(stored, enrollment.Secret) || stored[0] != e.keys.CurrentKeyID() {
		t.Errorf("stored secret is not encrypted with the current key")
	}
	if ok, err := secondfactor.NewStore(e.console, e.keys).Enabled(t.Context(), id); err != nil || ok {
		t.Errorf("Enabled() before the confirmation = %v, %v; want false", ok, err)
	}
}

func TestBegin_ReplacesAnUnconfirmedFactorButNotAConfirmedOne(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	id := e.createUser(t, "ada@example.com")
	var first, second secondfactor.Enrollment
	for _, en := range []*secondfactor.Enrollment{&first, &second} {
		err := e.in(t, e.keys, func(s *secondfactor.Store) error {
			var err error
			*en, err = s.Begin(t.Context(), id)
			return err
		})
		if err != nil {
			t.Fatalf("Begin() error = %v", err)
		}
	}
	// The first secret no longer confirms.
	err := e.in(t, e.keys, func(s *secondfactor.Store) error {
		_, err := s.Confirm(t.Context(), id, totp.Code(first.Secret, e.step(t)))
		return err
	})
	if !errors.Is(err, secondfactor.ErrWrongCode) {
		t.Errorf("Confirm() with the replaced secret error = %v, want ErrWrongCode", err)
	}

	other := e.createUser(t, "bob@example.com")
	e.enable(t, other)
	err = e.in(t, e.keys, func(s *secondfactor.Store) error {
		_, err := s.Begin(t.Context(), other)
		return err
	})
	if !errors.Is(err, secondfactor.ErrEnabled) {
		t.Errorf("Begin() with a confirmed factor error = %v, want ErrEnabled", err)
	}
}

func TestConfirm_IssuesRecoveryCodes(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	id := e.createUser(t, "ada@example.com")
	_, codes := e.enable(t, id)
	if len(codes) != totp.RecoveryCodeCount {
		t.Fatalf("got %d recovery codes, want %d", len(codes), totp.RecoveryCodeCount)
	}
	var stored int
	if err := e.owner.QueryRow(t.Context(), `SELECT count(*) FROM recovery_codes WHERE user_id = $1`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != totp.RecoveryCodeCount {
		t.Errorf("stored %d recovery codes, want %d", stored, totp.RecoveryCodeCount)
	}
	if ok, err := secondfactor.NewStore(e.console, e.keys).Enabled(t.Context(), id); err != nil || !ok {
		t.Errorf("Enabled() = %v, %v; want true", ok, err)
	}
}

func TestConfirm_RejectsWrongCodesAndExpiredSetups(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	id := e.createUser(t, "ada@example.com")
	var enrollment secondfactor.Enrollment
	err := e.in(t, e.keys, func(s *secondfactor.Store) error {
		var err error
		enrollment, err = s.Begin(t.Context(), id)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	confirm := func(code string) error {
		return e.in(t, e.keys, func(s *secondfactor.Store) error {
			_, err := s.Confirm(t.Context(), id, code)
			return err
		})
	}
	if err := confirm(totp.Code(enrollment.Secret, e.step(t)+3)); !errors.Is(err, secondfactor.ErrWrongCode) {
		t.Errorf("Confirm() with a code outside the skew error = %v, want ErrWrongCode", err)
	}
	if _, err := e.owner.Exec(t.Context(), `UPDATE totp_factors SET created_at = created_at - interval '11 minutes' WHERE user_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if err := confirm(totp.Code(enrollment.Secret, e.step(t))); !errors.Is(err, secondfactor.ErrNoEnrollment) {
		t.Errorf("Confirm() of an expired setup error = %v, want ErrNoEnrollment", err)
	}
}

func TestVerify_AcceptsACodeOnce(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	id := e.createUser(t, "ada@example.com")
	secret, _ := e.enable(t, id)
	step := e.step(t)

	code := totp.Code(secret, step)
	if err := e.verify(t, id, secondfactor.Proof{Code: code}); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if err := e.verify(t, id, secondfactor.Proof{Code: code}); !errors.Is(err, secondfactor.ErrWrongCode) {
		t.Errorf("Verify() with the same code again error = %v, want ErrWrongCode", err)
	}
	// The code of the previous step is older than the one used.
	if err := e.verify(t, id, secondfactor.Proof{Code: totp.Code(secret, step-1)}); !errors.Is(err, secondfactor.ErrWrongCode) {
		t.Errorf("Verify() with an older code error = %v, want ErrWrongCode", err)
	}
	if err := e.verify(t, id, secondfactor.Proof{Code: totp.Code(secret, step+1)}); err != nil {
		t.Errorf("Verify() with the code of the next step error = %v, want it accepted", err)
	}
}

func TestVerify_ConsumesARecoveryCode(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	id := e.createUser(t, "ada@example.com")
	_, codes := e.enable(t, id)

	// Case and grouping do not matter.
	typed := strings.ToUpper(strings.ReplaceAll(codes[0], "-", " "))
	if err := e.verify(t, id, secondfactor.Proof{RecoveryCode: typed}); err != nil {
		t.Fatalf("Verify() with a recovery code error = %v", err)
	}
	if err := e.verify(t, id, secondfactor.Proof{RecoveryCode: codes[0]}); !errors.Is(err, secondfactor.ErrWrongCode) {
		t.Errorf("Verify() with a used recovery code error = %v, want ErrWrongCode", err)
	}
	if err := e.verify(t, id, secondfactor.Proof{RecoveryCode: codes[1]}); err != nil {
		t.Errorf("Verify() with another recovery code error = %v", err)
	}

	// The codes of one account are no use for another.
	other := e.createUser(t, "bob@example.com")
	e.enable(t, other)
	if err := e.verify(t, other, secondfactor.Proof{RecoveryCode: codes[2]}); !errors.Is(err, secondfactor.ErrWrongCode) {
		t.Errorf("Verify() with the recovery code of another account error = %v, want ErrWrongCode", err)
	}
}

func TestVerify_RejectsInvalidProofs(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	id := e.createUser(t, "ada@example.com")
	if err := e.verify(t, id, secondfactor.Proof{Code: "123456"}); !errors.Is(err, secondfactor.ErrNotEnabled) {
		t.Errorf("Verify() without a factor error = %v, want ErrNotEnabled", err)
	}
	secret, codes := e.enable(t, id)
	code := totp.Code(secret, e.step(t))
	for _, p := range []secondfactor.Proof{{}, {Code: code, RecoveryCode: codes[0]}} {
		if err := e.verify(t, id, p); !errors.Is(err, secondfactor.ErrWrongCode) {
			t.Errorf("Verify(%+v) error = %v, want ErrWrongCode", p, err)
		}
	}
}

// A secret is bound to its account: copied into the row of another account, it
// does not decrypt.
func TestVerify_SecretIsBoundToItsAccount(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	ada, bob := e.createUser(t, "ada@example.com"), e.createUser(t, "bob@example.com")
	secret, _ := e.enable(t, ada)
	e.enable(t, bob)
	if _, err := e.owner.Exec(t.Context(),
		`UPDATE totp_factors SET secret = (SELECT secret FROM totp_factors WHERE user_id = $1) WHERE user_id = $2`, ada, bob); err != nil {
		t.Fatal(err)
	}
	err := e.verify(t, bob, secondfactor.Proof{Code: totp.Code(secret, e.step(t))})
	if !errors.Is(err, secretbox.ErrInvalid) {
		t.Errorf("Verify() with a copied secret error = %v, want a decryption failure", err)
	}
}

// After a new key is added, a verified code encrypts the secret again with it,
// so that the old key can eventually be removed.
func TestVerify_EncryptsTheSecretWithTheCurrentKey(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	oldEntry := secretboxtest.Entry(t, 1)
	old, err := secretbox.ParseKeyring(oldEntry)
	if err != nil {
		t.Fatal(err)
	}
	e.keys = old
	id := e.createUser(t, "ada@example.com")
	secret, _ := e.enable(t, id)

	newEntry := secretboxtest.Entry(t, 2)
	rotated, err := secretbox.ParseKeyring(newEntry + "," + oldEntry)
	if err != nil {
		t.Fatal(err)
	}
	if err := secondfactor.CheckKeys(t.Context(), e.console, rotated); err != nil {
		t.Errorf("CheckKeys() with the old key listed error = %v", err)
	}
	err = e.in(t, rotated, func(s *secondfactor.Store) error {
		return s.Verify(t.Context(), id, secondfactor.Proof{Code: totp.Code(secret, e.step(t))})
	})
	if err != nil {
		t.Fatalf("Verify() with the rotated keyring error = %v", err)
	}
	var keyID int
	if err := e.owner.QueryRow(t.Context(), `SELECT get_byte(secret, 0) FROM totp_factors WHERE user_id = $1`, id).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	if keyID != 2 {
		t.Errorf("secret encrypted with key %d after the use, want the current key 2", keyID)
	}
	// No secret needs the old key any more.
	onlyNew, err := secretbox.ParseKeyring(newEntry)
	if err != nil {
		t.Fatal(err)
	}
	if err := secondfactor.CheckKeys(t.Context(), e.console, onlyNew); err != nil {
		t.Errorf("CheckKeys() without the old key error = %v", err)
	}
}

func TestCheckKeys_RejectsSecretsOfUnlistedKeys(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	if err := secondfactor.CheckKeys(t.Context(), e.console, e.keys); err != nil {
		t.Errorf("CheckKeys() without secrets error = %v", err)
	}
	e.enable(t, e.createUser(t, "ada@example.com"))
	if err := secondfactor.CheckKeys(t.Context(), e.console, e.keys); err != nil {
		t.Errorf("CheckKeys() with the key listed error = %v", err)
	}
	other, err := secretbox.ParseKeyring(secretboxtest.Entry(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	err = secondfactor.CheckKeys(t.Context(), e.console, other)
	if err == nil || !strings.Contains(err.Error(), "key ID 1, which is not configured") {
		t.Errorf("CheckKeys() without the key in use error = %v, want it to name key 1", err)
	}
}

func TestRemove_RemovesTheFactorWithItsRecoveryCodes(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	id := e.createUser(t, "ada@example.com")
	if removed, err := secondfactor.Remove(t.Context(), e.console, id); err != nil || removed {
		t.Errorf("Remove() without a factor = %v, %v; want false", removed, err)
	}
	e.enable(t, id)
	if removed, err := secondfactor.Remove(t.Context(), e.console, id); err != nil || !removed {
		t.Errorf("Remove() = %v, %v; want true", removed, err)
	}
	var factors, codes int
	err := e.owner.QueryRow(context.WithoutCancel(t.Context()), `
SELECT (SELECT count(*) FROM totp_factors WHERE user_id = $1), (SELECT count(*) FROM recovery_codes WHERE user_id = $1)`, id).Scan(&factors, &codes)
	if err != nil {
		t.Fatal(err)
	}
	if factors != 0 || codes != 0 {
		t.Errorf("after Remove(): %d factors, %d recovery codes; want none", factors, codes)
	}
}

// Values that the store never writes are rejected by the schema.
func TestSchema_RejectsInvalidFactors(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	id := e.createUser(t, "ada@example.com")
	for name, tt := range map[string]struct{ sql, constraint string }{
		"short secret": {
			`INSERT INTO totp_factors (user_id, secret) VALUES ($1, decode(repeat('01', 48), 'hex'))`, "totp_factors_secret_check",
		},
		"secret without key": {
			`INSERT INTO totp_factors (user_id, secret) VALUES ($1, decode(repeat('00', 49), 'hex'))`, "totp_factors_secret_check",
		},
		"confirmed without a used step": {
			`INSERT INTO totp_factors (user_id, secret, confirmed_at) VALUES ($1, decode(repeat('01', 49), 'hex'), clock_timestamp())`,
			"totp_factors_confirmed_check",
		},
		"used step without confirmation": {
			`INSERT INTO totp_factors (user_id, secret, last_used_step) VALUES ($1, decode(repeat('01', 49), 'hex'), 1)`,
			"totp_factors_confirmed_check",
		},
		"recovery code without a factor": {
			`INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, sha256('\x00'::bytea))`, "recovery_codes_user_id_fkey",
		},
		"short challenge hash": {
			`INSERT INTO sign_in_challenges (token_hash, user_id) VALUES ('\x00'::bytea, $1)`, "sign_in_challenges_token_hash_check",
		},
	} {
		_, err := e.owner.Exec(t.Context(), tt.sql, id)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.ConstraintName != tt.constraint {
			t.Errorf("%s: error = %v, want a violation of %s", name, err, tt.constraint)
		}
	}
}

// A user who signs in only with recovery codes does not keep an old key in use.
func TestVerify_RecoveryCodeEncryptsTheSecretWithTheCurrentKey(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	oldEntry := secretboxtest.Entry(t, 1)
	old, err := secretbox.ParseKeyring(oldEntry)
	if err != nil {
		t.Fatal(err)
	}
	e.keys = old
	id := e.createUser(t, "ada@example.com")
	_, codes := e.enable(t, id)

	rotated, err := secretbox.ParseKeyring(secretboxtest.Entry(t, 2) + "," + oldEntry)
	if err != nil {
		t.Fatal(err)
	}
	err = e.in(t, rotated, func(s *secondfactor.Store) error {
		return s.Verify(t.Context(), id, secondfactor.Proof{RecoveryCode: codes[0]})
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	var keyID int
	if err := e.owner.QueryRow(t.Context(), `SELECT get_byte(secret, 0) FROM totp_factors WHERE user_id = $1`, id).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	if keyID != 2 {
		t.Errorf("secret encrypted with key %d after a recovery code, want the current key 2", keyID)
	}
}

// A setup that expired unconfirmed cannot be used, so its key does not keep
// the console from starting.
func TestCheckKeys_IgnoresExpiredSetups(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	id := e.createUser(t, "ada@example.com")
	err := e.in(t, e.keys, func(s *secondfactor.Store) error {
		_, err := s.Begin(t.Context(), id)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := secretbox.ParseKeyring(secretboxtest.Entry(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	if err := secondfactor.CheckKeys(t.Context(), e.console, other); err == nil {
		t.Error("CheckKeys() accepted a running setup under a missing key")
	}
	if _, err := e.owner.Exec(t.Context(), `UPDATE totp_factors SET created_at = created_at - interval '11 minutes'`); err != nil {
		t.Fatal(err)
	}
	if err := secondfactor.CheckKeys(t.Context(), e.console, other); err != nil {
		t.Errorf("CheckKeys() with an expired setup under a missing key error = %v", err)
	}
}
