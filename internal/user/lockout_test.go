// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/platform/schematest"
)

// lockoutUser creates an active account and returns the store as the console's
// database role, a pool of the owner and the account's ID.
func lockoutUser(t *testing.T) (*Store, *pgxpool.Pool, string) {
	t.Helper()
	ownerURL, consoleURL := schematest.Console(t)
	s := NewStore(schematest.Open(t, consoleURL))
	u, err := s.Create(t.Context(), NewUser{Email: "ada@example.com", DisplayName: "Ada", Role: RoleAdmin, PasswordHash: testHash})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	return s, schematest.Open(t, ownerURL), u.ID
}

type lockout struct {
	failures int
	locked   bool
	// remaining is the time until the lock ends.
	remaining time.Duration
}

func readLockout(t *testing.T, owner *pgxpool.Pool, id string) lockout {
	t.Helper()
	var (
		l       lockout
		seconds float64
	)
	err := owner.QueryRow(t.Context(), `
SELECT failed_logins, coalesce(locked_until > clock_timestamp(), false),
	coalesce(extract(epoch FROM locked_until - clock_timestamp()), 0)
FROM users WHERE id = $1`, id).Scan(&l.failures, &l.locked, &seconds)
	if err != nil {
		t.Fatalf("read lockout: %v", err)
	}
	l.remaining = time.Duration(seconds * float64(time.Second))
	return l
}

func fail(t *testing.T, s *Store, id string, n int) {
	t.Helper()
	for range n {
		if err := s.RecordFailedLogin(t.Context(), id); err != nil {
			t.Fatalf("RecordFailedLogin() error = %v", err)
		}
	}
}

func TestRecordFailedLogin_LocksOnTheFifthFailure(t *testing.T) {
	t.Parallel()

	s, owner, id := lockoutUser(t)
	fail(t, s, id, MaxFailedLogins-1)
	if l := readLockout(t, owner, id); l.failures != MaxFailedLogins-1 || l.locked {
		t.Fatalf("after %d failures: %+v, want counted and unlocked", MaxFailedLogins-1, l)
	}

	fail(t, s, id, 1)
	l := readLockout(t, owner, id)
	if l.failures != 0 || !l.locked || l.remaining <= LockDuration-time.Minute || l.remaining > LockDuration {
		t.Errorf("after %d failures: %+v, want locked for %v and the count started again", MaxFailedLogins, l, LockDuration)
	}
}

func TestRecordFailedLogin_FailuresDuringTheLockNeitherCountNorExtend(t *testing.T) {
	t.Parallel()

	s, owner, id := lockoutUser(t)
	fail(t, s, id, MaxFailedLogins)
	// Shorten the lock, so that an extension would be visible.
	if _, err := owner.Exec(t.Context(), `UPDATE users SET locked_until = clock_timestamp() + interval '1 minute' WHERE id = $1`, id); err != nil {
		t.Fatalf("shorten lock: %v", err)
	}

	fail(t, s, id, 2*MaxFailedLogins)
	if l := readLockout(t, owner, id); l.failures != 0 || !l.locked || l.remaining > time.Minute {
		t.Errorf("failures during the lock: %+v, want no count and the lock unchanged", l)
	}
}

func TestRecordFailedLogin_CountsAgainAfterTheLock(t *testing.T) {
	t.Parallel()

	s, owner, id := lockoutUser(t)
	fail(t, s, id, MaxFailedLogins)
	if _, err := owner.Exec(t.Context(), `UPDATE users SET locked_until = clock_timestamp() - interval '1 second' WHERE id = $1`, id); err != nil {
		t.Fatalf("end lock: %v", err)
	}
	fail(t, s, id, 1)
	if l := readLockout(t, owner, id); l.failures != 1 || l.locked {
		t.Errorf("failure after the lock: %+v, want counted from the start and unlocked", l)
	}
}

// waitForLockWaiter returns once a session of the test database waits for a
// lock. It polls instead of sleeping, so it neither depends on timing nor returns
// before the waiter has reached the lock.
func waitForLockWaiter(t *testing.T, owner *pgxpool.Pool, done <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		var waiting bool
		err := owner.QueryRow(ctx, `
SELECT EXISTS (SELECT FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting)
		if err != nil {
			t.Fatalf("query waiting sessions: %v", err)
		}
		if waiting {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("the operation completed without waiting for a row lock: %v", err)
		default:
		}
	}
}

// A failure that another transaction is counting at the same time must not be
// lost. If the count were read before the row lock and written afterwards, the
// waiting failure would overwrite the concurrent one and the account would not
// be locked.
func TestRecordFailedLogin_ConcurrentFailuresAreAllCounted(t *testing.T) {
	t.Parallel()

	s, owner, id := lockoutUser(t)
	fail(t, s, id, MaxFailedLogins-2)

	concurrent, err := owner.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = concurrent.Rollback(context.WithoutCancel(t.Context())) }()
	if err := NewStore(concurrent).RecordFailedLogin(t.Context(), id); err != nil {
		t.Fatalf("concurrent RecordFailedLogin() error = %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- s.RecordFailedLogin(t.Context(), id) }()
	waitForLockWaiter(t, owner, done)
	if err := concurrent.Commit(t.Context()); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("RecordFailedLogin() error = %v", err)
	}
	if l := readLockout(t, owner, id); !l.locked {
		t.Errorf("after %d failures, two of them concurrent: %+v, want locked", MaxFailedLogins, l)
	}
}

func TestLockForSignIn(t *testing.T) {
	t.Parallel()

	s, owner, id := lockoutUser(t)
	state, err := s.LockForSignIn(t.Context(), id)
	if err != nil || state.Status != StatusActive || state.RetryAfter != 0 {
		t.Errorf("LockForSignIn() unlocked = %+v, %v; want active without RetryAfter", state, err)
	}

	fail(t, s, id, MaxFailedLogins)
	state, err = s.LockForSignIn(t.Context(), id)
	if err != nil || state.RetryAfter <= LockDuration-time.Minute || state.RetryAfter > LockDuration {
		t.Errorf("LockForSignIn() locked = %+v, %v; want RetryAfter of about %v", state, err, LockDuration)
	}

	if _, err := owner.Exec(t.Context(), `UPDATE users SET locked_until = clock_timestamp() - interval '1 second' WHERE id = $1`, id); err != nil {
		t.Fatalf("end lock: %v", err)
	}
	if state, err := s.LockForSignIn(t.Context(), id); err != nil || state.RetryAfter != 0 {
		t.Errorf("LockForSignIn() after the lock = %+v, %v; want no RetryAfter", state, err)
	}

	for _, unknown := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if _, err := s.LockForSignIn(t.Context(), unknown); !errors.Is(err, ErrNotFound) {
			t.Errorf("LockForSignIn(%s) error = %v, want ErrNotFound", unknown, err)
		}
	}
}

func TestCompleteSignIn_ResetsCountAndReplacesHash(t *testing.T) {
	t.Parallel()

	s, owner, id := lockoutUser(t)
	fail(t, s, id, MaxFailedLogins-1)
	if err := s.CompleteSignIn(t.Context(), id, ""); err != nil {
		t.Fatalf("CompleteSignIn() error = %v", err)
	}
	if l := readLockout(t, owner, id); l.failures != 0 || l.locked {
		t.Errorf("after a successful sign-in: %+v, want the count reset", l)
	}
	before, err := s.Get(t.Context(), id)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	rehashed := strings.Replace(testHash, "m=65536", "m=131072", 1)
	if err := s.CompleteSignIn(t.Context(), id, rehashed); err != nil {
		t.Fatalf("CompleteSignIn() with hash error = %v", err)
	}
	after, err := s.Get(t.Context(), id)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if after.PasswordHash != rehashed || !after.UpdatedAt.After(before.UpdatedAt) {
		t.Errorf("after rehash: hash %q, updated %v (before %v); want the new hash and a later update time", after.PasswordHash, after.UpdatedAt, before.UpdatedAt)
	}

	if err := s.CompleteSignIn(t.Context(), id, "plain text password"); !errors.Is(err, ErrInvalidPasswordHash) {
		t.Errorf("CompleteSignIn() with plain text error = %v, want ErrInvalidPasswordHash", err)
	}
}

// Setting the password proves access to the account, so it ends a lock.
func TestSetPassword_ReplacesTheHashAndEndsTheLock(t *testing.T) {
	t.Parallel()

	s, owner, id := lockoutUser(t)
	fail(t, s, id, MaxFailedLogins)
	// A lock starts the count again; counted failures are set directly, so that
	// the test sees both reset.
	if _, err := owner.Exec(t.Context(), `UPDATE users SET failed_logins = 3 WHERE id = $1`, id); err != nil {
		t.Fatalf("set failures: %v", err)
	}
	if l := readLockout(t, owner, id); !l.locked || l.failures != 3 {
		t.Fatalf("lockout = %+v, want locked with counted failures", l)
	}

	newHash := strings.Replace(testHash, "t=3", "t=4", 1)
	u, err := s.SetPassword(t.Context(), id, newHash)
	if err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
	if u.PasswordHash != newHash {
		t.Errorf("PasswordHash = %q, want the new hash", u.PasswordHash)
	}
	if l := readLockout(t, owner, id); l.locked || l.failures != 0 {
		t.Errorf("lockout = %+v, want none", l)
	}
}

func TestSetPassword_RequiresAnActiveAccountAndAHash(t *testing.T) {
	t.Parallel()

	s, owner, id := lockoutUser(t)
	pending, err := s.Create(t.Context(), NewUser{Email: "pending@example.com", DisplayName: "P", Role: RoleViewer})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	deactivated, err := s.Create(t.Context(), NewUser{Email: "gone@example.com", DisplayName: "G", Role: RoleViewer, PasswordHash: testHash})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := owner.Exec(t.Context(), `UPDATE users SET status = 'deactivated' WHERE id = $1`, deactivated.ID); err != nil {
		t.Fatalf("deactivate: %v", err)
	}

	for name, target := range map[string]string{
		"pending":     pending.ID,
		"deactivated": deactivated.ID,
		"unknown":     "00000000-0000-4000-8000-000000000000",
		"malformed":   "not-a-uuid",
	} {
		if _, err := s.SetPassword(t.Context(), target, testHash); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: SetPassword() error = %v, want ErrNotFound", name, err)
		}
	}
	if _, err := s.SetPassword(t.Context(), id, "correct horse battery"); !errors.Is(err, ErrInvalidPasswordHash) {
		t.Errorf("plain text: SetPassword() error = %v, want ErrInvalidPasswordHash", err)
	}
}
