// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/platform/schematest"
)

// manageDB returns a store connected as the console's database role, its pool
// and a pool of the owner.
func manageDB(t *testing.T) (*Store, *pgxpool.Pool, *pgxpool.Pool) {
	t.Helper()
	ownerURL, consoleURL := schematest.Console(t)
	pool := schematest.Open(t, consoleURL)
	return NewStore(pool), pool, schematest.Open(t, ownerURL)
}

// account creates an account with role and status. Active and deactivated
// accounts get a password hash.
func account(t *testing.T, owner *pgxpool.Pool, email string, role Role, status Status) string {
	t.Helper()
	var hash *string
	if status != StatusPending {
		h := testHash
		hash = &h
	}
	var id string
	err := owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, password_hash) VALUES ($1, 'Test User', $2, $3, $4)
RETURNING id`, email, role, status, hash).Scan(&id)
	if err != nil {
		t.Fatalf("create %s: %v", email, err)
	}
	return id
}

// inTx runs f in a transaction of the console's role and commits if f
// succeeds, as the callers of Update and Delete do.
func inTx(t *testing.T, pool *pgxpool.Pool, f func(*Store) error) error {
	t.Helper()
	return pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error { return f(NewStore(tx)) })
}

func update(t *testing.T, pool *pgxpool.Pool, id string, c Change) (User, []string, error) {
	t.Helper()
	var (
		u       User
		changed []string
	)
	err := inTx(t, pool, func(s *Store) error {
		var err error
		u, changed, err = s.Update(t.Context(), id, c)
		return err
	})
	return u, changed, err
}

func ptr[T any](v T) *T { return &v }

func TestList_ReturnsUsersNewestFirstInPages(t *testing.T) {
	t.Parallel()

	s, _, owner := manageDB(t)
	var want []string
	for _, email := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		want = append([]string{account(t, owner, email, RoleViewer, StatusPending)}, want...)
	}
	// Accounts created in one transaction share their creation time, so the
	// identifier must break the tie.
	if _, err := owner.Exec(t.Context(), `UPDATE users SET created_at = '2026-10-10T12:00:00Z', updated_at = '2026-10-10T12:00:00Z' WHERE email <> 'c@example.com'`); err != nil {
		t.Fatalf("set creation times: %v", err)
	}
	slices.SortFunc(want[1:], func(a, b string) int { return strings.Compare(b, a) })

	var got []string
	var after *Cursor
	for range 3 {
		page, next, err := s.List(t.Context(), 1, after)
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		for _, u := range page {
			got = append(got, u.ID)
		}
		after = next
	}
	if after != nil || !slices.Equal(got, want) {
		t.Errorf("pages = %v, next %v; want %v and no further page", got, after, want)
	}
	all, next, err := s.List(t.Context(), MaxPageSize, nil)
	if err != nil || len(all) != 3 || next != nil {
		t.Errorf("List(MaxPageSize) = %d accounts, next %v, error %v; want 3 without a next page", len(all), next, err)
	}
}

func TestList_RejectsInvalidPageSize(t *testing.T) {
	t.Parallel()

	s, _, _ := manageDB(t)
	for _, size := range []int{-1, 0, MaxPageSize + 1} {
		if _, _, err := s.List(t.Context(), size, nil); !errors.Is(err, ErrInvalidPageSize) {
			t.Errorf("List(%d) error = %v, want ErrInvalidPageSize", size, err)
		}
	}
}

// A page after a cursor must seek into the index, also with the generic plan
// that PostgreSQL may choose for a prepared statement after a few executions.
func TestList_CursorIsAnIndexConditionInTheGenericPlan(t *testing.T) {
	t.Parallel()

	ownerURL, _ := schematest.Console(t)
	// A connection of its own, closed afterwards: the settings and the prepared
	// statement below must not reach a connection that other queries reuse.
	conn, err := pgx.Connect(t.Context(), ownerURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(t.Context())) }()

	for _, statement := range []string{
		"SET plan_cache_mode = force_generic_plan",
		// The test table is tiny; without this, a sequential scan would win.
		"SET enable_seqscan = off",
		"PREPARE list_after AS " + listAfter,
	} {
		if _, err := conn.Exec(t.Context(), statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	rows, err := conn.Query(t.Context(), "EXPLAIN EXECUTE list_after('2026-10-10T12:00:00Z', '00000000-0000-4000-8000-000000000000', 51)")
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	plan, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}
	text := strings.Join(plan, "\n")
	if !strings.Contains(text, "users_created_at_id_idx") || !strings.Contains(text, "Index Cond: (ROW(created_at, id) < ROW(") {
		t.Errorf("generic plan does not seek into the index with the cursor:\n%s", text)
	}
}

func TestUpdate_ReportsOnlyChangedFields(t *testing.T) {
	t.Parallel()

	_, pool, owner := manageDB(t)
	account(t, owner, "admin@example.com", RoleAdmin, StatusActive)
	id := account(t, owner, "jane@example.com", RoleViewer, StatusActive)

	u, changed, err := update(t, pool, id, Change{DisplayName: ptr("Jane Roe"), Role: ptr(RoleEditor), Status: ptr(StatusActive)})
	if err != nil || !slices.Equal(changed, []string{FieldDisplayName, FieldRole}) {
		t.Fatalf("Update() changed %v, error %v; want display_name and role", changed, err)
	}
	if u.DisplayName != "Jane Roe" || u.Role != RoleEditor || u.Status != StatusActive || !u.UpdatedAt.After(u.CreatedAt) {
		t.Errorf("Update() = %+v, want the new name and role and a new update time", u)
	}
	u2, changed, err := update(t, pool, id, Change{DisplayName: ptr("Jane Roe"), Role: ptr(RoleEditor)})
	if err != nil || len(changed) != 0 || !u2.UpdatedAt.Equal(u.UpdatedAt) {
		t.Errorf("Update() without a difference changed %v, error %v, updated at %v; want nothing", changed, err, u2.UpdatedAt)
	}
}

func TestUpdate_StatusTransitions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		from    Status
		to      Status
		want    Status
		changed bool
		err     error
	}{
		{name: "deactivate active", from: StatusActive, to: StatusDeactivated, want: StatusDeactivated, changed: true},
		{name: "deactivate pending", from: StatusPending, to: StatusDeactivated, want: StatusDeactivated, changed: true},
		{name: "deactivate deactivated", from: StatusDeactivated, to: StatusDeactivated, want: StatusDeactivated},
		{name: "reactivate with password", from: StatusDeactivated, to: StatusActive, want: StatusActive, changed: true},
		{name: "activate active", from: StatusActive, to: StatusActive, want: StatusActive},
		{name: "activate pending", from: StatusPending, to: StatusActive, err: ErrInvalidTransition},
		{name: "set pending", from: StatusActive, to: StatusPending, err: ErrInvalidStatus},
		{name: "unknown status", from: StatusActive, to: "locked", err: ErrInvalidStatus},
	}
	// One database for all cases keeps the number of connections low; each case
	// has an account of its own.
	_, pool, owner := manageDB(t)
	account(t, owner, "admin@example.com", RoleAdmin, StatusActive)
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := account(t, owner, fmt.Sprintf("user%d@example.com", i), RoleViewer, tt.from)
			u, changed, err := update(t, pool, id, Change{Status: ptr(tt.to)})
			if !errors.Is(err, tt.err) {
				t.Fatalf("Update() error = %v, want %v", err, tt.err)
			}
			if err == nil && (u.Status != tt.want || (len(changed) > 0) != tt.changed) {
				t.Errorf("Update() = status %s, changed %v; want %s, changed %v", u.Status, changed, tt.want, tt.changed)
			}
		})
	}
}

// An account that never set a password returns to pending, because an active
// account needs a password.
func TestUpdate_ReactivatingWithoutPasswordReturnsToPending(t *testing.T) {
	t.Parallel()

	_, pool, owner := manageDB(t)
	id := account(t, owner, "jane@example.com", RoleViewer, StatusPending)
	if _, _, err := update(t, pool, id, Change{Status: ptr(StatusDeactivated)}); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if u, _, err := update(t, pool, id, Change{Status: ptr(StatusActive)}); err != nil || u.Status != StatusPending {
		t.Errorf("reactivate = %s, %v; want pending", u.Status, err)
	}
}

func TestUpdate_ReactivatingEndsTheLock(t *testing.T) {
	t.Parallel()

	_, pool, owner := manageDB(t)
	id := account(t, owner, "jane@example.com", RoleViewer, StatusDeactivated)
	if _, err := owner.Exec(t.Context(), `UPDATE users SET failed_logins = 3, locked_until = clock_timestamp() + interval '10 minutes' WHERE id = $1`, id); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if _, _, err := update(t, pool, id, Change{Status: ptr(StatusActive)}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if l := readLockout(t, owner, id); l.failures != 0 || l.locked {
		t.Errorf("after reactivation: %+v, want no failures and no lock", l)
	}
}

func TestUpdate_RejectsInvalidInputAndUnknownAccounts(t *testing.T) {
	t.Parallel()

	_, pool, owner := manageDB(t)
	id := account(t, owner, "jane@example.com", RoleViewer, StatusActive)
	tests := []struct {
		id   string
		c    Change
		want error
	}{
		{id: id, c: Change{DisplayName: ptr(" Jane")}, want: ErrInvalidDisplayName},
		{id: id, c: Change{DisplayName: ptr("Jane\u202eRoe")}, want: ErrInvalidDisplayName},
		{id: id, c: Change{Role: ptr(Role("owner"))}, want: ErrInvalidRole},
		{id: "00000000-0000-4000-8000-000000000000", c: Change{DisplayName: ptr("Jane")}, want: ErrNotFound},
		{id: "not-a-uuid", c: Change{Role: ptr(RoleEditor)}, want: ErrNotFound},
	}
	for _, tt := range tests {
		if _, _, err := update(t, pool, tt.id, tt.c); !errors.Is(err, tt.want) {
			t.Errorf("Update(%s, %+v) error = %v, want %v", tt.id, tt.c, err, tt.want)
		}
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()

	_, pool, owner := manageDB(t)
	id := account(t, owner, "jane@example.com", RoleViewer, StatusActive)
	if err := inTx(t, pool, func(s *Store) error { return s.Delete(t.Context(), id) }); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if err := inTx(t, pool, func(s *Store) error { return s.Delete(t.Context(), id) }); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete() of a deleted account: error = %v, want ErrNotFound", err)
	}
}

// Demoting, deactivating or deleting the last active administrator is
// rejected. Pending and deactivated administrators do not count.
func TestUpdateAndDelete_KeepTheLastActiveAdmin(t *testing.T) {
	t.Parallel()

	changes := map[string]func(*Store, string) error{
		"demote": func(s *Store, id string) error {
			_, _, err := s.Update(context.Background(), id, Change{Role: ptr(RoleEditor)})
			return err
		},
		"deactivate": func(s *Store, id string) error {
			_, _, err := s.Update(context.Background(), id, Change{Status: ptr(StatusDeactivated)})
			return err
		},
		"delete": func(s *Store, id string) error { return s.Delete(context.Background(), id) },
	}
	// The subtests run one after another, each with its own database, so that
	// they do not hold more connections at once than one test.
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			_, pool, owner := manageDB(t)
			last := account(t, owner, "ada@example.com", RoleAdmin, StatusActive)
			account(t, owner, "pending@example.com", RoleAdmin, StatusPending)
			account(t, owner, "deactivated@example.com", RoleAdmin, StatusDeactivated)
			if err := inTx(t, pool, func(s *Store) error { return change(s, last) }); !errors.Is(err, ErrLastActiveAdmin) {
				t.Fatalf("%s the last active administrator: error = %v, want ErrLastActiveAdmin", name, err)
			}

			account(t, owner, "grace@example.com", RoleAdmin, StatusActive)
			if err := inTx(t, pool, func(s *Store) error { return change(s, last) }); err != nil {
				t.Errorf("%s one of two active administrators: error = %v, want nil", name, err)
			}
		})
	}
}

// The schema keeps the last active administrator also against statements that
// bypass the store.
func TestSchema_KeepsTheLastActiveAdmin(t *testing.T) {
	t.Parallel()

	_, pool, owner := manageDB(t)
	account(t, owner, "ada@example.com", RoleAdmin, StatusActive)
	account(t, owner, "grace@example.com", RoleAdmin, StatusActive)
	account(t, owner, "jane@example.com", RoleViewer, StatusActive)
	// Each statement fails as a whole, so the next one starts from the same state.
	for _, statement := range []string{
		"UPDATE users SET role = 'viewer'",
		"UPDATE users SET status = 'deactivated'",
		"DELETE FROM users",
		"DELETE FROM users WHERE role = 'admin'",
	} {
		if _, err := pool.Exec(t.Context(), statement); !isLastAdminViolation(err) {
			t.Errorf("%s: error = %v, want a violation of users_active_admin_check", statement, err)
		}
	}
	if n := countActiveAdmins(t, owner); n != 2 {
		t.Errorf("active administrators = %d, want 2", n)
	}
}

func countActiveAdmins(t *testing.T, owner *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := owner.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE role = 'admin' AND status = 'active'`).Scan(&n); err != nil {
		t.Fatalf("count active administrators: %v", err)
	}
	return n
}

// Changes that leave an active administrator, or that concern no active one,
// pass the trigger.
func TestSchema_AllowsChangesThatKeepAnActiveAdmin(t *testing.T) {
	t.Parallel()

	_, pool, owner := manageDB(t)
	ada := account(t, owner, "ada@example.com", RoleAdmin, StatusActive)
	account(t, owner, "grace@example.com", RoleAdmin, StatusActive)
	account(t, owner, "jane@example.com", RoleViewer, StatusActive)
	account(t, owner, "pending@example.com", RoleAdmin, StatusPending)
	for _, statement := range []string{
		"UPDATE users SET role = 'editor' WHERE role = 'viewer'",
		"DELETE FROM users WHERE status = 'pending'",
		"UPDATE users SET display_name = 'Ada' WHERE role = 'admin'",
		"UPDATE users SET role = 'admin', status = 'active' WHERE role = 'admin'",
		"UPDATE users SET status = 'deactivated' WHERE id = '" + ada + "'",
	} {
		if _, err := pool.Exec(t.Context(), statement); err != nil {
			t.Errorf("%s: error = %v, want nil", statement, err)
		}
	}
}

func isLastAdminViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == checkViolation && pgErr.ConstraintName == "users_active_admin_check"
}

// The store locks every active administrator before it decides, also when the
// account it changes is none. A probe that only the lock of another
// administrator blocks shows this: changing a viewer locks the viewer's row
// itself, and no trigger fires.
func TestUpdate_LocksTheActiveAdmins(t *testing.T) {
	t.Parallel()

	_, _, owner := manageDB(t)
	admin := account(t, owner, "ada@example.com", RoleAdmin, StatusActive)
	viewer := account(t, owner, "jane@example.com", RoleViewer, StatusActive)

	tx, err := owner.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	if _, _, err := NewStore(tx).Update(t.Context(), viewer, Change{Role: ptr(RoleEditor)}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	_, err = owner.Exec(t.Context(), `SELECT FROM users WHERE id = $1 FOR UPDATE NOWAIT`, admin)
	var pgErr *pgconn.PgError
	// 55P03 is lock_not_available.
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("lock the administrator while a role changes: error = %v, want lock_not_available", err)
	}
}

// Two administrators demoting each other at the same time must not both
// succeed. The second change waits for the first, then sees its result and is
// rejected.
func TestUpdate_ConcurrentDemotionsKeepAnActiveAdmin(t *testing.T) {
	t.Parallel()

	_, pool, owner := manageDB(t)
	ada := account(t, owner, "ada@example.com", RoleAdmin, StatusActive)
	grace := account(t, owner, "grace@example.com", RoleAdmin, StatusActive)

	first, err := owner.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = first.Rollback(context.WithoutCancel(t.Context())) }()
	if _, _, err := NewStore(first).Update(t.Context(), ada, Change{Role: ptr(RoleViewer)}); err != nil {
		t.Fatalf("first Update() error = %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, _, err := update(t, pool, grace, Change{Role: ptr(RoleViewer)})
		done <- err
	}()
	waitForLockWaiter(t, owner, done)
	if err := first.Commit(t.Context()); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := <-done; !errors.Is(err, ErrLastActiveAdmin) {
		t.Errorf("second Update() error = %v, want ErrLastActiveAdmin", err)
	}
	if n := countActiveAdmins(t, owner); n != 1 {
		t.Errorf("active administrators = %d, want 1", n)
	}
}

// The trigger serializes changes that bypass the store as well: the second
// statement waits for the lock that the trigger of the first one holds, and
// then rejects the change.
func TestSchema_ConcurrentDemotionsKeepAnActiveAdmin(t *testing.T) {
	t.Parallel()

	_, pool, owner := manageDB(t)
	ada := account(t, owner, "ada@example.com", RoleAdmin, StatusActive)
	grace := account(t, owner, "grace@example.com", RoleAdmin, StatusActive)

	first, err := owner.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = first.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := first.Exec(t.Context(), `UPDATE users SET role = 'viewer' WHERE id = $1`, ada); err != nil {
		t.Fatalf("first UPDATE: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := pool.Exec(t.Context(), `UPDATE users SET role = 'viewer' WHERE id = $1`, grace)
		done <- err
	}()
	waitForLockWaiter(t, owner, done)
	if err := first.Commit(t.Context()); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := <-done; !isLastAdminViolation(err) {
		t.Errorf("second UPDATE error = %v, want a violation of users_active_admin_check", err)
	}
}

func TestActivate(t *testing.T) {
	t.Parallel()

	s, _, owner := manageDB(t)
	pending := account(t, owner, "jane@example.com", RoleViewer, StatusPending)
	active := account(t, owner, "ada@example.com", RoleViewer, StatusActive)
	deactivated := account(t, owner, "grace@example.com", RoleViewer, StatusDeactivated)

	if _, err := s.Activate(t.Context(), pending, "correct horse battery staple"); !errors.Is(err, ErrInvalidPasswordHash) {
		t.Errorf("Activate() with a plain-text password: error = %v, want ErrInvalidPasswordHash", err)
	}
	u, err := s.Activate(t.Context(), pending, testHash)
	if err != nil || u.Status != StatusActive || u.PasswordHash != testHash {
		t.Errorf("Activate() = %s, %v; want active with the hash", u.Status, err)
	}
	// A link must never replace the password of an account that has one.
	for _, id := range []string{pending, active, deactivated, "not-a-uuid"} {
		if _, err := s.Activate(t.Context(), id, testHash); !errors.Is(err, ErrNotFound) {
			t.Errorf("Activate(%s) error = %v, want ErrNotFound", id, err)
		}
	}
}

// Failed sign-ins count for pending accounts too, so the account may be locked
// before its owner activates it. The activation proves access and ends the lock.
func TestActivate_EndsALockFromBeforeTheActivation(t *testing.T) {
	t.Parallel()

	s, _, owner := manageDB(t)
	id := account(t, owner, "jane@example.com", RoleViewer, StatusPending)
	fail(t, s, id, MaxFailedLogins)
	if l := readLockout(t, owner, id); !l.locked {
		t.Fatalf("after %d failures: %+v, want locked", MaxFailedLogins, l)
	}
	if _, err := s.Activate(t.Context(), id, testHash); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if l := readLockout(t, owner, id); l.failures != 0 || l.locked {
		t.Errorf("after activation: %+v, want no failures and no lock", l)
	}
}
