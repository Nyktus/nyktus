// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dbtest

import (
	"context"
	"crypto/rand"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestGroupRole_IsIdempotent(t *testing.T) {
	t.Parallel()

	name := uniqueRoleName(t)
	GroupRole(t, name)
	GroupRole(t, name)

	conn := connect(t, serverURL(t))
	var canLogin bool
	if err := conn.QueryRow(t.Context(), "SELECT rolcanlogin FROM pg_roles WHERE rolname = $1", name).Scan(&canLogin); err != nil {
		t.Fatalf("query role: %v", err)
	}
	if canLogin {
		t.Errorf("role %s can log in, want a group role", name)
	}
}

// The second creation starts while the first is uncommitted, so it cannot see the
// role yet and has to wait for the first transaction to end.
func TestGroupRole_ConcurrentCreationSucceeds(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	name := uniqueRoleName(t)
	first := connect(t, serverURL(t))
	second := connect(t, serverURL(t))

	tx, err := first.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, groupRoleStatement(name)); err != nil {
		t.Fatalf("create role in first transaction: %v", err)
	}

	var secondPID uint32
	if err := second.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&secondPID); err != nil {
		t.Fatalf("query backend pid: %v", err)
	}
	// The goroutine owns the second connection until it is done. It ends before
	// the test does, also when the test fails early, because the connection must
	// not be closed while it is in use.
	secondCtx, cancelSecond := context.WithCancel(ctx)
	var secondErr error
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, secondErr = second.Exec(secondCtx, groupRoleStatement(name))
	}()
	defer func() {
		cancelSecond()
		<-finished
	}()

	waitUntilBlocked(t, tx, secondPID)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit first transaction: %v", err)
	}
	<-finished
	if secondErr != nil {
		t.Errorf("concurrent GroupRole statement error = %v, want nil", secondErr)
	}
}

// waitUntilBlocked returns once the backend pid waits for a lock held by another
// session. It polls the lock state instead of sleeping for a fixed time, so the
// test does not depend on timing.
func waitUntilBlocked(t *testing.T, tx pgx.Tx, pid uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for {
		var blocked bool
		if err := tx.QueryRow(ctx, "SELECT cardinality(pg_blocking_pids($1)) > 0", pid).Scan(&blocked); err != nil {
			t.Fatalf("query blocking pids: %v", err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("second session never waited for the first")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func uniqueRoleName(t *testing.T) string {
	t.Helper()
	name := "nyktus_test_group_" + strings.ToLower(rand.Text())
	t.Cleanup(func() { Exec(t, serverURL(t), "DROP ROLE IF EXISTS "+pgx.Identifier{name}.Sanitize()) })
	return name
}

func connect(t *testing.T, dbURL string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(t.Context(), dbURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.WithoutCancel(t.Context())) })
	return conn
}

// failingTB turns a failure of the code under test into a panic, so that a test
// can observe what a failed preparation leaves on the server.
type failingTB struct{ testing.TB }

func (failingTB) Fatalf(string, ...any) { panic("fatal") }

func templateKey(t *testing.T) string {
	t.Helper()
	return strings.ToLower(rand.Text())
}

func TestNewFromTemplate_PreparesOncePerKeyAndCopiesIndependently(t *testing.T) {
	t.Parallel()

	var prepared atomic.Int32
	prepare := func(tb testing.TB, dbURL string) {
		tb.Helper()
		prepared.Add(1)
		Exec(tb, dbURL, "CREATE TABLE marker (n int)", "INSERT INTO marker VALUES (1)")
	}
	key := templateKey(t)
	t.Cleanup(func() { Exec(t, serverURL(t), "DROP DATABASE IF EXISTS nyktus_tpl_"+key+" WITH (FORCE)") })

	first := NewFromTemplate(t, key, prepare)
	second := NewFromTemplate(t, key, prepare)
	// Another process finds the template on the server and not in its memory.
	readyMu.Lock()
	clear(readyTemplates)
	readyMu.Unlock()
	NewFromTemplate(t, key, prepare)
	if n := prepared.Load(); n != 1 {
		t.Errorf("prepare ran %d times for one key, want 1", n)
	}
	Exec(t, first, "INSERT INTO marker VALUES (2)")
	for dbURL, want := range map[string]int{first: 2, second: 1} {
		var n int
		if err := connect(t, dbURL).QueryRow(t.Context(), "SELECT count(*) FROM marker").Scan(&n); err != nil {
			t.Fatalf("count rows: %v", err)
		}
		if n != want {
			t.Errorf("copy has %d rows, want %d: copies share state or miss the template", n, want)
		}
	}
}

func TestNewFromTemplate_FailedPreparationLeavesNoTemplate(t *testing.T) {
	t.Parallel()

	key := templateKey(t)
	t.Cleanup(func() { Exec(t, serverURL(t), "DROP DATABASE IF EXISTS nyktus_tpl_"+key+" WITH (FORCE)") })

	func() {
		defer func() {
			if recover() == nil {
				t.Error("a failing preparation did not stop the test")
			}
		}()
		NewFromTemplate(failingTB{t}, key, func(tb testing.TB, _ string) {
			tb.Helper()
			tb.Fatalf("preparation failed")
		})
	}()

	var exists bool
	if err := connect(t, serverURL(t)).QueryRow(t.Context(),
		"SELECT EXISTS (SELECT FROM pg_database WHERE datname = $1)", "nyktus_tpl_"+key).Scan(&exists); err != nil {
		t.Fatalf("look up template: %v", err)
	}
	if exists {
		t.Error("a template exists after a failed preparation, so the next test would copy a half-built database")
	}

	var left int
	if err := connect(t, serverURL(t)).QueryRow(t.Context(),
		"SELECT count(*) FROM pg_database WHERE starts_with(datname, $1)", buildPrefix("nyktus_tpl_"+key)).Scan(&left); err != nil {
		t.Fatalf("look up unfinished templates: %v", err)
	}
	if left != 0 {
		t.Errorf("%d databases of the failed construction are left", left)
	}

	// The next call builds it.
	var prepared atomic.Int32
	NewFromTemplate(t, key, func(testing.TB, string) { prepared.Add(1) })
	if prepared.Load() != 1 {
		t.Error("the preparation did not run again after it had failed")
	}
}

func TestNewFromTemplate_RemovesWhatAStoppedConstructionLeft(t *testing.T) {
	t.Parallel()

	key := templateKey(t)
	orphan := buildPrefix("nyktus_tpl_"+key) + "stopped"
	Exec(t, serverURL(t), "CREATE DATABASE "+orphan)
	t.Cleanup(func() {
		Exec(t, serverURL(t),
			"DROP DATABASE IF EXISTS "+orphan+" WITH (FORCE)",
			"DROP DATABASE IF EXISTS nyktus_tpl_"+key+" WITH (FORCE)")
	})

	NewFromTemplate(t, key, func(testing.TB, string) {})

	var n int
	if err := connect(t, serverURL(t)).QueryRow(t.Context(),
		"SELECT count(*) FROM pg_database WHERE datname = $1", orphan).Scan(&n); err != nil {
		t.Fatalf("look up database: %v", err)
	}
	if n != 0 {
		t.Error("the database of the stopped construction is still there")
	}
}

// Two processes that find no template must not both build it: the second would
// fail on the name or copy a template that is not complete. The lock is proven by
// holding it and waiting until the construction is blocked on it.
func TestNewFromTemplate_WaitsForTheLockOfTheKey(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	key := templateKey(t)
	t.Cleanup(func() { Exec(t, serverURL(t), "DROP DATABASE IF EXISTS nyktus_tpl_"+key+" WITH (FORCE)") })

	holder := connect(t, serverURL(t))
	var id int64
	if err := holder.QueryRow(ctx, "SELECT hashtextextended($1, 0)", "nyktus_tpl_"+key).Scan(&id); err != nil {
		t.Fatalf("hash key: %v", err)
	}
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_lock($1)", id); err != nil {
		t.Fatalf("take lock: %v", err)
	}

	prepared := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		NewFromTemplate(t, key, func(testing.TB, string) { close(prepared) })
	}()

	observer := connect(t, serverURL(t))
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		var waiting int
		if err := observer.QueryRow(waitCtx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted
AND classid = (($1::bigint >> 32) & 4294967295)::oid AND objid = ($1::bigint & 4294967295)::oid`, id).Scan(&waiting); err != nil {
			t.Fatalf("look up waiters: %v", err)
		}
		if waiting > 0 {
			break
		}
		select {
		case <-waitCtx.Done():
			t.Fatal("the construction does not wait for the lock")
		case <-time.After(5 * time.Millisecond):
		}
	}
	select {
	case <-prepared:
		t.Fatal("the template is prepared while another session holds its lock")
	default:
	}

	if _, err := holder.Exec(ctx, "SELECT pg_advisory_unlock($1)", id); err != nil {
		t.Fatalf("release lock: %v", err)
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the construction does not continue after the lock is released")
	}
}
