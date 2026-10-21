// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dbtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
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
// holding it and waiting until both constructions are blocked on it; the one that
// gets the lock second finds the template built.
func TestNewFromTemplate_WaitsForTheLockOfTheKey(t *testing.T) {
	t.Parallel()

	const callers = 2
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

	var prepared atomic.Int32
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			NewFromTemplate(t, key, func(testing.TB, string) { prepared.Add(1) })
		})
	}
	// The goroutines end before the test does, also when it fails early: they are
	// blocked until the lock is released, and use the test until they are done.
	defer func() {
		_, _ = holder.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", id)
		wg.Wait()
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
		if waiting == callers {
			break
		}
		select {
		case <-waitCtx.Done():
			t.Fatalf("%d of %d constructions wait for the lock", waiting, callers)
		case <-time.After(5 * time.Millisecond):
		}
	}
	if n := prepared.Load(); n != 0 {
		t.Fatalf("the template is prepared %d times while another session holds its lock", n)
	}

	if _, err := holder.Exec(ctx, "SELECT pg_advisory_unlock($1)", id); err != nil {
		t.Fatalf("release lock: %v", err)
	}
	wg.Wait()
	if n := prepared.Load(); n != 1 {
		t.Errorf("the template is prepared %d times, want once: the second construction finds it built", n)
	}
}

func TestNewFromTemplate_BuildsATemplateAgainThatWasRemoved(t *testing.T) {
	t.Parallel()

	var prepared atomic.Int32
	prepare := func(testing.TB, string) { prepared.Add(1) }
	key := templateKey(t)
	t.Cleanup(func() { Exec(t, serverURL(t), "DROP DATABASE IF EXISTS nyktus_tpl_"+key+" WITH (FORCE)") })

	NewFromTemplate(t, key, prepare)
	Exec(t, serverURL(t), "DROP DATABASE nyktus_tpl_"+key)
	NewFromTemplate(t, key, prepare)

	if n := prepared.Load(); n != 2 {
		t.Errorf("prepare ran %d times, want 2: a removed template is built again", n)
	}
}

func TestNewFromTemplate_KeepsTheNewestTemplatesOfDigestKeys(t *testing.T) {
	t.Parallel()

	digestKey := func() string { return hexDigits(t) }
	var names []string
	t.Cleanup(func() {
		for _, name := range names {
			Exec(t, serverURL(t), "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		}
	})
	// Older than the template that is built below, and more than are kept.
	for range keptTemplates {
		name := "nyktus_tpl_" + digestKey()
		names = append(names, name)
		Exec(t, serverURL(t), "CREATE DATABASE "+name)
	}
	key := digestKey()
	names = append(names, "nyktus_tpl_"+key)

	NewFromTemplate(t, key, func(testing.TB, string) {})

	var oldest, newest bool
	conn := connect(t, serverURL(t))
	for name, exists := range map[string]*bool{names[0]: &oldest, names[len(names)-1]: &newest} {
		if err := conn.QueryRow(t.Context(), "SELECT EXISTS (SELECT FROM pg_database WHERE datname = $1)", name).Scan(exists); err != nil {
			t.Fatalf("look up %s: %v", name, err)
		}
	}
	if oldest {
		t.Error("the oldest template is kept although newer ones fill the quota")
	}
	if !newest {
		t.Error("the template that was just built is gone")
	}
}

// hexDigits returns 24 random lower case hexadecimal digits, the form of a digest key.
func hexDigits(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("read random bytes: %v", err)
	}
	return hex.EncodeToString(raw)
}

// The lock of a process that stopped must not leave the others waiting for the
// timeout of the test binary.
func TestEnsureTemplate_FailsAfterTheWaitForTheLock(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	name := "nyktus_tpl_" + templateKey(t)
	holder := connect(t, serverURL(t))
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_lock(hashtextextended($1, 0))", name); err != nil {
		t.Fatalf("take lock: %v", err)
	}

	defer func() {
		if recover() == nil {
			t.Error("the construction did not fail while another session held the lock")
		}
	}()
	ensureTemplate(failingTB{t}, name, 100*time.Millisecond, func(testing.TB, string) {
		t.Error("the template is prepared while another session holds its lock")
	})
}

func TestNewFromTemplate_RefusesKeysThatDoNotFitAName(t *testing.T) {
	t.Parallel()

	for _, key := range []string{strings.Repeat("a", maxTemplateName), "Upper", "with space", `quote"`} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewFromTemplate(%q) did not fail", key)
				}
			}()
			NewFromTemplate(failingTB{t}, key, func(testing.TB, string) {})
		}()
	}
}

// PostgreSQL cuts longer identifiers without a word, and a cut name no longer
// starts with the prefix by which what a stopped construction left is found.
func TestBuildName_FitsAnIdentifierAndStartsWithItsPrefix(t *testing.T) {
	t.Parallel()

	name := "nyktus_tpl_" + strings.Repeat("a", maxTemplateName-len("nyktus_tpl_"))
	got := buildName(name)
	if len(got) > 63 {
		t.Errorf("len(buildName(%q)) = %d, want at most 63", name, len(got))
	}
	if !strings.HasPrefix(got, buildPrefix(name)) {
		t.Errorf("buildName(%q) = %q, want the prefix %q", name, got, buildPrefix(name))
	}
}
