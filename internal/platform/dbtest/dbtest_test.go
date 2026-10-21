// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dbtest

import (
	"context"
	"crypto/rand"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// templateOf returns a family and a key that no other test uses, and drops the
// databases of the template when the test ends. A family of its own keeps the
// cleanup of the templates of other tests, and of the schema, away from them.
func templateOf(t *testing.T) (family, key, name string) {
	t.Helper()
	family, key = strings.ToLower(rand.Text())[:12], strings.ToLower(rand.Text())[:12]
	name = templatePrefix(family) + key
	t.Cleanup(func() {
		Exec(t, serverURL(t), "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	})
	return family, key, name
}

func exists(t *testing.T, name string) bool {
	t.Helper()
	var found bool
	if err := connect(t, serverURL(t)).QueryRow(t.Context(),
		"SELECT EXISTS (SELECT FROM pg_database WHERE datname = $1)", name).Scan(&found); err != nil {
		t.Fatalf("look up database %s: %v", name, err)
	}
	return found
}

func TestNewFromTemplate_PreparesOncePerKeyAndCopiesIndependently(t *testing.T) {
	t.Parallel()

	var prepared atomic.Int32
	prepare := func(tb testing.TB, dbURL string) {
		tb.Helper()
		prepared.Add(1)
		Exec(tb, dbURL, "CREATE TABLE marker (n int)", "INSERT INTO marker VALUES (1)")
	}
	family, key, _ := templateOf(t)

	first := NewFromTemplate(t, family, key, prepare)
	second := NewFromTemplate(t, family, key, prepare)
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

	family, key, name := templateOf(t)

	func() {
		defer func() {
			if recover() == nil {
				t.Error("a failing preparation did not stop the test")
			}
		}()
		NewFromTemplate(failingTB{t}, family, key, func(tb testing.TB, _ string) {
			tb.Helper()
			tb.Fatalf("preparation failed")
		})
	}()

	if exists(t, name) {
		t.Error("a template exists after a failed preparation, so the next test would copy a half-built database")
	}
	var left int
	if err := connect(t, serverURL(t)).QueryRow(t.Context(),
		"SELECT count(*) FROM pg_database WHERE starts_with(datname, $1)", buildPrefix(name)).Scan(&left); err != nil {
		t.Fatalf("look up unfinished templates: %v", err)
	}
	if left != 0 {
		t.Errorf("%d databases of the failed construction are left", left)
	}

	// The next call builds it.
	var prepared atomic.Int32
	NewFromTemplate(t, family, key, func(testing.TB, string) { prepared.Add(1) })
	if prepared.Load() != 1 {
		t.Error("the preparation did not run again after it had failed")
	}
}

func TestNewFromTemplate_RemovesWhatAStoppedConstructionLeft(t *testing.T) {
	t.Parallel()

	family, key, name := templateOf(t)
	orphan := buildPrefix(name) + "stopped"
	Exec(t, serverURL(t), "CREATE DATABASE "+orphan)
	t.Cleanup(func() { Exec(t, serverURL(t), "DROP DATABASE IF EXISTS "+orphan+" WITH (FORCE)") })

	NewFromTemplate(t, family, key, func(testing.TB, string) {})

	if exists(t, orphan) {
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
	family, key, name := templateOf(t)

	holder := connect(t, serverURL(t))
	var id int64
	if err := holder.QueryRow(ctx, "SELECT hashtextextended($1, 0)", name).Scan(&id); err != nil {
		t.Fatalf("hash key: %v", err)
	}
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_lock($1)", id); err != nil {
		t.Fatalf("take lock: %v", err)
	}

	var prepared atomic.Int32
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			NewFromTemplate(t, family, key, func(testing.TB, string) { prepared.Add(1) })
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
	family, key, name := templateOf(t)

	NewFromTemplate(t, family, key, prepare)
	Exec(t, serverURL(t), "DROP DATABASE "+name)
	NewFromTemplate(t, family, key, prepare)

	if n := prepared.Load(); n != 2 {
		t.Errorf("prepare ran %d times, want 2: a removed template is built again", n)
	}
}

// Another process may remove the template between its construction and the copy.
// The attempt after the last construction must copy, not give up.
func TestRetryMissing_CopiesAfterTheLastConstruction(t *testing.T) {
	t.Parallel()

	missing := &pgconn.PgError{Code: invalidCatalogName}
	for _, tt := range []struct {
		name       string
		failures   int
		wantBuilds int
		wantErr    bool
	}{
		{"present", 0, 0, false},
		{"missing once", 1, 1, false},
		{"missing before the last attempt", copyAttempts - 1, copyAttempts - 1, false},
		{"missing at every attempt", copyAttempts, copyAttempts - 1, true},
	} {
		builds, tries := 0, 0
		_, err := retryMissing(copyAttempts,
			func() (string, error) {
				tries++
				if tries <= tt.failures {
					return "", missing
				}
				return "url", nil
			},
			func() { builds++ })
		if builds != tt.wantBuilds || (err != nil) != tt.wantErr {
			t.Errorf("%s: %d builds and error %v, want %d builds and error %v", tt.name, builds, err, tt.wantBuilds, tt.wantErr)
		}
	}

	// Another error is not a missing template and ends the attempts.
	builds := 0
	_, err := retryMissing(copyAttempts, func() (string, error) { return "", errors.New("refused") }, func() { builds++ })
	if err == nil || builds != 0 {
		t.Errorf("another error: %d builds and error %v, want none and an error", builds, err)
	}
}

func TestNewFromTemplate_KeepsTheNewestTemplatesOfAFamily(t *testing.T) {
	t.Parallel()

	family, key, _ := templateOf(t)
	// Another family, older than all that are kept in this one.
	_, _, otherName := templateOf(t)
	Exec(t, serverURL(t), "CREATE DATABASE "+otherName)
	var names []string
	t.Cleanup(func() {
		for _, name := range names {
			Exec(t, serverURL(t), "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		}
	})
	// Older than the template that is built below, and as many as are kept.
	for i := range keptTemplates {
		name := templatePrefix(family) + "old" + strconv.Itoa(i)
		names = append(names, name)
		Exec(t, serverURL(t), "CREATE DATABASE "+name)
	}

	NewFromTemplate(t, family, key, func(testing.TB, string) {})

	if exists(t, names[0]) {
		t.Error("the oldest template is kept although newer ones fill the quota")
	}
	if !exists(t, names[len(names)-1]) {
		t.Error("a template within the quota is gone")
	}
	if !exists(t, templatePrefix(family)+key) {
		t.Error("the template that was just built is gone")
	}
	if !exists(t, otherName) {
		t.Error("a template of another family was removed")
	}
}

// The lock of a process that stopped must not leave the others waiting for the
// timeout of the test binary.
func TestEnsureTemplate_FailsAfterTheWaitForTheLock(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	family, _, name := templateOf(t)
	holder := connect(t, serverURL(t))
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_lock(hashtextextended($1, 0))", name); err != nil {
		t.Fatalf("take lock: %v", err)
	}

	defer func() {
		if recover() == nil {
			t.Error("the construction did not fail while another session held the lock")
		}
	}()
	// A wait below a millisecond must not mean no limit.
	ensureTemplate(failingTB{t}, family, name, time.Microsecond, func(testing.TB, string) {
		t.Error("the template is prepared while another session holds its lock")
	})
}

func TestNewFromTemplate_RefusesFamiliesAndKeysThatDoNotFitAName(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct{ family, key string }{
		{"", "key"},
		{"family", ""},
		{"Upper", "key"},
		{"family", "with space"},
		{"family", `quote"`},
		{"family", "under_score"},
		{"family", strings.Repeat("a", maxIdentifier)},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewFromTemplate(%q, %q) did not fail", tt.family, tt.key)
				}
			}()
			NewFromTemplate(failingTB{t}, tt.family, tt.key, func(testing.TB, string) {})
		}()
	}
}

// PostgreSQL cuts longer identifiers without a word, and a cut name no longer
// starts with the prefix by which what a stopped construction left is found.
func TestBuildName_FitsAnIdentifierAndStartsWithItsPrefix(t *testing.T) {
	t.Parallel()

	name := templatePrefix("family") + strings.Repeat("a", maxIdentifier-len(templatePrefix("family")))
	got := buildName(name)
	if len(got) > maxIdentifier {
		t.Errorf("len(buildName(%q)) = %d, want at most %d", name, len(got), maxIdentifier)
	}
	if !strings.HasPrefix(got, buildPrefix(name)) {
		t.Errorf("buildName(%q) = %q, want the prefix %q", name, got, buildPrefix(name))
	}
}
