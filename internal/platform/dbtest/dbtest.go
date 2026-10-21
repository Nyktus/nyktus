// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dbtest provides isolated PostgreSQL databases for integration tests.
//
// Tests that call New run against the server named by NYKTUS_TEST_DATABASE_URL,
// which must allow creating databases. Without it they are skipped, unless
// NYKTUS_REQUIRE_DB_TESTS=1 is set, as in CI, where a missing database fails the
// test instead of silently skipping it.
package dbtest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// New creates an empty database for the calling test and drops it when the test
// ends. It returns the connection URL of the new database.
func New(tb testing.TB) string {
	tb.Helper()

	dbURL, err := create(tb, "")
	if err != nil {
		tb.Fatalf("create database: %v", err)
	}
	return dbURL
}

// create makes a database for the calling test, as a copy of the database
// template unless that is empty, and drops it when the test ends.
func create(tb testing.TB, template string) (string, error) {
	tb.Helper()

	adminURL := serverURL(tb)
	u, err := url.Parse(adminURL)
	if err != nil {
		tb.Fatalf("parse database url: %v", err)
	}

	name := "nyktus_test_" + strings.ToLower(rand.Text())
	statement := "CREATE DATABASE " + pgx.Identifier{name}.Sanitize()
	if template != "" {
		statement += " TEMPLATE " + pgx.Identifier{template}.Sanitize()
	}
	if err := tryExec(tb, adminURL, statement); err != nil {
		return "", err
	}
	tb.Cleanup(func() {
		exec(tb, adminURL, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	})

	u.Path = "/" + name
	return u.String(), nil
}

// NewFromTemplate creates a database for the calling test as a copy of the
// template of family and key and drops it when the test ends. The template is
// built once per server by prepare, which receives the URL of an empty database
// and fills it, and is kept for later runs, so a copy costs a quarter of what
// preparing a database does. The key must change whenever what prepare does
// changes, for example by holding a digest of its input: a template with an
// existing key is never rebuilt.
//
// A family is one kind of template, such as the migrated schema. Only the newest
// keptTemplates of a family stay on the server, so that every state of the input
// does not leave a database behind. Family and key consist of lower case letters
// and digits.
//
// A copy takes the files of the template and what is stored in it, but nothing
// that belongs to the database itself: its privileges, its settings and its
// comment. What prepare sets of those is lost, and the caller sets it again on
// the database it gets.
func NewFromTemplate(tb testing.TB, family, key string, prepare func(tb testing.TB, dbURL string)) string {
	tb.Helper()

	for _, part := range []string{family, key} {
		if part == "" || strings.Trim(part, "abcdefghijklmnopqrstuvwxyz0123456789") != "" {
			tb.Fatalf("template family %q and key %q must be lower case letters and digits", family, key)
		}
	}
	name := templatePrefix(family) + key
	if len(name) > maxIdentifier {
		tb.Fatalf("template name %q has %d bytes, want at most %d", name, len(name), maxIdentifier)
	}
	// A copy is tried first. Only a server without the template pays for the
	// lock, and a template that another process removed meanwhile is built again.
	dbURL, err := retryMissing(copyAttempts,
		func() (string, error) { return create(tb, name) },
		func() { ensureTemplate(tb, family, name, lockTimeout, prepare) })
	if err != nil {
		tb.Fatalf("create database from template %s: %v", name, err)
	}
	return dbURL
}

// retryMissing calls try up to attempts times. After an attempt that fails
// because the template is missing it calls build, unless that was the last one.
// The last attempt follows the last build.
func retryMissing(attempts int, try func() (string, error), build func()) (string, error) {
	for attempt := 1; ; attempt++ {
		dbURL, err := try()
		if err == nil || !isMissing(err) || attempt == attempts {
			return dbURL, err
		}
		build()
	}
}

// maxIdentifier is the length of the longest identifier PostgreSQL keeps; it cuts
// longer ones without a word.
const maxIdentifier = 63

// copyAttempts is how often a copy is tried: a template that is built and then
// removed by another process's cleanup before it is copied is built again once.
const copyAttempts = 3

// lockTimeout is how long a process waits for another that builds the same
// template. A building takes about a second.
const lockTimeout = time.Minute

// keptTemplates is the number of templates of a family that stay on the server.
// Other checkouts may use older ones, so a few stay.
const keptTemplates = 4

// templatePrefix starts the names of the templates of family.
func templatePrefix(family string) string { return "nyktus_tpl_" + family + "_" }

// ensureTemplate builds the template name unless the server has it. The
// template is built under another name and renamed when it is complete, so that
// a process that stops while it builds leaves no template that looks finished.
//
// A test that waits here holds one connection and has opened none of its own, so
// a server without the template needs no more connections than one with it.
func ensureTemplate(tb testing.TB, family, name string, wait time.Duration, prepare func(tb testing.TB, dbURL string)) {
	tb.Helper()

	adminURL := serverURL(tb)
	ctx := context.WithoutCancel(tb.Context())
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		tb.Fatalf("connect to test database: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	// Packages run in separate processes, so a lock in the database is the only one
	// they share. It belongs to the session and ends with the connection. A process
	// that stops while it holds the lock fails the others after the wait instead of
	// leaving them to the timeout of the test binary. A wait of zero would be none.
	if _, err := conn.Exec(ctx, "SELECT set_config('lock_timeout', $1, false)", strconv.FormatInt(max(wait.Milliseconds(), 1), 10)); err != nil {
		tb.Fatalf("set lock timeout: %v", err)
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(hashtextextended($1, 0))", name); err != nil {
		tb.Fatalf("lock template construction: %v", err)
	}

	var exists bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_database WHERE datname = $1)", name).Scan(&exists); err != nil {
		tb.Fatalf("look up template: %v", err)
	}
	if exists {
		return
	}
	build(ctx, tb, conn, adminURL, name, prepare)

	// The others need not wait for the cleanup.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_unlock(hashtextextended($1, 0))", name); err != nil {
		tb.Logf("release template lock: %v", err)
		return
	}
	prune(ctx, tb, conn, family, name)
}

// buildPrefix starts the names of the databases in which the template name is
// built. It holds a digest of the name, so that it stays short.
func buildPrefix(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "nyktus_tplb_" + hex.EncodeToString(sum[:6]) + "_"
}

// buildName returns the name of a database in which the template name is built.
func buildName(name string) string { return buildPrefix(name) + strings.ToLower(rand.Text())[:16] }

func build(ctx context.Context, tb testing.TB, conn *pgx.Conn, adminURL, name string, prepare func(tb testing.TB, dbURL string)) {
	tb.Helper()

	// Constructions of one template are serialized, so a database of this kind
	// belongs to a process that stopped in the middle.
	rows, err := conn.Query(ctx, "SELECT datname FROM pg_database WHERE starts_with(datname, $1)", buildPrefix(name))
	if err != nil {
		tb.Fatalf("look up unfinished templates: %v", err)
	}
	orphans, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		tb.Fatalf("read unfinished templates: %v", err)
	}
	for _, orphan := range orphans {
		if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{orphan}.Sanitize()+" WITH (FORCE)"); err != nil {
			tb.Fatalf("drop unfinished template %s: %v", orphan, err)
		}
	}

	building := buildName(name)
	ident := pgx.Identifier{building}.Sanitize()
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+ident); err != nil {
		tb.Fatalf("create template: %v", err)
	}
	renamed := false
	defer func() {
		if !renamed {
			_, _ = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+ident+" WITH (FORCE)")
		}
	}()

	u, err := url.Parse(adminURL)
	if err != nil {
		tb.Fatalf("parse database url: %v", err)
	}
	u.Path = "/" + building
	prepare(tb, u.String())

	// A database cannot be copied while a session is connected to it, so prepare
	// must have closed its connections.
	if _, err := conn.Exec(ctx, "ALTER DATABASE "+ident+" RENAME TO "+pgx.Identifier{name}.Sanitize()); err != nil {
		tb.Fatalf("complete template: %v", err)
	}
	renamed = true
}

// prune drops the templates of family beyond the newest keptTemplates, other
// than keep. It is housekeeping: a failure is logged and never fails the test. A
// template that is being copied makes the drop wait, and it gives up after a
// second, so the template stays. One that was dropped in vain is built again by
// whoever finds it missing.
func prune(ctx context.Context, tb testing.TB, conn *pgx.Conn, family, keep string) {
	tb.Helper()

	if _, err := conn.Exec(ctx, "SET lock_timeout = 1000"); err != nil {
		tb.Logf("prune templates: %v", err)
		return
	}
	rows, err := conn.Query(ctx, `SELECT datname FROM pg_database
WHERE starts_with(datname, $1) AND datname <> $2 ORDER BY oid DESC OFFSET $3`, templatePrefix(family), keep, keptTemplates-1)
	if err != nil {
		tb.Logf("look up old templates: %v", err)
		return
	}
	old, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		tb.Logf("read old templates: %v", err)
		return
	}
	for _, name := range old {
		if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()); err != nil {
			tb.Logf("drop old template %s: %v", name, err)
		}
	}
}

// invalidCatalogName is the SQLSTATE of a database that does not exist.
const invalidCatalogName = "3D000"

// isMissing reports whether err says that a database does not exist.
func isMissing(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == invalidCatalogName
}

// GroupRole creates the group role name on the test server unless it exists. It
// stands in for the operator, who creates the group roles of the server roles
// before the first migration.
//
// Roles are global to the server and are not dropped, because tests in other
// packages may use them at the same time. Tests run in parallel, so concurrent
// calls for the same name must all succeed.
func GroupRole(tb testing.TB, name string) {
	tb.Helper()
	exec(tb, serverURL(tb), groupRoleStatement(name))
}

func groupRoleStatement(name string) string {
	// CREATE ROLE has no IF NOT EXISTS. Checking first would race with a
	// concurrent run: both would see no role, and the second CREATE ROLE would wait
	// for the first and then fail with a unique violation instead of
	// duplicate_object.
	return "DO $$ BEGIN CREATE ROLE " + pgx.Identifier{name}.Sanitize() + " NOLOGIN; " +
		"EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$"
}

// serverURL returns the URL of the test server, or skips the test if none is
// configured.
func serverURL(tb testing.TB) string {
	tb.Helper()

	adminURL := os.Getenv("NYKTUS_TEST_DATABASE_URL")
	if adminURL == "" {
		if os.Getenv("NYKTUS_REQUIRE_DB_TESTS") == "1" {
			tb.Fatal("NYKTUS_TEST_DATABASE_URL is not set but database tests are required")
		}
		tb.Skip("NYKTUS_TEST_DATABASE_URL is not set")
	}
	u, err := url.Parse(adminURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		tb.Fatal("NYKTUS_TEST_DATABASE_URL must be a postgres:// URL")
	}
	return adminURL
}

// Role creates a login role for the database at dbURL and drops it, together with
// everything it owns or was granted there, when the test ends. The attributes are
// appended to CREATE ROLE, for example "BYPASSRLS". Role returns the role name and
// a URL that connects to the database as the role.
func Role(tb testing.TB, dbURL, suffix, attributes string) (name, roleURL string) {
	tb.Helper()

	u, err := url.Parse(dbURL)
	if err != nil {
		tb.Fatalf("parse database url: %v", err)
	}
	// Role names are global to the server, so they derive from the unique database name.
	name = strings.TrimPrefix(u.Path, "/") + "_" + suffix
	ident := pgx.Identifier{name}.Sanitize()
	password := rand.Text()

	exec(tb, dbURL, "CREATE ROLE "+ident+" LOGIN PASSWORD '"+password+"' "+attributes)
	tb.Cleanup(func() {
		Exec(tb, dbURL,
			"REASSIGN OWNED BY "+ident+" TO CURRENT_USER",
			"DROP OWNED BY "+ident,
			"DROP ROLE "+ident,
		)
	})

	u.User = url.UserPassword(name, password)
	return name, u.String()
}

// Exec runs statements against the database at dbURL and fails the test on error.
func Exec(tb testing.TB, dbURL string, statements ...string) {
	tb.Helper()
	for _, s := range statements {
		exec(tb, dbURL, s)
	}
}

func exec(tb testing.TB, dbURL, statement string) {
	tb.Helper()
	if err := tryExec(tb, dbURL, statement); err != nil {
		tb.Fatalf("exec %q: %v", statement, err)
	}
}

// tryExec runs statement against the database at dbURL. It fails the test if it
// cannot connect, and returns the error of the statement.
func tryExec(tb testing.TB, dbURL, statement string) error {
	tb.Helper()
	ctx := context.WithoutCancel(tb.Context())
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		tb.Fatalf("connect to test database: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	_, err = conn.Exec(ctx, statement)
	return err
}
