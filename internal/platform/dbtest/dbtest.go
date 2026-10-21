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
// template key and drops it when the test ends. The template is built once per
// server by prepare, which receives the URL of an empty database and fills it,
// and is kept for later runs, so a copy costs a quarter of what preparing a
// database does. The key must change whenever what prepare does changes, for
// example by holding a digest of its input: a template with an existing key is
// never rebuilt.
//
// A copy takes the files of the template and what is stored in it, but nothing
// that belongs to the database itself: its privileges, its settings and its
// comment. What prepare needs of those cannot be done in prepare.
//
// Keys of 24 lowercase hexadecimal digits are digests of a caller that keeps a
// template for every state of its input. Only the newest keptTemplates of those
// stay on the server. Other keys are for the caller to drop.
func NewFromTemplate(tb testing.TB, key string, prepare func(tb testing.TB, dbURL string)) string {
	tb.Helper()

	name := "nyktus_tpl_" + key
	if len(name) > maxTemplateName || strings.Trim(key, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
		tb.Fatalf("template key %q must be lower case letters, digits and underscores, and %q at most %d bytes", key, name, maxTemplateName)
	}
	// A copy is tried first. Only a server without the template pays for the
	// lock, and a template that another process removed meanwhile is built again.
	for range 3 {
		dbURL, err := create(tb, name)
		if err == nil {
			return dbURL
		}
		if !isMissing(err) {
			tb.Fatalf("create database from template: %v", err)
		}
		ensureTemplate(tb, name, lockTimeout, prepare)
	}
	tb.Fatalf("template %s keeps disappearing", name)
	return ""
}

// maxTemplateName leaves room in the 63 bytes of a PostgreSQL identifier for the
// prefix and suffix of the database in which a template is built.
const maxTemplateName = 40

// lockTimeout is how long a process waits for another that builds the same
// template. A building takes about a second.
const lockTimeout = time.Minute

// keptTemplates is the number of templates with a digest as their key that stay
// on the server. Other checkouts may use older ones, so a few stay.
const keptTemplates = 4

// ensureTemplate builds the template name unless the server has it. The
// template is built under another name and renamed when it is complete, so that
// a process that stops while it builds leaves no template that looks finished.
func ensureTemplate(tb testing.TB, name string, wait time.Duration, prepare func(tb testing.TB, dbURL string)) {
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
	// leaving them to the timeout of the test binary.
	if _, err := conn.Exec(ctx, "SELECT set_config('lock_timeout', $1, false)", strconv.FormatInt(wait.Milliseconds(), 10)); err != nil {
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
	prune(ctx, tb, conn, name)
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

// prune drops the templates with a digest as their key beyond the newest
// keptTemplates, other than keep. A template that is being copied cannot be
// dropped; it stays, and one that was dropped in vain is built again by whoever
// finds it missing.
func prune(ctx context.Context, tb testing.TB, conn *pgx.Conn, keep string) {
	tb.Helper()

	rows, err := conn.Query(ctx, `SELECT datname FROM pg_database
WHERE datname ~ '^nyktus_tpl_[0-9a-f]{24}$' AND datname <> $1 ORDER BY oid DESC OFFSET $2`, keep, keptTemplates-1)
	if err != nil {
		tb.Fatalf("look up old templates: %v", err)
	}
	old, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		tb.Fatalf("read old templates: %v", err)
	}
	for _, name := range old {
		_, _ = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize())
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
