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
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

// New creates an empty database for the calling test and drops it when the test
// ends. It returns the connection URL of the new database.
func New(tb testing.TB) string {
	tb.Helper()
	return create(tb, "")
}

// NewFromTemplate creates a database for the calling test as a copy of the
// template key and drops it when the test ends. The template is built once per
// server by prepare, which receives the URL of an empty database and fills it,
// and is kept for later runs, so a copy costs a quarter of what preparing a
// database does. The key must change whenever what prepare does changes, for
// example by holding a digest of its input: a template with an existing key is
// never rebuilt.
func NewFromTemplate(tb testing.TB, key string, prepare func(tb testing.TB, dbURL string)) string {
	tb.Helper()
	return create(tb, ensureTemplate(tb, key, prepare))
}

func create(tb testing.TB, template string) string {
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
	exec(tb, adminURL, statement)
	tb.Cleanup(func() {
		exec(tb, adminURL, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	})

	u.Path = "/" + name
	return u.String()
}

// readyTemplates remembers, per process, the templates known to exist on the
// server, so that only the first test asks the server.
var (
	readyMu        sync.Mutex
	readyTemplates = map[string]bool{}
)

// ensureTemplate returns the name of the template key, building it if the server
// has none. The template is built under another name and renamed when it is
// complete, so that a process that stops while it builds leaves no template that
// looks finished. Templates of other keys stay: another checkout may still use
// them, and a container is thrown away anyway.
func ensureTemplate(tb testing.TB, key string, prepare func(tb testing.TB, dbURL string)) string {
	tb.Helper()

	adminURL := serverURL(tb)
	name := "nyktus_tpl_" + key
	readyMu.Lock()
	defer readyMu.Unlock()
	if readyTemplates[adminURL+name] {
		return name
	}

	ctx := context.WithoutCancel(tb.Context())
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		tb.Fatalf("connect to test database: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	// Packages run in separate processes, so a lock in the database is the only one
	// they share. It belongs to the session and ends with the connection.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(hashtextextended($1, 0))", name); err != nil {
		tb.Fatalf("lock template construction: %v", err)
	}

	var exists bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_database WHERE datname = $1)", name).Scan(&exists); err != nil {
		tb.Fatalf("look up template: %v", err)
	}
	if !exists {
		build(ctx, tb, conn, adminURL, name, prepare)
	}
	readyTemplates[adminURL+name] = true
	return name
}

// buildPrefix starts the names of the databases in which the template name is
// built.
func buildPrefix(name string) string { return "nyktus_tplbuild_" + name + "_" }

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

	building := buildPrefix(name) + strings.ToLower(rand.Text())
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
	ctx := context.WithoutCancel(tb.Context())
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		tb.Fatalf("connect to test database: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, statement); err != nil {
		tb.Fatalf("exec %q: %v", statement, err)
	}
}
