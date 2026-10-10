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
	"testing"

	"github.com/jackc/pgx/v5"
)

// New creates an empty database for the calling test and drops it when the test
// ends. It returns the connection URL of the new database.
func New(tb testing.TB) string {
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

	name := "nyktus_test_" + strings.ToLower(rand.Text())
	exec(tb, adminURL, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	tb.Cleanup(func() {
		exec(tb, adminURL, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	})

	u.Path = "/" + name
	return u.String()
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
