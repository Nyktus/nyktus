// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package schematest provides migrated databases for store tests.
//
// Store tests connect with the database role of the server role they belong to,
// not as a superuser, so that a missing grant fails the test as it would fail in
// production.
package schematest

import (
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/migrate"
	"nyktus.org/nyktus/migrations"
)

// ConsoleRole is the group role of the console.
const ConsoleRole = "nyktus_console"

// New creates a database with all migrations applied, like "nyktus migrate" on a
// fresh installation, and returns a URL that connects as its owner.
func New(tb testing.TB) string {
	tb.Helper()

	dbURL := dbtest.New(tb)
	dbtest.GroupRole(tb, ConsoleRole)

	all, err := migrate.Load(migrations.FS)
	if err != nil {
		tb.Fatalf("load migrations: %v", err)
	}
	pool := Open(tb, dbURL)
	if _, err := migrate.Apply(tb.Context(), pool, all, slog.New(slog.DiscardHandler)); err != nil {
		tb.Fatalf("apply migrations: %v", err)
	}
	return dbURL
}

// Console creates a migrated database and returns the URL of a login role that is
// a member of the console's group role, as the console connects in production.
func Console(tb testing.TB) (ownerURL, consoleURL string) {
	tb.Helper()

	ownerURL = New(tb)
	_, consoleURL = dbtest.Role(tb, ownerURL, "console", "IN ROLE "+pgx.Identifier{ConsoleRole}.Sanitize())
	return ownerURL, consoleURL
}

// Open connects to dbURL and closes the pool when the test ends.
func Open(tb testing.TB, dbURL string) *pgxpool.Pool {
	tb.Helper()

	pool, err := db.Open(tb.Context(), dbURL, db.Options{MaxConns: 4})
	if err != nil {
		tb.Fatalf("open database: %v", err)
	}
	tb.Cleanup(pool.Close)
	return pool
}
