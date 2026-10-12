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

// Group roles of the server roles.
const (
	ConsoleRole = "nyktus_console"
	TriggerRole = "nyktus_trigger"
)

// GroupRoles creates the group roles of all server roles, as the operator does
// before the first migration.
func GroupRoles(tb testing.TB) {
	tb.Helper()
	dbtest.GroupRole(tb, ConsoleRole)
	dbtest.GroupRole(tb, TriggerRole)
}

// New creates a database with all migrations applied, like "nyktus migrate" on a
// fresh installation, and returns a URL that connects as its owner.
func New(tb testing.TB) string {
	tb.Helper()

	dbURL := dbtest.New(tb)
	GroupRoles(tb)

	all, err := migrate.Load(migrations.FS)
	if err != nil {
		tb.Fatalf("load migrations: %v", err)
	}
	// The pool is closed right away, so that parallel tests do not hold idle
	// connections they no longer need.
	pool, err := db.Open(tb.Context(), dbURL, db.Options{MaxConns: 1})
	if err != nil {
		tb.Fatalf("open database: %v", err)
	}
	defer pool.Close()
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

// Trigger creates a migrated database and returns the URL of a login role that is
// a member of the trigger's group role, as the trigger connects in production.
func Trigger(tb testing.TB) (ownerURL, triggerURL string) {
	tb.Helper()

	ownerURL = New(tb)
	_, triggerURL = dbtest.Role(tb, ownerURL, "trigger", "IN ROLE "+pgx.Identifier{TriggerRole}.Sanitize())
	return ownerURL, triggerURL
}

// Open connects to dbURL and closes the pool when the test ends. The pool holds
// at most two connections, enough for a test that holds a transaction while the
// code under test waits for it. Packages and their tests run in parallel, and
// larger pools would exhaust the connections of the test server.
func Open(tb testing.TB, dbURL string) *pgxpool.Pool {
	tb.Helper()

	pool, err := db.Open(tb.Context(), dbURL, db.Options{MaxConns: 2})
	if err != nil {
		tb.Fatalf("open database: %v", err)
	}
	tb.Cleanup(pool.Close)
	return pool
}
