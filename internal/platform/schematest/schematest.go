// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package schematest provides migrated databases for store tests.
//
// Store tests connect with the database role of the server role they belong to,
// not as a superuser, so that a missing grant fails the test as it would fail in
// production.
package schematest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"sync"
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
	DNSRole     = "nyktus_dns"
	WorkerRole  = "nyktus_worker"
)

// GroupRoles creates the group roles of all server roles, as the operator does
// before the first migration.
func GroupRoles(tb testing.TB) {
	tb.Helper()
	dbtest.GroupRole(tb, ConsoleRole)
	dbtest.GroupRole(tb, TriggerRole)
	dbtest.GroupRole(tb, DNSRole)
	dbtest.GroupRole(tb, WorkerRole)
}

// New creates a database with all migrations applied, like "nyktus migrate" on a
// fresh installation, and returns a URL that connects as its owner.
//
// The migrations are applied once per server, to a template named after a digest
// of the migration files, and every database is a copy of it. Tests of the
// migrations themselves apply them to an empty database from dbtest.New.
func New(tb testing.TB) string {
	tb.Helper()

	// The migrations check that the group roles exist, and a copy keeps the
	// grants to them, so they must exist before the template is built.
	GroupRoles(tb)
	key, err := templateKey()
	if err != nil {
		tb.Fatalf("digest migrations: %v", err)
	}
	return dbtest.NewFromTemplate(tb, key, applyMigrations)
}

// templateKey identifies the contents of the migration files.
var templateKey = sync.OnceValues(func() (string, error) { return digest(migrations.FS) })

// digest returns a key that changes with the name or the content of any file of
// fsys.
func digest(fsys fs.FS) (string, error) {
	sum := sha256.New()
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		content, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		// Length prefixes keep the boundaries between names and contents unambiguous.
		_, err = fmt.Fprintf(sum, "%d:%s%d:", len(path), path, len(content))
		sum.Write(content)
		return err
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil))[:24], nil
}

func applyMigrations(tb testing.TB, dbURL string) {
	tb.Helper()

	all, err := migrate.Load(migrations.FS)
	if err != nil {
		tb.Fatalf("load migrations: %v", err)
	}
	// The pool is closed before the database is copied, which needs it unused.
	pool, err := db.Open(tb.Context(), dbURL, db.Options{MaxConns: 1})
	if err != nil {
		tb.Fatalf("open database: %v", err)
	}
	defer pool.Close()
	if _, err := migrate.Apply(tb.Context(), pool, all, slog.New(slog.DiscardHandler)); err != nil {
		tb.Fatalf("apply migrations: %v", err)
	}
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

// DNS creates a migrated database and returns the URL of a login role that is a
// member of the DNS role's group role, as the DNS role connects in production.
func DNS(tb testing.TB) (ownerURL, dnsURL string) {
	tb.Helper()

	ownerURL = New(tb)
	_, dnsURL = dbtest.Role(tb, ownerURL, "dns", "IN ROLE "+pgx.Identifier{DNSRole}.Sanitize())
	return ownerURL, dnsURL
}

// Worker creates a migrated database and returns the URL of a login role that is
// a member of the worker's group role, as the worker connects in production.
func Worker(tb testing.TB) (ownerURL, workerURL string) {
	tb.Helper()

	ownerURL = New(tb)
	_, workerURL = dbtest.Role(tb, ownerURL, "worker", "IN ROLE "+pgx.Identifier{WorkerRole}.Sanitize())
	return ownerURL, workerURL
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
