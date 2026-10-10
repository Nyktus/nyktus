// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/migrate"
)

func TestApply_RevokesPublicSchemaPrivileges(t *testing.T) {
	t.Parallel()

	dbURL := dbtest.New(t)
	if err := applyAll(t, dbURL); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	pool := open(t, dbURL)
	var usage, create bool
	err := pool.QueryRow(t.Context(),
		"SELECT has_schema_privilege('public', 'public', 'USAGE'), has_schema_privilege('public', 'public', 'CREATE')",
	).Scan(&usage, &create)
	if err != nil {
		t.Fatalf("query schema privileges: %v", err)
	}
	if usage || create {
		t.Errorf("PUBLIC privileges on schema public: usage=%v create=%v, want none", usage, create)
	}
}

func TestApply_FailsWithoutSchemaOwnership(t *testing.T) {
	t.Parallel()

	dbURL := dbtest.New(t)
	role, roleURL := dbtest.Role(t, dbURL, "migrator", "")
	dbtest.Exec(t, dbURL, "GRANT CREATE ON SCHEMA public TO "+pgx.Identifier{role}.Sanitize())

	err := applyAll(t, roleURL)
	if err == nil || !strings.Contains(err.Error(), "run migrations as the owner of the schema") {
		t.Errorf("Apply() error = %v, want the schema ownership error", err)
	}
}

func applyAll(t *testing.T, dbURL string) error {
	t.Helper()
	all, err := migrate.Load(FS)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	_, err = migrate.Apply(t.Context(), open(t, dbURL), all, slog.New(slog.DiscardHandler))
	return err
}

func open(t *testing.T, dbURL string) *pgxpool.Pool {
	t.Helper()
	pool, err := db.Open(t.Context(), dbURL, db.Options{MaxConns: 1})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
