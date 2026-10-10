// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/migrate"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/migrations"
)

func TestApply_RevokesPublicSchemaPrivileges(t *testing.T) {
	t.Parallel()

	pool := schematest.Open(t, schematest.New(t))
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

	err := apply(t, roleURL, load(t))
	if err == nil || !strings.Contains(err.Error(), "run migrations as the owner of the schema") {
		t.Errorf("Apply() error = %v, want the schema ownership error", err)
	}
}

func TestApply_FailsWithoutConsoleRole(t *testing.T) {
	t.Parallel()

	// Roles are global to the server, and other tests create nyktus_console, so
	// the migrations refer to a role that certainly does not exist instead.
	missing := "nyktus_missing_" + strings.ToLower(rand.Text())
	all := load(t)
	for i := range all {
		all[i].SQL = strings.ReplaceAll(all[i].SQL, schematest.ConsoleRole, missing)
	}

	dbURL := dbtest.New(t)
	err := apply(t, dbURL, all)
	want := "database role " + missing + " does not exist; create the server roles with deploy/postgres/roles.sql"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Apply() error = %v, want it to contain %q", err, want)
	}

	var table *string
	if err := schematest.Open(t, dbURL).QueryRow(t.Context(), "SELECT to_regclass('public.users')::text").Scan(&table); err != nil {
		t.Fatalf("query table: %v", err)
	}
	if table != nil {
		t.Error("the failed migration left the users table behind")
	}
}

func TestRolesScript_CreatesConsoleRoleIdempotently(t *testing.T) {
	t.Parallel()

	script, err := os.ReadFile("../deploy/postgres/roles.sql")
	if err != nil {
		t.Fatalf("read roles script: %v", err)
	}
	dbURL := dbtest.New(t)
	dbtest.Exec(t, dbURL, string(script), string(script))

	var canLogin bool
	err = schematest.Open(t, dbURL).QueryRow(t.Context(), "SELECT rolcanlogin FROM pg_roles WHERE rolname = $1", schematest.ConsoleRole).Scan(&canLogin)
	if err != nil {
		t.Fatalf("query role %s: %v", schematest.ConsoleRole, err)
	}
	if canLogin {
		t.Errorf("role %s can log in, want a group role", schematest.ConsoleRole)
	}
}

func TestConsoleRole_PassesLeastPrivilegeCheck(t *testing.T) {
	t.Parallel()

	_, consoleURL := schematest.Console(t)
	if err := db.CheckLeastPrivilege(t.Context(), schematest.Open(t, consoleURL)); err != nil {
		t.Errorf("CheckLeastPrivilege() error = %v, want nil", err)
	}
}

func TestConsoleRole_HasOnlyGrantedPrivileges(t *testing.T) {
	t.Parallel()

	_, consoleURL := schematest.Console(t)
	pool := schematest.Open(t, consoleURL)

	allowed := []string{
		"SELECT count(*) FROM users",
		"INSERT INTO users (email, display_name, role, status) VALUES ('a@example.com', 'A', 'viewer', 'pending')",
		"UPDATE users SET display_name = 'B', updated_at = now()",
		"DELETE FROM users",
	}
	for _, statement := range allowed {
		if _, err := pool.Exec(t.Context(), statement); err != nil {
			t.Errorf("%s: error = %v, want nil", statement, err)
		}
	}

	denied := []string{
		"SELECT * FROM schema_migrations",
		"CREATE TABLE extra (id int)",
		"INSERT INTO users (id, email, display_name, role, status) VALUES (gen_random_uuid(), 'b@example.com', 'B', 'viewer', 'pending')",
		"INSERT INTO users (email, display_name, role, status, created_at) VALUES ('c@example.com', 'C', 'viewer', 'pending', now())",
		"UPDATE users SET id = gen_random_uuid()",
		"UPDATE users SET created_at = now()",
		"TRUNCATE users",
	}
	for _, statement := range denied {
		_, err := pool.Exec(t.Context(), statement)
		var pgErr *pgconn.PgError
		// 42501 is insufficient_privilege.
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s: error = %v, want insufficient_privilege", statement, err)
		}
	}
}

func load(t *testing.T) []migrate.Migration {
	t.Helper()
	all, err := migrate.Load(migrations.FS)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return all
}

func apply(t *testing.T, dbURL string, all []migrate.Migration) error {
	t.Helper()
	_, err := migrate.Apply(t.Context(), schematest.Open(t, dbURL), all, slog.New(slog.DiscardHandler))
	return err
}
