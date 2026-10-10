// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrate

import (
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/dbtest"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	fsys := fstest.MapFS{
		"0002_second.sql": {Data: []byte("SELECT 2;")},
		"0001_first.sql":  {Data: []byte("SELECT 1;")},
	}
	migrations, err := Load(fsys)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(migrations) != 2 || migrations[0].Name != "first" || migrations[1].Version != 2 {
		t.Errorf("Load() = %+v, want two migrations in version order", migrations)
	}
}

func TestLoad_RejectsInvalidSets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fsys fstest.MapFS
		want string
	}{
		{name: "gap", fsys: fstest.MapFS{"0001_a.sql": {}, "0003_c.sql": {}}, want: "expected 0002, found 0003"},
		{name: "not starting at 1", fsys: fstest.MapFS{"0002_b.sql": {}}, want: "expected 0001, found 0002"},
		{name: "duplicate version", fsys: fstest.MapFS{"0001_a.sql": {}, "0001_b.sql": {}}, want: "duplicate migration version 0001"},
		{name: "invalid name", fsys: fstest.MapFS{"0001_A-B.sql": {}}, want: `unexpected entry "0001_A-B.sql"`},
		{name: "foreign file", fsys: fstest.MapFS{"0001_a.sql": {}, "README.md": {}}, want: `unexpected entry "README.md"`},
		{name: "directory", fsys: fstest.MapFS{"0001_a.sql": {}, "0002_dir/x.sql": {}}, want: `unexpected entry "0002_dir"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(tt.fsys)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Load() error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestVerify_ReportsOldestProblemFirst(t *testing.T) {
	t.Parallel()

	migrations := mustLoad(t, fstest.MapFS{
		"0001_a.sql": {Data: []byte("SELECT 1;")},
		"0002_b.sql": {Data: []byte("SELECT 2;")},
		"0003_c.sql": {Data: []byte("SELECT 3;")},
	})
	applied := map[int][]byte{1: {0}, 2: {0}, 3: {0}}
	// Map iteration order varies between runs, so a single run could pass by chance.
	for range 20 {
		err := verify(migrations, applied)
		if !errors.Is(err, ErrChecksumMismatch) || !strings.Contains(err.Error(), "0001_a") {
			t.Fatalf("verify() error = %v, want a checksum mismatch for 0001_a", err)
		}
	}
}

func TestApply_AppliesPendingMigrationsOnce(t *testing.T) {
	t.Parallel()

	pool := openPool(t)
	first := mustLoad(t, fstest.MapFS{"0001_create.sql": {Data: []byte("CREATE TABLE things (id integer PRIMARY KEY);")}})

	if n, err := Apply(t.Context(), pool, first, discard()); err != nil || n != 1 {
		t.Fatalf("first Apply() = %d, %v; want 1 applied", n, err)
	}
	if n, err := Apply(t.Context(), pool, first, discard()); err != nil || n != 0 {
		t.Fatalf("repeated Apply() = %d, %v; want 0 applied", n, err)
	}

	both := mustLoad(t, fstest.MapFS{
		"0001_create.sql": {Data: []byte("CREATE TABLE things (id integer PRIMARY KEY);")},
		"0002_insert.sql": {Data: []byte("INSERT INTO things VALUES (1);")},
	})
	if n, err := Apply(t.Context(), pool, both, discard()); err != nil || n != 1 {
		t.Fatalf("Apply() with a new migration = %d, %v; want 1 applied", n, err)
	}

	var count int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM things").Scan(&count); err != nil || count != 1 {
		t.Errorf("things row count = %d, %v; want 1", count, err)
	}
}

func TestApply_RejectsModifiedMigration(t *testing.T) {
	t.Parallel()

	pool := openPool(t)
	original := mustLoad(t, fstest.MapFS{"0001_create.sql": {Data: []byte("CREATE TABLE things (id integer);")}})
	if _, err := Apply(t.Context(), pool, original, discard()); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	edited := mustLoad(t, fstest.MapFS{"0001_create.sql": {Data: []byte("CREATE TABLE things (id bigint);")}})
	if _, err := Apply(t.Context(), pool, edited, discard()); !errors.Is(err, ErrChecksumMismatch) {
		t.Errorf("Apply() error = %v, want ErrChecksumMismatch", err)
	}
}

func TestApply_RejectsDatabaseNewerThanBinary(t *testing.T) {
	t.Parallel()

	pool := openPool(t)
	newer := mustLoad(t, fstest.MapFS{"0001_a.sql": {Data: []byte("SELECT 1;")}, "0002_b.sql": {Data: []byte("SELECT 2;")}})
	if _, err := Apply(t.Context(), pool, newer, discard()); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	older := newer[:1]
	if _, err := Apply(t.Context(), pool, older, discard()); !errors.Is(err, ErrUnknownVersion) {
		t.Errorf("Apply() error = %v, want ErrUnknownVersion", err)
	}
}

func TestApply_HistoryIsIndependentOfSearchPath(t *testing.T) {
	t.Parallel()

	dbURL := dbtest.New(t)
	dbtest.Exec(t, dbURL, "CREATE SCHEMA elsewhere")
	migrations := mustLoad(t, fstest.MapFS{"0001_a.sql": {Data: []byte("SELECT 1;")}})

	if n, err := Apply(t.Context(), openPoolAt(t, dbURL), migrations, discard()); err != nil || n != 1 {
		t.Fatalf("Apply() = %d, %v; want 1 applied", n, err)
	}
	other := openPoolAt(t, withSearchPath(t, dbURL, "elsewhere,public"))
	if n, err := Apply(t.Context(), other, migrations, discard()); err != nil || n != 0 {
		t.Fatalf("Apply() with another search_path = %d, %v; want 0 applied", n, err)
	}

	var misplaced bool
	if err := other.QueryRow(t.Context(), "SELECT to_regclass('elsewhere.schema_migrations') IS NOT NULL").Scan(&misplaced); err != nil {
		t.Fatalf("query: %v", err)
	}
	if misplaced {
		t.Error("schema_migrations was created in the first schema of the search_path")
	}
}

func withSearchPath(t *testing.T, dbURL, searchPath string) string {
	t.Helper()
	u, err := url.Parse(dbURL)
	if err != nil {
		t.Fatalf("parse database url: %v", err)
	}
	q := u.Query()
	q.Set("search_path", searchPath)
	u.RawQuery = q.Encode()
	return u.String()
}

func TestApply_FailedMigrationLeavesNoTrace(t *testing.T) {
	t.Parallel()

	pool := openPool(t)
	migrations := mustLoad(t, fstest.MapFS{
		"0001_ok.sql":     {Data: []byte("CREATE TABLE ok (id integer);")},
		"0002_broken.sql": {Data: []byte("CREATE TABLE partial (id integer); SELECT * FROM missing_table;")},
	})

	n, err := Apply(t.Context(), pool, migrations, discard())
	if err == nil || n != 1 || !strings.Contains(err.Error(), "0002_broken") {
		t.Fatalf("Apply() = %d, %v; want 1 applied and an error naming 0002_broken", n, err)
	}

	var partialExists, recorded bool
	if err := pool.QueryRow(t.Context(), "SELECT to_regclass('partial') IS NOT NULL").Scan(&partialExists); err != nil {
		t.Fatalf("query: %v", err)
	}
	if err := pool.QueryRow(t.Context(), "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 2)").Scan(&recorded); err != nil {
		t.Fatalf("query: %v", err)
	}
	if partialExists || recorded {
		t.Errorf("failed migration left changes behind: table=%v, recorded=%v", partialExists, recorded)
	}
}

func TestApply_ReleasesLock(t *testing.T) {
	t.Parallel()

	pool := openPool(t)
	migrations := mustLoad(t, fstest.MapFS{"0001_broken.sql": {Data: []byte("SELECT * FROM missing_table;")}})
	if _, err := Apply(t.Context(), pool, migrations, discard()); err == nil {
		t.Fatal("Apply() succeeded with a broken migration")
	}

	var locked bool
	if err := pool.QueryRow(t.Context(), "SELECT pg_try_advisory_lock($1)", lockKey).Scan(&locked); err != nil {
		t.Fatalf("query: %v", err)
	}
	if !locked {
		t.Error("migration lock is still held after a failed run")
	}
}

func openPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return openPoolAt(t, dbtest.New(t))
}

func openPoolAt(t *testing.T, dbURL string) *pgxpool.Pool {
	t.Helper()
	pool, err := db.Open(t.Context(), dbURL, db.Options{MaxConns: 2})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func mustLoad(t *testing.T, fsys fstest.MapFS) []Migration {
	t.Helper()
	migrations, err := Load(fsys)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return migrations
}

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }
