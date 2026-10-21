// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package schematest_test

import (
	"log/slog"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/migrate"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/migrations"
)

// A digest of everything the migrations leave in a database that a copy could
// lose: objects with their owners and grants, function bodies, constraints,
// triggers and the recorded migrations.
const catalogDigest = `
SELECT md5(string_agg(entry, E'\n' ORDER BY entry)) FROM (
  SELECT 'schema ' || nspname || ' ' || coalesce(nspacl::text, '') || ' ' || pg_get_userbyid(nspowner) AS entry
    FROM pg_namespace WHERE nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema'
  UNION ALL
  SELECT 'class ' || n.nspname || '.' || c.relname || ' ' || c.relkind::text || ' ' || coalesce(c.relacl::text, '') || ' ' || pg_get_userbyid(c.relowner)
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
  UNION ALL
  SELECT 'column ' || attrelid::regclass || '.' || attname || ' ' || coalesce(attacl::text, '')
    FROM pg_attribute JOIN pg_class c ON c.oid = attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE attnum > 0 AND NOT attisdropped AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
  UNION ALL
  SELECT 'function ' || n.nspname || '.' || p.proname || ' ' || coalesce(p.proacl::text, '') || ' ' || md5(p.prosrc) || ' ' || pg_get_userbyid(p.proowner)
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
  UNION ALL
  SELECT 'constraint ' || conname || ' ' || pg_get_constraintdef(oid) FROM pg_constraint
    WHERE connamespace IN (SELECT oid FROM pg_namespace WHERE nspname = 'public')
  UNION ALL
  SELECT 'trigger ' || tgname || ' ' || pg_get_triggerdef(oid) FROM pg_trigger WHERE NOT tgisinternal
  UNION ALL
  SELECT 'migration ' || version || ' ' || name || ' ' || encode(checksum, 'hex') FROM public.schema_migrations
) s`

func TestNew_IsEquivalentToApplyingTheMigrations(t *testing.T) {
	t.Parallel()

	schematest.GroupRoles(t)
	applied := dbtest.New(t)
	all, err := migrate.Load(migrations.FS)
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	pool := schematest.Open(t, applied)
	if _, err := migrate.Apply(t.Context(), pool, all, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	copied := schematest.Open(t, schematest.New(t))

	digest := func(pool *pgxpool.Pool) string {
		var d string
		if err := pool.QueryRow(t.Context(), catalogDigest).Scan(&d); err != nil {
			t.Fatalf("digest catalog: %v", err)
		}
		return d
	}
	if got, want := digest(copied), digest(pool); got != want {
		t.Errorf("catalog digest of schematest.New = %s, want %s of the applied migrations", got, want)
	}
}

func TestTemplateKey_IsTheDigestOfTheMigrations(t *testing.T) {
	t.Parallel()

	got, err := schematest.TemplateKey()
	if err != nil {
		t.Fatalf("TemplateKey() error = %v", err)
	}
	want, err := schematest.Digest(migrations.FS)
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	if got != want {
		t.Errorf("TemplateKey() = %q, want %q: a changed migration would not build a new template", got, want)
	}
}

// A template with an existing key is never rebuilt, so a key that ignores a
// change would let every later run copy the old schema.
func TestDigest_ChangesWithNamesAndContentsOfTheFiles(t *testing.T) {
	t.Parallel()

	files := func(m map[string]string) fstest.MapFS {
		fsys := fstest.MapFS{}
		for name, content := range m {
			fsys[name] = &fstest.MapFile{Data: []byte(content)}
		}
		return fsys
	}
	keys := map[string]string{}
	for name, m := range map[string]map[string]string{
		"base":             {"0001_a.sql": "x", "0002_b.sql": "y"},
		"content changed":  {"0001_a.sql": "x", "0002_b.sql": "z"},
		"name changed":     {"0001_a.sql": "x", "0003_b.sql": "y"},
		"file added":       {"0001_a.sql": "x", "0002_b.sql": "y", "0003_c.sql": ""},
		"file removed":     {"0001_a.sql": "x"},
		"boundary shifted": {"0001_a.sql": "xy", "0002_b.sql": ""},
	} {
		key, err := schematest.Digest(files(m))
		if err != nil {
			t.Fatalf("%s: Digest() error = %v", name, err)
		}
		if other, ok := keys[key]; ok {
			t.Errorf("%q and %q have the same key %s", name, other, key)
		}
		keys[key] = name
	}
}
