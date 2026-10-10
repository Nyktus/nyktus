// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package migrate applies forward-only schema migrations.
//
// Migration files are named NNNN_description.sql and numbered without gaps from
// 0001. Every applied migration is recorded with the SHA-256 checksum of its file.
// A changed checksum aborts the run, because a released migration must never be
// edited, and a recorded version that the binary does not know aborts it as well,
// because the database is then newer than the binary.
package migrate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"regexp"
	"slices"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// lockKey is the PostgreSQL advisory lock that serializes concurrent runs.
const lockKey int64 = 0x6e796b7475730001

var fileName = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

// Migration is a single schema change.
type Migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum [sha256.Size]byte
}

// Load reads the migrations from the root of fsys. Every file must follow the
// naming scheme, and versions must start at 1 without gaps.
func Load(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}

	migrations := make([]Migration, 0, len(entries))
	for _, e := range entries {
		m := fileName.FindStringSubmatch(e.Name())
		if e.IsDir() || m == nil {
			return nil, fmt.Errorf("unexpected entry %q in migrations; expected NNNN_description.sql", e.Name())
		}
		version, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, fmt.Errorf("parse version of %q: %w", e.Name(), err)
		}
		content, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", e.Name(), err)
		}
		migrations = append(migrations, Migration{
			Version:  version,
			Name:     m[2],
			SQL:      string(content),
			Checksum: sha256.Sum256(content),
		})
	}

	slices.SortFunc(migrations, func(a, b Migration) int { return a.Version - b.Version })
	for i, m := range migrations {
		if i > 0 && m.Version == migrations[i-1].Version {
			return nil, fmt.Errorf("duplicate migration version %04d", m.Version)
		}
		if m.Version != i+1 {
			return nil, fmt.Errorf("migration versions must be numbered from 1 without gaps; expected %04d, found %04d", i+1, m.Version)
		}
	}
	return migrations, nil
}

// ErrChecksumMismatch is returned when an applied migration has been edited.
var ErrChecksumMismatch = errors.New("applied migration has been modified")

// ErrUnknownVersion is returned when the database records a migration that is not
// part of this binary.
var ErrUnknownVersion = errors.New("database schema is newer than this binary")

// Apply applies all pending migrations in order, each in its own transaction, and
// returns how many were applied.
func Apply(ctx context.Context, pool *pgxpool.Pool, migrations []Migration, logger *slog.Logger) (int, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", lockKey); err != nil {
		return 0, fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		// Releasing the connection to the pool keeps the session alive, so the lock
		// must be released explicitly, even when the run failed.
		_, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", lockKey)
	}()

	// The table is schema-qualified, so that a search_path that differs between runs
	// or roles cannot create a second, empty history and reapply every migration.
	if _, err := conn.Exec(ctx, `
CREATE TABLE IF NOT EXISTS public.schema_migrations (
	version    integer PRIMARY KEY CHECK (version > 0),
	name       text NOT NULL,
	checksum   bytea NOT NULL CHECK (octet_length(checksum) = 32),
	applied_at timestamptz NOT NULL DEFAULT now()
)`); err != nil {
		return 0, fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, err := appliedChecksums(ctx, conn.Conn())
	if err != nil {
		return 0, err
	}
	if err := verify(migrations, applied); err != nil {
		return 0, err
	}

	count := 0
	for _, m := range migrations {
		if _, ok := applied[m.Version]; ok {
			continue
		}
		if err := apply(ctx, conn.Conn(), m); err != nil {
			return count, err
		}
		count++
		logger.InfoContext(ctx, "migrate: applied migration", slog.Int("version", m.Version), slog.String("name", m.Name))
	}
	return count, nil
}

func appliedChecksums(ctx context.Context, conn *pgx.Conn) (map[int][]byte, error) {
	rows, err := conn.Query(ctx, "SELECT version, checksum FROM public.schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("read applied migrations: %w", err)
	}
	applied := make(map[int][]byte)
	var (
		version  int
		checksum []byte
	)
	_, err = pgx.ForEachRow(rows, []any{&version, &checksum}, func() error {
		applied[version] = slices.Clone(checksum)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read applied migrations: %w", err)
	}
	return applied, nil
}

func verify(migrations []Migration, applied map[int][]byte) error {
	known := make(map[int]Migration, len(migrations))
	for _, m := range migrations {
		known[m.Version] = m
	}
	// Sorted, so that the oldest problem is reported first and on every run.
	for _, version := range slices.Sorted(maps.Keys(applied)) {
		m, ok := known[version]
		if !ok {
			return fmt.Errorf("%w: version %04d is applied but unknown", ErrUnknownVersion, version)
		}
		if !bytes.Equal(applied[version], m.Checksum[:]) {
			return fmt.Errorf("%w: %04d_%s", ErrChecksumMismatch, m.Version, m.Name)
		}
	}
	return nil
}

func apply(ctx context.Context, conn *pgx.Conn, m Migration) error {
	err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			return fmt.Errorf("execute: %w", err)
		}
		_, err := tx.Exec(ctx, "INSERT INTO public.schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
			m.Version, m.Name, m.Checksum[:])
		if err != nil {
			return fmt.Errorf("record: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("apply migration %04d_%s: %w", m.Version, m.Name, err)
	}
	return nil
}
