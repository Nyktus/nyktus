// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package db opens PostgreSQL connection pools and verifies that application roles
// connect without excessive privileges.
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// defaultConnectTimeout bounds each connection attempt when the URL does not set
// connect_timeout. Without it, an unreachable host that drops packets blocks the
// start until the operating system gives up.
const defaultConnectTimeout = 10 * time.Second

// Options configures a connection pool.
type Options struct {
	// MaxConns limits the number of open connections. Zero keeps the pgx default.
	MaxConns int32
}

// Open connects to the database at url and verifies the connection.
func Open(ctx context.Context, url string, opts Options) (*pgxpool.Pool, error) {
	cfg, err := parseConfig(url, opts)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	return pool, nil
}

func parseConfig(url string, opts Options) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		// pgx redacts the password in parse errors, so the error is safe to log.
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	if cfg.ConnConfig.ConnectTimeout == 0 {
		cfg.ConnConfig.ConnectTimeout = defaultConnectTimeout
	}
	if opts.MaxConns > 0 {
		cfg.MaxConns = opts.MaxConns
	}
	return cfg, nil
}

// Querier is the subset of pgx used to run a single query.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ErrExcessivePrivileges is returned when an application role could bypass the
// privilege separation between server roles.
var ErrExcessivePrivileges = errors.New("database role has excessive privileges")

// CheckLeastPrivilege returns ErrExcessivePrivileges if the connected role could
// read or write data beyond its grants, or grant itself more privileges. Such a role
// would make the per-role grants meaningless.
//
// The server file and program roles count as excessive because they give access to
// the data files and the operating system account of the server, which bypasses
// every grant. A replication role can copy the whole cluster with a base backup.
//
// Membership is checked with MEMBER rather than USAGE, because a member that does
// not inherit privileges can still switch to the role with SET ROLE.
func CheckLeastPrivilege(ctx context.Context, q Querier) error {
	const query = `
SELECT r.rolname, r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb, r.rolreplication,
	pg_has_role(r.oid, 'pg_read_all_data', 'MEMBER'),
	pg_has_role(r.oid, 'pg_write_all_data', 'MEMBER'),
	pg_has_role(r.oid, 'pg_read_server_files', 'MEMBER'),
	pg_has_role(r.oid, 'pg_write_server_files', 'MEMBER'),
	pg_has_role(r.oid, 'pg_execute_server_program', 'MEMBER'),
	pg_has_role(r.oid, d.datdba, 'MEMBER'),
	pg_has_role(r.oid, n.nspowner, 'MEMBER')
FROM pg_roles r, pg_database d, pg_namespace n
WHERE r.rolname = current_user
	AND d.datname = current_database()
	AND n.nspname = current_schema()`

	var (
		name                                                    string
		superuser, bypassRLS, createRole, createDB, replication bool
		readAll, writeAll, readFiles, writeFiles, execProgram   bool
		ownsDatabase, ownsSchema                                bool
	)
	err := q.QueryRow(ctx, query).Scan(&name, &superuser, &bypassRLS, &createRole, &createDB, &replication,
		&readAll, &writeAll, &readFiles, &writeFiles, &execProgram, &ownsDatabase, &ownsSchema)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("check database privileges: no current schema; check the search_path of the role")
	}
	if err != nil {
		return fmt.Errorf("check database privileges: %w", err)
	}

	var reason string
	switch {
	case superuser:
		reason = "is a superuser"
	case bypassRLS:
		reason = "can bypass row-level security"
	case createRole:
		reason = "can create roles"
	case createDB:
		reason = "can create databases"
	case replication:
		reason = "can start replication"
	case readAll:
		reason = "is a member of pg_read_all_data"
	case writeAll:
		reason = "is a member of pg_write_all_data"
	case readFiles:
		reason = "is a member of pg_read_server_files"
	case writeFiles:
		reason = "is a member of pg_write_server_files"
	case execProgram:
		reason = "is a member of pg_execute_server_program"
	case ownsDatabase:
		reason = "owns the database; use a separate owner role for migrations"
	case ownsSchema:
		reason = "owns the schema; use a separate owner role for migrations"
	default:
		return nil
	}
	return fmt.Errorf("%w: role %q %s", ErrExcessivePrivileges, name, reason)
}
