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
	"github.com/jackc/pgx/v5/pgconn"
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

// Querier runs queries on a connection pool or inside a transaction. Stores work on
// a Querier instead of a pool, so that a caller can combine several stores in one
// transaction, for example an action and its audit entry.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
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

// ErrRolePrivileges is returned when a role that may only execute one function
// holds other privileges, or lacks that one.
var ErrRolePrivileges = errors.New("database role holds other privileges than its group role")

// CheckFunctionOnly returns ErrRolePrivileges unless the connected role can
// execute function and do nothing else in schema public: it must not access any
// table, create objects in the schema, execute another function of the schema,
// or be a member of a role other than groupRole. function is a signature such as
// "public.record(text, inet)".
//
// The roles that answer requests from the internet hold nothing but their
// recording function. A login with the privileges of the console, set up by
// mistake, would put the inventory within reach of whoever takes over their
// host; a login without the function would answer every request and record
// none.
//
// Membership counts even without inheritance, because a member can switch to
// the role with SET ROLE.
func CheckFunctionOnly(ctx context.Context, q Querier, groupRole, function string) error {
	// Without USAGE on the schema, the signature cannot be resolved, so a role
	// that is no member of groupRole would fail with a permission error instead.
	var canUse bool
	if err := q.QueryRow(ctx, `SELECT has_schema_privilege('public', 'USAGE')`).Scan(&canUse); err != nil {
		return fmt.Errorf("check privileges of %s: %w", groupRole, err)
	}
	if !canUse {
		return fmt.Errorf("%w: it cannot execute %s; connect as a member of %s", ErrRolePrivileges, function, groupRole)
	}

	var (
		canExecute, canCreate bool
		tables, functions     []string
		roles                 []string
	)
	err := q.QueryRow(ctx, `
SELECT has_function_privilege($1::regprocedure, 'EXECUTE'),
	has_schema_privilege('public', 'CREATE'),
	ARRAY(
		SELECT c.relname::text FROM pg_catalog.pg_class AS c
		WHERE c.relnamespace = 'public'::regnamespace
			AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
			AND (has_table_privilege(c.oid, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
				OR has_any_column_privilege(c.oid, 'SELECT, INSERT, UPDATE, REFERENCES'))
		ORDER BY 1
	),
	ARRAY(
		SELECT p.oid::regprocedure::text FROM pg_catalog.pg_proc AS p
		WHERE p.pronamespace = 'public'::regnamespace
			AND p.oid <> $1::regprocedure
			AND has_function_privilege(p.oid, 'EXECUTE')
		ORDER BY 1
	),
	ARRAY(
		SELECT r.rolname::text FROM pg_catalog.pg_roles AS r
		WHERE pg_has_role(current_user, r.oid, 'MEMBER')
			AND r.rolname NOT IN (current_user, $2)
		ORDER BY 1
	)`, function, groupRole).Scan(&canExecute, &canCreate, &tables, &functions, &roles)
	switch {
	case err != nil:
		return fmt.Errorf("check privileges of %s: %w", groupRole, err)
	case !canExecute:
		return fmt.Errorf("%w: it cannot execute %s; connect as a member of %s", ErrRolePrivileges, function, groupRole)
	case len(roles) > 0:
		return fmt.Errorf("%w: it is a member of %v; connect with a login that is a member of %s only", ErrRolePrivileges, roles, groupRole)
	case len(tables) > 0:
		return fmt.Errorf("%w: it can access the tables %v", ErrRolePrivileges, tables)
	case len(functions) > 0:
		return fmt.Errorf("%w: it can execute %v", ErrRolePrivileges, functions)
	case canCreate:
		return fmt.Errorf("%w: it can create objects in schema public", ErrRolePrivileges)
	}
	return nil
}
