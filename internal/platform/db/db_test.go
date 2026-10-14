// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/platform/dbtest"
)

func TestOpen_ParseErrorDoesNotLeakPassword(t *testing.T) {
	t.Parallel()

	_, err := Open(t.Context(), "postgres://user:hunter2@db:notaport/nyktus", Options{})
	if err == nil {
		t.Fatal("Open() accepted an invalid URL")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error leaks the password: %v", err)
	}
}

func TestParseConfig_ConnectTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		url  string
		want time.Duration
	}{
		{url: "postgres://db/nyktus", want: defaultConnectTimeout},
		{url: "postgres://db/nyktus?connect_timeout=3", want: 3 * time.Second},
	}
	for _, tt := range tests {
		cfg, err := parseConfig(tt.url, Options{})
		if err != nil {
			t.Fatalf("parseConfig(%q) error = %v", tt.url, err)
		}
		if got := cfg.ConnConfig.ConnectTimeout; got != tt.want {
			t.Errorf("parseConfig(%q) connect timeout = %v, want %v", tt.url, got, tt.want)
		}
	}
}

func TestCheckLeastPrivilege(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// asCreator connects as the superuser that created the test database
		// instead of a new role.
		asCreator  bool
		attributes string
		// grant is run by the test database's superuser with the role and database
		// identifiers as arguments.
		grant func(role, database string) string
		// wantReason is empty if the role must pass.
		wantReason string
	}{
		{name: "superuser", asCreator: true, wantReason: "is a superuser"},
		{name: "bypassrls", attributes: "BYPASSRLS", wantReason: "can bypass row-level security"},
		{name: "createrole", attributes: "CREATEROLE", wantReason: "can create roles"},
		{name: "createdb", attributes: "CREATEDB", wantReason: "can create databases"},
		{
			name:       "member of pg_read_all_data",
			grant:      func(role, _ string) string { return "GRANT pg_read_all_data TO " + role },
			wantReason: "pg_read_all_data",
		},
		{
			name:       "member of pg_write_all_data without inheritance",
			grant:      func(role, _ string) string { return "GRANT pg_write_all_data TO " + role + " WITH INHERIT FALSE" },
			wantReason: "pg_write_all_data",
		},
		{name: "replication", attributes: "REPLICATION", wantReason: "can start replication"},
		{
			name:       "member of pg_read_server_files",
			grant:      func(role, _ string) string { return "GRANT pg_read_server_files TO " + role },
			wantReason: "pg_read_server_files",
		},
		{
			name:       "member of pg_write_server_files",
			grant:      func(role, _ string) string { return "GRANT pg_write_server_files TO " + role },
			wantReason: "pg_write_server_files",
		},
		{
			name: "member of pg_execute_server_program without inheritance",
			grant: func(role, _ string) string {
				return "GRANT pg_execute_server_program TO " + role + " WITH INHERIT FALSE"
			},
			wantReason: "pg_execute_server_program",
		},
		{
			name:       "database owner",
			grant:      func(role, database string) string { return "ALTER DATABASE " + database + " OWNER TO " + role },
			wantReason: "owns the database",
		},
		{
			name:       "schema owner",
			grant:      func(role, _ string) string { return "ALTER SCHEMA public OWNER TO " + role },
			wantReason: "owns the schema",
		},
		{name: "unprivileged application role"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dbURL := dbtest.New(t)
			roleURL := dbURL
			if !tt.asCreator {
				var role string
				role, roleURL = dbtest.Role(t, dbURL, "app", tt.attributes)
				if tt.grant != nil {
					u, err := url.Parse(dbURL)
					if err != nil {
						t.Fatalf("parse database url: %v", err)
					}
					database := strings.TrimPrefix(u.Path, "/")
					dbtest.Exec(t, dbURL, tt.grant(pgx.Identifier{role}.Sanitize(), pgx.Identifier{database}.Sanitize()))
				}
			}

			pool, err := Open(t.Context(), roleURL, Options{MaxConns: 1})
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			defer pool.Close()

			err = CheckLeastPrivilege(t.Context(), pool)
			switch {
			case tt.wantReason == "" && err != nil:
				t.Errorf("CheckLeastPrivilege() error = %v, want nil", err)
			case tt.wantReason != "" && !errors.Is(err, ErrExcessivePrivileges):
				t.Errorf("CheckLeastPrivilege() error = %v, want ErrExcessivePrivileges", err)
			case tt.wantReason != "" && !strings.Contains(err.Error(), tt.wantReason):
				t.Errorf("CheckLeastPrivilege() error = %v, want reason %q", err, tt.wantReason)
			}
		})
	}
}

// A role that answers requests from the internet passes the check only while it
// can execute its function and nothing else.
func TestCheckFunctionOnly(t *testing.T) {
	t.Parallel()

	dbURL := dbtest.New(t)
	group, _ := dbtest.Role(t, dbURL, "group", "")
	other, _ := dbtest.Role(t, dbURL, "other", "")
	groupIdent, otherIdent := pgx.Identifier{group}.Sanitize(), pgx.Identifier{other}.Sanitize()
	dbtest.Exec(t, dbURL,
		"REVOKE ALL ON SCHEMA public FROM PUBLIC",
		"CREATE TABLE public.inventory (id int)",
		"CREATE FUNCTION public.record(v text) RETURNS int LANGUAGE sql AS 'SELECT 1'",
		"CREATE FUNCTION public.other() RETURNS int LANGUAGE sql AS 'SELECT 1'",
		"REVOKE ALL ON FUNCTION public.record(text), public.other() FROM PUBLIC",
		"GRANT USAGE ON SCHEMA public TO "+groupIdent,
		"GRANT EXECUTE ON FUNCTION public.record(text) TO "+groupIdent,
	)
	const function = "public.record(text)"

	tests := []struct {
		suffix, attributes string
		grant              string
		// want is empty if the role must pass.
		want string
	}{
		{suffix: "member", attributes: "IN ROLE " + groupIdent},
		{suffix: "outsider", want: "cannot execute public.record(text)"},
		{suffix: "usage", grant: "GRANT USAGE ON SCHEMA public TO %s", want: "cannot execute public.record(text)"},
		{suffix: "both", attributes: "IN ROLE " + groupIdent + ", " + otherIdent, want: "member of [" + other + "]"},
		// A member that does not inherit can still switch to the role.
		{suffix: "noinherit", attributes: "IN ROLE " + groupIdent, grant: "GRANT " + otherIdent + " TO %s WITH INHERIT FALSE", want: "member of [" + other + "]"},
		{suffix: "table", attributes: "IN ROLE " + groupIdent, grant: "GRANT SELECT ON public.inventory TO %s", want: "tables [inventory]"},
		{suffix: "column", attributes: "IN ROLE " + groupIdent, grant: "GRANT SELECT (id) ON public.inventory TO %s", want: "tables [inventory]"},
		{suffix: "function", attributes: "IN ROLE " + groupIdent, grant: "GRANT EXECUTE ON FUNCTION public.other() TO %s", want: "execute [other()]"},
		{suffix: "create", attributes: "IN ROLE " + groupIdent, grant: "GRANT CREATE ON SCHEMA public TO %s", want: "create objects"},
	}
	for _, tt := range tests {
		name, roleURL := dbtest.Role(t, dbURL, tt.suffix, tt.attributes)
		if tt.grant != "" {
			dbtest.Exec(t, dbURL, strings.ReplaceAll(tt.grant, "%s", pgx.Identifier{name}.Sanitize()))
		}
		pool, err := Open(t.Context(), roleURL, Options{MaxConns: 1})
		if err != nil {
			t.Fatalf("Open(%s) error = %v", tt.suffix, err)
		}
		err = CheckFunctionOnly(t.Context(), pool, group, function)
		pool.Close()
		switch {
		case tt.want == "" && err != nil:
			t.Errorf("CheckFunctionOnly(%s) = %v, want nil", tt.suffix, err)
		case tt.want != "" && (!errors.Is(err, ErrRolePrivileges) || !strings.Contains(err.Error(), tt.want)):
			t.Errorf("CheckFunctionOnly(%s) = %v, want ErrRolePrivileges containing %q", tt.suffix, err, tt.want)
		}
	}
}

// A role that works on tables passes the check only while it reaches no table
// beyond its own and can execute its functions and no other.
func TestCheckScope(t *testing.T) {
	t.Parallel()

	dbURL := dbtest.New(t)
	group, _ := dbtest.Role(t, dbURL, "group", "")
	groupIdent := pgx.Identifier{group}.Sanitize()
	dbtest.Exec(t, dbURL,
		"REVOKE ALL ON SCHEMA public FROM PUBLIC",
		"CREATE TABLE public.jobs (id int)",
		"CREATE TABLE public.inventory (id int)",
		"CREATE FUNCTION public.valid(v text) RETURNS boolean LANGUAGE sql AS 'SELECT true'",
		"CREATE FUNCTION public.other() RETURNS int LANGUAGE sql AS 'SELECT 1'",
		"REVOKE ALL ON FUNCTION public.valid(text), public.other() FROM PUBLIC",
		"GRANT USAGE ON SCHEMA public TO "+groupIdent,
		"GRANT SELECT, DELETE ON public.jobs TO "+groupIdent,
		"GRANT EXECUTE ON FUNCTION public.valid(text) TO "+groupIdent,
	)
	withFunction := Scope{GroupRole: group, Tables: []string{"jobs"}, Functions: []string{"public.valid(text)"}}
	tablesOnly := Scope{GroupRole: group, Tables: []string{"jobs"}}

	tests := []struct {
		suffix, attributes, grant string
		scope                     Scope
		// want is empty if the role must pass.
		want string
	}{
		{suffix: "member", attributes: "IN ROLE " + groupIdent, scope: withFunction},
		{suffix: "outsider", scope: withFunction, want: "cannot execute public.valid(text)"},
		{suffix: "outsidertables", scope: tablesOnly, want: "cannot use schema public"},
		{suffix: "nofunction", attributes: "IN ROLE " + groupIdent, scope: Scope{GroupRole: group, Tables: []string{"jobs"}, Functions: []string{"public.other()"}}, want: "cannot execute public.other()"},
		{suffix: "table", attributes: "IN ROLE " + groupIdent, scope: withFunction, grant: "GRANT SELECT ON public.inventory TO %s", want: "tables [inventory]"},
		{suffix: "column", attributes: "IN ROLE " + groupIdent, scope: withFunction, grant: "GRANT UPDATE (id) ON public.inventory TO %s", want: "tables [inventory]"},
		// Functions the scope does not name count, even if the group may
		// execute them.
		{suffix: "function", attributes: "IN ROLE " + groupIdent, scope: tablesOnly, want: "execute [valid(text)]"},
		{suffix: "create", attributes: "IN ROLE " + groupIdent, scope: withFunction, grant: "GRANT CREATE ON SCHEMA public TO %s", want: "create objects"},
		// The login may not hold more on the tables of the scope than its
		// group role.
		{suffix: "ownbeyond", attributes: "IN ROLE " + groupIdent, scope: withFunction, grant: "GRANT TRUNCATE ON public.jobs TO %s", want: "privileges that " + group + " lacks: [jobs: TRUNCATE]"},
		{suffix: "owncolumn", attributes: "IN ROLE " + groupIdent, scope: withFunction, grant: "GRANT UPDATE (id) ON public.jobs TO %s", want: "lacks: [jobs.id: UPDATE]"},
	}
	for _, tt := range tests {
		name, roleURL := dbtest.Role(t, dbURL, tt.suffix, tt.attributes)
		if tt.grant != "" {
			dbtest.Exec(t, dbURL, strings.ReplaceAll(tt.grant, "%s", pgx.Identifier{name}.Sanitize()))
		}
		pool, err := Open(t.Context(), roleURL, Options{MaxConns: 1})
		if err != nil {
			t.Fatalf("Open(%s) error = %v", tt.suffix, err)
		}
		err = CheckScope(t.Context(), pool, tt.scope)
		pool.Close()
		switch {
		case tt.want == "" && err != nil:
			t.Errorf("CheckScope(%s) = %v, want nil", tt.suffix, err)
		case tt.want != "" && (!errors.Is(err, ErrRolePrivileges) || !strings.Contains(err.Error(), tt.want)):
			t.Errorf("CheckScope(%s) = %v, want ErrRolePrivileges containing %q", tt.suffix, err, tt.want)
		}
	}
}
