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
