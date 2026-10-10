// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dbtest

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestGroupRole_IsIdempotent(t *testing.T) {
	t.Parallel()

	name := uniqueRoleName(t)
	GroupRole(t, name)
	GroupRole(t, name)

	conn := connect(t, serverURL(t))
	var canLogin bool
	if err := conn.QueryRow(t.Context(), "SELECT rolcanlogin FROM pg_roles WHERE rolname = $1", name).Scan(&canLogin); err != nil {
		t.Fatalf("query role: %v", err)
	}
	if canLogin {
		t.Errorf("role %s can log in, want a group role", name)
	}
}

// The second creation starts while the first is uncommitted, so it cannot see the
// role yet and has to wait for the first transaction to end.
func TestGroupRole_ConcurrentCreationSucceeds(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	name := uniqueRoleName(t)
	first := connect(t, serverURL(t))
	second := connect(t, serverURL(t))

	tx, err := first.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, groupRoleStatement(name)); err != nil {
		t.Fatalf("create role in first transaction: %v", err)
	}

	var secondPID uint32
	if err := second.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&secondPID); err != nil {
		t.Fatalf("query backend pid: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := second.Exec(ctx, groupRoleStatement(name))
		done <- err
	}()

	waitUntilBlocked(t, tx, secondPID)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit first transaction: %v", err)
	}
	if err := <-done; err != nil {
		t.Errorf("concurrent GroupRole statement error = %v, want nil", err)
	}
}

// waitUntilBlocked returns once the backend pid waits for a lock held by another
// session. It polls the lock state instead of sleeping for a fixed time, so the
// test does not depend on timing.
func waitUntilBlocked(t *testing.T, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, pid uint32,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for {
		var blocked bool
		if err := q.QueryRow(ctx, "SELECT cardinality(pg_blocking_pids($1)) > 0", pid).Scan(&blocked); err != nil {
			t.Fatalf("query blocking pids: %v", err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("second session never waited for the first")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func uniqueRoleName(t *testing.T) string {
	t.Helper()
	name := "nyktus_test_group_" + strings.ToLower(rand.Text())
	t.Cleanup(func() { Exec(t, serverURL(t), "DROP ROLE IF EXISTS "+pgx.Identifier{name}.Sanitize()) })
	return name
}

func connect(t *testing.T, dbURL string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(t.Context(), dbURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.WithoutCancel(t.Context())) })
	return conn
}
