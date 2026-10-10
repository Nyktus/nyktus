// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package setup_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/auth/setup"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/user"
)

// testHash has the format of an encoded Argon2id hash. These tests do not need a
// real hash, and computing one would only slow them down.
const testHash = "$argon2id$v=19$m=65536,t=3,p=4$AAECAwQFBgcICQoLDA0ODw$hTsnKkTbFCHAKWJmmlXrCZTzyrOF7RxMeSU+7hm6tJ4"

var tokenFormat = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// testDB is a migrated database with a pool of the owner, for setting up state
// that the console cannot create, and a pool of the console's database role.
type testDB struct {
	owner, console *pgxpool.Pool
}

func newTestDB(t *testing.T) testDB {
	t.Helper()
	ownerURL, consoleURL := schematest.Console(t)
	return testDB{owner: schematest.Open(t, ownerURL), console: schematest.Open(t, consoleURL)}
}

func (d testDB) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := d.owner.Exec(t.Context(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (d testDB) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := d.owner.QueryRow(t.Context(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func issue(t *testing.T, svc *setup.Service) setup.Token {
	t.Helper()
	tok, ok, err := svc.Issue(t.Context())
	if err != nil || !ok {
		t.Fatalf("Issue() = %v, %v; want a token", ok, err)
	}
	return tok
}

func admin(email string) setup.Admin {
	return setup.Admin{Email: email, DisplayName: "Ada Admin", PasswordHash: testHash}
}

func digest(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func TestIssue_StoresOnlyTheHashOfARandomToken(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	svc := setup.NewService(d.console)
	first, second := issue(t, svc), issue(t, svc)

	for _, tok := range []setup.Token{first, second} {
		if !tokenFormat.MatchString(tok.Value) {
			t.Errorf("token %q does not encode 32 bytes in base64url", tok.Value)
		}
		var lifetime time.Duration
		err := d.owner.QueryRow(t.Context(),
			`SELECT extract(epoch FROM expires_at - clock_timestamp()) * interval '1 second' FROM setup_tokens WHERE token_hash = $1`,
			digest(tok.Value)).Scan(&lifetime)
		if err != nil {
			t.Fatalf("read token by its SHA-256 hash: %v", err)
		}
		if lifetime <= 59*time.Minute || lifetime > time.Hour {
			t.Errorf("token expires in %v, want one hour", lifetime)
		}
		if tok.ExpiresAt.Location() != time.UTC {
			t.Errorf("ExpiresAt = %v, want UTC", tok.ExpiresAt)
		}
	}
	if first.Value == second.Value {
		t.Error("two tokens are equal")
	}
}

// Tokens of other console processes stay valid, so that a setup request can reach
// any of them behind a load balancer.
func TestIssue_KeepsValidTokensAndRemovesExpiredOnes(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	svc := setup.NewService(d.console)
	other, expired := issue(t, svc), issue(t, svc)
	d.exec(t, `UPDATE setup_tokens SET expires_at = clock_timestamp() - interval '1 second' WHERE token_hash = $1`, digest(expired.Value))

	current := issue(t, svc)
	for _, tt := range []struct {
		tok  setup.Token
		want bool
	}{{other, true}, {expired, false}, {current, true}} {
		if n := d.count(t, `SELECT count(*) FROM setup_tokens WHERE token_hash = $1`, digest(tt.tok.Value)); (n == 1) != tt.want {
			t.Errorf("token stored = %v, want %v", n == 1, tt.want)
		}
	}
}

func TestIssue_IssuesNoTokenOnceAnAdministratorExists(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	d.exec(t, `INSERT INTO users (email, display_name, role, status) VALUES ('ada@example.com', 'Ada', 'admin', 'deactivated')`)
	tok, ok, err := setup.NewService(d.console).Issue(t.Context())
	if err != nil || ok || tok != (setup.Token{}) {
		t.Errorf("Issue() = %+v, %v, %v; want no token", tok, ok, err)
	}
	if n := d.count(t, `SELECT count(*) FROM setup_tokens`); n != 0 {
		t.Errorf("%d tokens stored, want none", n)
	}
}

// Every start of every console process issues a token or finds the setup closed.
// Once it is closed, a start must not wait for the setup lock, which another
// session may hold.
func TestIssue_TakesNoLockOnceAnAdministratorExists(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	d.exec(t, `INSERT INTO users (email, display_name, role, status) VALUES ('ada@example.com', 'Ada', 'admin', 'pending')`)
	holder, err := d.owner.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = holder.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := holder.Exec(t.Context(), `LOCK TABLE setup_tokens IN EXCLUSIVE MODE`); err != nil {
		t.Fatalf("lock: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, ok, err := setup.NewService(d.console).Issue(t.Context())
		if err == nil && ok {
			err = errors.New("issued a token")
		}
		done <- err
	}()
	// Either Issue returns, or it waits for the lock, which pg_locks shows.
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Issue() error = %v, want no token and no error", err)
			}
			return
		default:
		}
		var waiting bool
		err := d.owner.QueryRow(t.Context(),
			`SELECT EXISTS (SELECT FROM pg_locks WHERE relation = 'public.setup_tokens'::regclass AND NOT granted)`).Scan(&waiting)
		if err != nil {
			t.Fatalf("query locks: %v", err)
		}
		if waiting {
			t.Fatal("Issue() waits for the setup lock although an administrator exists")
		}
	}
}

func TestToken_FormattingHidesTheValue(t *testing.T) {
	t.Parallel()

	tok := setup.Token{Value: "secret-token-value", ExpiresAt: time.Date(2026, 10, 10, 19, 0, 0, 0, time.UTC)}
	for format, out := range map[string]string{
		"%v":    fmt.Sprintf("%v", tok),
		"%+v":   fmt.Sprintf("%+v", tok),
		"%#v":   fmt.Sprintf("%#v", tok),
		"%q":    fmt.Sprintf("%q", tok),
		"error": fmt.Errorf("announce %v: %w", tok, errors.New("failed")).Error(),
	} {
		if strings.Contains(out, tok.Value) {
			t.Errorf("format %s leaks the token: %s", format, out)
		}
	}
}

func TestComplete_CreatesActiveAdministratorWithAuditEntry(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	svc := setup.NewService(d.console)
	tok := issue(t, svc)
	issue(t, svc)

	u, err := svc.Complete(t.Context(), tok.Value, admin("Ada@Example.com"))
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if u.Email != "ada@example.com" || u.Role != user.RoleAdmin || u.Status != user.StatusActive || u.PasswordHash != testHash {
		t.Errorf("Complete() = %+v, want an active administrator with the hash", u)
	}

	var actorKind, authMethod, resourceType, resourceID string
	err = d.owner.QueryRow(t.Context(), `
SELECT actor_kind, auth_method, resource_type, resource_id::text FROM audit_entries
WHERE action = 'user.create' AND outcome = 'success' AND actor_user_id IS NULL`).
		Scan(&actorKind, &authMethod, &resourceType, &resourceID)
	if err != nil {
		t.Fatalf("read audit entry: %v", err)
	}
	if actorKind != "setup" || authMethod != "setup_token" || resourceType != "user" || resourceID != u.ID {
		t.Errorf("audit entry = %s/%s %s/%s, want setup/setup_token user/%s", actorKind, authMethod, resourceType, resourceID, u.ID)
	}
	if n := d.count(t, `SELECT count(*) FROM setup_tokens`); n != 0 {
		t.Errorf("%d tokens remain after the setup, want none", n)
	}
	if open, err := svc.Open(t.Context()); err != nil || open {
		t.Errorf("Open() = %v, %v; want false", open, err)
	}
}

func TestComplete_RejectsInvalidTokens(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	svc := setup.NewService(d.console)
	expired, valid := issue(t, svc), issue(t, svc)
	d.exec(t, `UPDATE setup_tokens SET expires_at = clock_timestamp() - interval '1 second' WHERE token_hash = $1`, digest(expired.Value))

	for name, token := range map[string]string{
		"unknown":       strings.Repeat("A", 43),
		"empty":         "",
		"expired":       expired.Value,
		"prefix":        valid.Value[:42],
		"hash as token": string(digest(valid.Value)),
	} {
		if ok, err := svc.Valid(t.Context(), token); err != nil || ok {
			t.Errorf("Valid(%s) = %v, %v; want false", name, ok, err)
		}
		if _, err := svc.Complete(t.Context(), token, admin("ada@example.com")); !errors.Is(err, setup.ErrInvalidToken) {
			t.Errorf("Complete(%s) error = %v, want ErrInvalidToken", name, err)
		}
	}
	if n := d.count(t, `SELECT count(*) FROM users`) + d.count(t, `SELECT count(*) FROM audit_entries`); n != 0 {
		t.Errorf("rejected setups left %d users and audit entries, want none", n)
	}
	if ok, err := svc.Valid(t.Context(), valid.Value); err != nil || !ok {
		t.Errorf("Valid(valid) = %v, %v; want true after the rejected attempts", ok, err)
	}
}

func TestComplete_IsClosedOnceAnAdministratorExists(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	svc := setup.NewService(d.console)
	first, second := issue(t, svc), issue(t, svc)
	if _, err := svc.Complete(t.Context(), first.Value, admin("ada@example.com")); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}

	for name, token := range map[string]string{"used token": first.Value, "token of another process": second.Value} {
		if _, err := svc.Complete(t.Context(), token, admin("eve@example.com")); !errors.Is(err, setup.ErrClosed) {
			t.Errorf("Complete(%s) error = %v, want ErrClosed", name, err)
		}
	}
	if n := d.count(t, `SELECT count(*) FROM users`); n != 1 {
		t.Errorf("%d users, want 1", n)
	}
}

// Once a process has seen an administrator, it answers the setup as closed without
// asking the database again.
func TestOpen_StaysClosedOnceAnAdministratorWasSeen(t *testing.T) {
	t.Parallel()

	tests := map[string]func(t *testing.T, d testDB, svc *setup.Service){
		"created through this service": func(t *testing.T, _ testDB, svc *setup.Service) {
			t.Helper()
			if _, err := svc.Complete(t.Context(), issue(t, svc).Value, admin("ada@example.com")); err != nil {
				t.Fatalf("Complete() error = %v", err)
			}
		},
		"created elsewhere": func(t *testing.T, d testDB, _ *setup.Service) {
			t.Helper()
			d.exec(t, `INSERT INTO users (email, display_name, role, status) VALUES ('ada@example.com', 'Ada', 'admin', 'pending')`)
		},
	}
	for name, create := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			d := newTestDB(t)
			svc := setup.NewService(d.console)
			if open, err := svc.Open(t.Context()); err != nil || !open {
				t.Fatalf("Open() before the setup = %v, %v; want true", open, err)
			}
			create(t, d, svc)
			if open, err := svc.Open(t.Context()); err != nil || open {
				t.Fatalf("Open() with an administrator = %v, %v; want false", open, err)
			}

			d.exec(t, `DELETE FROM users`)
			if open, err := svc.Open(t.Context()); err != nil || open {
				t.Errorf("Open() after the administrator was removed = %v, %v; want false for the rest of the process", open, err)
			}
		})
	}
}

// The administrator, the consumed token and the audit entry are one transaction:
// if the entry cannot be written, the setup has not happened and the token can be
// used again.
func TestComplete_FailsWithoutItsAuditEntry(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	svc := setup.NewService(d.console)
	tok := issue(t, svc)
	// Grants are objects of the test database, so this does not affect other tests.
	d.exec(t, `REVOKE INSERT ON audit_entries FROM `+pgx.Identifier{schematest.ConsoleRole}.Sanitize())

	if _, err := svc.Complete(t.Context(), tok.Value, admin("ada@example.com")); err == nil {
		t.Fatal("Complete() succeeded without its audit entry")
	}
	if n := d.count(t, `SELECT count(*) FROM users`); n != 0 {
		t.Errorf("%d users created, want none", n)
	}
	if ok, err := svc.Valid(t.Context(), tok.Value); err != nil || !ok {
		t.Errorf("Valid() = %v, %v; want the token to remain valid", ok, err)
	}
}

// lockedElsewhere reports whether another transaction holds the setup lock on the
// setup tokens. ROW SHARE conflicts only with EXCLUSIVE and ACCESS EXCLUSIVE, not
// with the ROW EXCLUSIVE lock that every insert and delete takes, so the probe
// detects the setup lock and nothing else.
func lockedElsewhere(t *testing.T, pool *pgxpool.Pool) bool {
	t.Helper()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `LOCK TABLE setup_tokens IN ROW SHARE MODE NOWAIT`)
		return err
	})
	var pgErr *pgconn.PgError
	// 55P03 is lock_not_available.
	if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
		return true
	}
	if err != nil {
		t.Fatalf("lock setup tokens: %v", err)
	}
	return false
}

func TestServiceHoldsTheSetupLockUntilCommit(t *testing.T) {
	t.Parallel()

	tests := map[string]func(t *testing.T, svc *setup.Service, token string){
		"Issue": func(t *testing.T, svc *setup.Service, _ string) {
			t.Helper()
			issue(t, svc)
		},
		"Complete": func(t *testing.T, svc *setup.Service, token string) {
			t.Helper()
			if _, err := svc.Complete(t.Context(), token, admin("ada@example.com")); err != nil {
				t.Fatalf("Complete() error = %v", err)
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			d := newTestDB(t)
			tok := issue(t, setup.NewService(d.console))
			if lockedElsewhere(t, d.console) {
				t.Fatal("setup tokens are locked before the test")
			}

			tx, err := d.console.Begin(t.Context())
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
			// On a transaction, the service works in a savepoint, so the
			// transaction stays open after the call returns.
			run(t, setup.NewService(tx), tok.Value)
			if !lockedElsewhere(t, d.console) {
				t.Errorf("%s does not hold the lock on the setup tokens until its transaction ends", name)
			}
		})
	}
}

// waitForLockWaiter returns once a session waits for a lock on the setup tokens.
// It polls the lock table instead of sleeping, so it neither depends on timing
// nor returns before the waiter has reached the lock.
func waitForLockWaiter(t *testing.T, pool *pgxpool.Pool, done <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		var waiting bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT FROM pg_locks WHERE relation = 'public.setup_tokens'::regclass AND NOT granted)`).
			Scan(&waiting)
		if err != nil {
			t.Fatalf("query locks: %v", err)
		}
		if waiting {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("Complete() returned without waiting for the lock: %v", err)
		default:
		}
	}
}

// Two console processes have issued two tokens. While one setup is creating an
// administrator, a second one with the other token must wait and then find the
// setup closed. If the second checked for an administrator before taking the lock,
// it would see none and create a second one.
func TestComplete_ConcurrentSetupsCreateOneAdministrator(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	svc := setup.NewService(d.console)
	issue(t, svc)
	second := issue(t, svc)

	first, err := d.console.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = first.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := first.Exec(t.Context(), `LOCK TABLE setup_tokens IN EXCLUSIVE MODE`); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if _, err := user.NewStore(first).Create(t.Context(), user.NewUser{
		Email: "ada@example.com", DisplayName: "Ada", Role: user.RoleAdmin, PasswordHash: testHash,
	}); err != nil {
		t.Fatalf("create first administrator: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := svc.Complete(t.Context(), second.Value, admin("eve@example.com"))
		done <- err
	}()
	waitForLockWaiter(t, d.owner, done)
	if err := first.Commit(t.Context()); err != nil {
		t.Fatalf("commit first setup: %v", err)
	}

	if err := <-done; !errors.Is(err, setup.ErrClosed) {
		t.Errorf("second Complete() error = %v, want ErrClosed", err)
	}
	if n := d.count(t, `SELECT count(*) FROM users WHERE role = 'admin'`); n != 1 {
		t.Errorf("%d administrators, want 1", n)
	}
}

func TestWriteInstructions_PrintsSetupURLWithTokenInFragment(t *testing.T) {
	t.Parallel()

	tok := setup.Token{Value: "abc_-123", ExpiresAt: time.Date(2026, 10, 10, 19, 0, 0, 0, time.FixedZone("CEST", 2*60*60))}
	var out bytes.Buffer
	if err := setup.WriteInstructions(&out, "https://nyktus.example.com", tok); err != nil {
		t.Fatalf("WriteInstructions() error = %v", err)
	}
	for _, want := range []string{"https://nyktus.example.com/setup#token=abc_-123", "2026-10-10T17:00:00Z"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("instructions do not contain %q:\n%s", want, out.String())
		}
	}
}
