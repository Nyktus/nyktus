// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package apikey_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/apikey"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/platform/schematest"
)

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

// createAdmin inserts an active administrator.
func createAdmin(t *testing.T, d testDB, email string) string {
	t.Helper()
	var id string
	err := d.owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, password_hash)
VALUES ($1, 'Test User', 'admin', 'active', '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA')
RETURNING id`, email).Scan(&id)
	if err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	return id
}

func spec(name string) apikey.Spec {
	return apikey.Spec{Name: name, Scopes: []httpx.Permission{"audit:read"}, ExpiresAt: time.Now().Add(24 * time.Hour)}
}

func tryCreate(ctx context.Context, d testDB, createdBy string, s apikey.Spec) (apikey.Key, string, error) {
	var (
		k   apikey.Key
		key string
	)
	err := pgx.BeginFunc(ctx, d.console, func(tx pgx.Tx) error {
		var err error
		k, key, err = apikey.NewStore(tx).Create(ctx, createdBy, s)
		return err
	})
	return k, key, err
}

func create(t *testing.T, d testDB, createdBy string, s apikey.Spec) (apikey.Key, string) {
	t.Helper()
	k, key, err := tryCreate(t.Context(), d, createdBy, s)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	return k, key
}

func TestStore_CreateAuthenticateListAndDelete(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	admin := createAdmin(t, d, "ada@example.com")
	k, key := create(t, d, admin, spec("SIEM export"))
	if k.CreatedBy == nil || *k.CreatedBy != admin || k.Name != "SIEM export" || len(k.Scopes) != 1 || k.Scopes[0] != "audit:read" || k.LastUsedAt != nil {
		t.Errorf("Create() = %+v", k)
	}
	if !strings.HasPrefix(key, apikey.Prefix) {
		t.Errorf("key %q lacks the prefix", key)
	}
	// Only the hash of the secret is stored.
	if n := d.count(t, `SELECT count(*) FROM api_keys WHERE position(convert_to($1, 'UTF8') IN secret_hash) > 0 OR name = $1`, key); n != 0 {
		t.Error("the key is stored")
	}

	store := apikey.NewStore(d.console)
	got, err := store.Authenticate(t.Context(), key)
	if err != nil || got.ID != k.ID || got.LastUsedAt == nil {
		t.Fatalf("Authenticate() = %+v, %v; want the key with its use recorded", got, err)
	}
	keys, err := store.List(t.Context())
	if err != nil || len(keys) != 1 || keys[0].ID != k.ID || keys[0].LastUsedAt == nil {
		t.Errorf("List() = %+v, %v", keys, err)
	}

	for _, id := range []string{"not-a-uuid", "00000000-0000-4000-8000-000000000000"} {
		if err := store.Delete(t.Context(), id); !errors.Is(err, apikey.ErrNotFound) {
			t.Errorf("Delete(%s) error = %v, want ErrNotFound", id, err)
		}
	}
	// PostgreSQL accepts an identifier in uppercase, as clients may send it.
	if err := store.Delete(t.Context(), strings.ToUpper(k.ID)); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := store.Authenticate(t.Context(), key); !errors.Is(err, apikey.ErrInvalidKey) {
		t.Errorf("Authenticate() after revocation: error = %v, want ErrInvalidKey", err)
	}
}

func TestStore_AuthenticateRejectsInvalidKeys(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	store := apikey.NewStore(d.console)
	admin := createAdmin(t, d, "ada@example.com")
	valid, key := create(t, d, admin, spec("valid"))
	// A well-formed key with the identifier of a valid key and another secret.
	wrongSecret, err := apikey.Format(valid.ID, make([]byte, 32))
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	revoked, revokedKey := create(t, d, admin, spec("revoked"))
	d.exec(t, `DELETE FROM api_keys WHERE id = $1`, revoked.ID)
	expired, expiredKey := create(t, d, admin, spec("expired"))
	d.exec(t, `UPDATE api_keys SET created_at = clock_timestamp() - interval '1 day', expires_at = clock_timestamp() WHERE id = $1`, expired.ID)

	for name, k := range map[string]string{
		"malformed":      "nyk_secret",
		"empty":          "",
		"another secret": wrongSecret,
		"revoked":        revokedKey,
		"expired":        expiredKey,
	} {
		if _, err := store.Authenticate(t.Context(), k); !errors.Is(err, apikey.ErrInvalidKey) {
			t.Errorf("%s: Authenticate() error = %v, want ErrInvalidKey", name, err)
		}
	}
	if _, err := store.Authenticate(t.Context(), key); err != nil {
		t.Errorf("valid key: error = %v", err)
	}
}

// A key records its use at most once per interval, so that a request does not
// cost a write.
func TestStore_AuthenticateRecordsUseOncePerInterval(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	k, key := create(t, d, createAdmin(t, d, "ada@example.com"), spec("k"))
	store := apikey.NewStore(d.console)

	first, err := store.Authenticate(t.Context(), key)
	if err != nil || first.LastUsedAt == nil {
		t.Fatalf("Authenticate() = %+v, %v", first, err)
	}
	second, err := store.Authenticate(t.Context(), key)
	if err != nil || second.LastUsedAt == nil || !second.LastUsedAt.Equal(*first.LastUsedAt) {
		t.Errorf("second use: last used %v, want %v", second.LastUsedAt, first.LastUsedAt)
	}
	d.exec(t, `UPDATE api_keys SET created_at = created_at - $2::interval, last_used_at = last_used_at - $2::interval WHERE id = $1`,
		k.ID, apikey.TouchInterval)
	third, err := store.Authenticate(t.Context(), key)
	if err != nil || third.LastUsedAt == nil || !third.LastUsedAt.After(*first.LastUsedAt) {
		t.Errorf("use after the interval: last used %v, want after %v", third.LastUsedAt, first.LastUsedAt)
	}
}

// Expired keys do not count against the limit and are deleted when a key is
// created.
func TestStore_CreateLimitsKeysOfTheInstallation(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	ada := createAdmin(t, d, "ada@example.com")
	bob := createAdmin(t, d, "bob@example.com")
	for i := range apikey.MaxKeys {
		create(t, d, []string{ada, bob}[i%2], spec("key"))
	}
	if _, _, err := tryCreate(t.Context(), d, ada, spec("one too many")); !errors.Is(err, apikey.ErrTooManyKeys) {
		t.Fatalf("Create() beyond the limit: error = %v, want ErrTooManyKeys", err)
	}

	d.exec(t, `
UPDATE api_keys SET created_at = clock_timestamp() - interval '2 days', expires_at = clock_timestamp() - interval '1 day'
WHERE id = (SELECT id FROM api_keys LIMIT 1)`)
	create(t, d, bob, spec("replacement"))
	if n := d.count(t, `SELECT count(*) FROM api_keys`); n != apikey.MaxKeys {
		t.Errorf("%d keys, want %d: the expired key is deleted", n, apikey.MaxKeys)
	}
}

// The database bounds what the console stores, also if the application checks
// were bypassed.
func TestStore_CreateRejectsInvalidFields(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	admin := createAdmin(t, d, "ada@example.com")
	for _, tt := range []struct {
		name   string
		modify func(*apikey.Spec)
		want   error
	}{
		{"expiry in the past", func(s *apikey.Spec) { s.ExpiresAt = time.Now().Add(-time.Minute) }, apikey.ErrInvalidExpiry},
		{"expiry beyond three years", func(s *apikey.Spec) { s.ExpiresAt = time.Now().Add(apikey.MaxLifetime + time.Hour) }, apikey.ErrInvalidExpiry},
		{"empty name", func(s *apikey.Spec) { s.Name = "" }, apikey.ErrInvalidName},
		{"long name", func(s *apikey.Spec) { s.Name = strings.Repeat("n", apikey.MaxNameLength+1) }, apikey.ErrInvalidName},
		{"no scopes", func(s *apikey.Spec) { s.Scopes = nil }, apikey.ErrInvalidScopes},
		{"duplicate scopes", func(s *apikey.Spec) { s.Scopes = []httpx.Permission{"audit:read", "audit:read"} }, apikey.ErrInvalidScopes},
		{"malformed scope", func(s *apikey.Spec) { s.Scopes = []httpx.Permission{"audit"} }, apikey.ErrInvalidScopes},
		{"wildcard scope", func(s *apikey.Spec) { s.Scopes = []httpx.Permission{"*:*"} }, apikey.ErrInvalidScopes},
	} {
		s := spec("k")
		tt.modify(&s)
		if _, _, err := tryCreate(t.Context(), d, admin, s); !errors.Is(err, tt.want) {
			t.Errorf("%s: error = %v, want %v", tt.name, err, tt.want)
		}
	}
	// Three years are allowed.
	s := spec("long-lived")
	s.ExpiresAt = time.Now().Add(apikey.MaxLifetime - time.Hour)
	create(t, d, admin, s)
}

// Keys belong to the team: deleting the administrator who created a key keeps
// the key and its audit entries.
func TestDeletingTheCreator_KeepsTheKeyAndItsEntries(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	// Another administrator remains.
	createAdmin(t, d, "bob@example.com")
	ada := createAdmin(t, d, "ada@example.com")
	k, key := create(t, d, ada, spec("SIEM export"))
	err := audit.NewStore(d.console).Record(t.Context(), audit.Entry{
		Action: audit.ActionAuditRead, Outcome: audit.OutcomeSuccess,
		Actor: audit.Actor{Kind: audit.ActorAPIKey, Method: audit.AuthAPIKey, APIKeyID: k.ID},
	})
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if _, err := d.console.Exec(t.Context(), `DELETE FROM users WHERE id = $1`, ada); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	got, err := apikey.NewStore(d.console).Authenticate(t.Context(), key)
	if err != nil || got.CreatedBy != nil {
		t.Errorf("Authenticate() after deleting the creator = %+v, %v; want the key without its creator", got, err)
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE api_key_id = $1 AND actor_display_name = 'SIEM export'`, k.ID); n != 1 {
		t.Errorf("%d entries of the key, want 1", n)
	}
}

func TestValidateScopes(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		scopes []httpx.Permission
		ok     bool
	}{
		{[]httpx.Permission{"audit:read"}, true},
		{[]httpx.Permission{"users:read"}, false},
		{[]httpx.Permission{"users:write"}, false},
		{[]httpx.Permission{"api_keys:write"}, false},
		{[]httpx.Permission{"audit:read", "audit:read"}, false},
		{nil, false},
		{[]httpx.Permission{"*:*"}, false},
		{[]httpx.Permission{"honeytokens:read"}, true},
		{[]httpx.Permission{"honeytokens:write", "honeytokens:read"}, true},
		// A key that changes honeytokens reads them in the responses.
		{[]httpx.Permission{"honeytokens:write"}, false},
		{[]httpx.Permission{"audit:read", "honeytokens:write"}, false},
	} {
		if err := apikey.ValidateScopes(tt.scopes); (err == nil) != tt.ok {
			t.Errorf("ValidateScopes(%v) error = %v, want ok %v", tt.scopes, err, tt.ok)
		}
	}
}

func TestParseName(t *testing.T) {
	t.Parallel()

	for name, ok := range map[string]bool{
		"SIEM export": true,
		strings.Repeat("n", apikey.MaxNameLength):   true,
		strings.Repeat("n", apikey.MaxNameLength+1): false,
		"":                     false,
		" padded":              false,
		"line\nbreak":          false,
		"bidi \u202e override": false,
	} {
		if _, err := apikey.ParseName(name); (err == nil) != ok {
			t.Errorf("ParseName(%q) error = %v, want ok %v", name, err, ok)
		}
	}
}
