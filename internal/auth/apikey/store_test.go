// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package apikey_test

import (
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
	"nyktus.org/nyktus/internal/user"
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

// createUser inserts an active administrator.
func createUser(t *testing.T, d testDB, email string) string {
	t.Helper()
	var id string
	err := d.owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, password_hash) VALUES ($1, 'Test User', 'admin', 'active', '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA')
RETURNING id`, email).Scan(&id)
	if err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	return id
}

func spec(name string) apikey.Spec {
	return apikey.Spec{Name: name, Scopes: []httpx.Permission{"audit:read"}, ExpiresAt: time.Now().Add(24 * time.Hour)}
}

func create(t *testing.T, d testDB, userID string, s apikey.Spec) (apikey.Key, string) {
	t.Helper()
	var (
		k   apikey.Key
		key string
	)
	err := pgx.BeginFunc(t.Context(), d.console, func(tx pgx.Tx) error {
		var err error
		k, key, err = apikey.NewStore(tx).Create(t.Context(), userID, s)
		return err
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	return k, key
}

func TestStore_CreateAuthenticateListAndDelete(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	id := createUser(t, d, "ada@example.com")
	k, key := create(t, d, id, spec("SIEM export"))
	if k.UserID != id || k.Name != "SIEM export" || len(k.Scopes) != 1 || k.Scopes[0] != "audit:read" || k.LastUsedAt != nil {
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
	got, u, err := store.Authenticate(t.Context(), key)
	if err != nil || got.ID != k.ID || u.ID != id || u.Role != user.RoleAdmin || got.LastUsedAt == nil {
		t.Fatalf("Authenticate() = %+v, %+v, %v; want the key with its use recorded", got, u, err)
	}

	keys, err := store.List(t.Context(), id)
	if err != nil || len(keys) != 1 || keys[0].ID != k.ID || keys[0].LastUsedAt == nil {
		t.Errorf("List() = %+v, %v", keys, err)
	}
	if keys, err := store.List(t.Context(), createUser(t, d, "bob@example.com")); err != nil || len(keys) != 0 {
		t.Errorf("List() of another user = %+v, %v; want none", keys, err)
	}

	for _, keyID := range []string{"not-a-uuid", "00000000-0000-4000-8000-000000000000"} {
		if err := store.Delete(t.Context(), id, keyID); !errors.Is(err, apikey.ErrNotFound) {
			t.Errorf("Delete(%s) error = %v, want ErrNotFound", keyID, err)
		}
	}
	if err := store.Delete(t.Context(), createUser(t, d, "eve@example.com"), k.ID); !errors.Is(err, apikey.ErrNotFound) {
		t.Errorf("Delete() by another user: error = %v, want ErrNotFound", err)
	}
	if err := store.Delete(t.Context(), id, k.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, _, err := store.Authenticate(t.Context(), key); !errors.Is(err, apikey.ErrInvalidKey) {
		t.Errorf("Authenticate() after revocation: error = %v, want ErrInvalidKey", err)
	}
}

func TestStore_AuthenticateRejectsInvalidKeys(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	store := apikey.NewStore(d.console)

	id := createUser(t, d, "ada@example.com")
	valid, key := create(t, d, id, spec("valid"))
	// A well-formed key with the identifier of a valid key and another secret.
	wrongSecret, err := apikey.Format(valid.ID, make([]byte, 32))
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	revoked, revokedKey := create(t, d, id, spec("revoked"))
	d.exec(t, `DELETE FROM api_keys WHERE id = $1`, revoked.ID)

	expired, expiredKey := create(t, d, id, spec("expired"))
	d.exec(t, `UPDATE api_keys SET created_at = clock_timestamp() - interval '1 day', expires_at = clock_timestamp() WHERE id = $1`, expired.ID)

	deactivated := createUser(t, d, "bob@example.com")
	_, deactivatedKey := create(t, d, deactivated, spec("deactivated"))
	d.exec(t, `UPDATE users SET status = 'deactivated' WHERE id = $1`, deactivated)

	for name, k := range map[string]string{
		"malformed":           "nyk_secret",
		"empty":               "",
		"another secret":      wrongSecret,
		"revoked":             revokedKey,
		"expired":             expiredKey,
		"deactivated account": deactivatedKey,
	} {
		if _, _, err := store.Authenticate(t.Context(), k); !errors.Is(err, apikey.ErrInvalidKey) {
			t.Errorf("%s: Authenticate() error = %v, want ErrInvalidKey", name, err)
		}
	}
	if _, _, err := store.Authenticate(t.Context(), key); err != nil {
		t.Errorf("valid key %s: error = %v", valid.ID, err)
	}
}

// A key records its use at most once per interval, so that a request does not
// cost a write.
func TestStore_AuthenticateRecordsUseOncePerInterval(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	id := createUser(t, d, "ada@example.com")
	k, key := create(t, d, id, spec("k"))
	store := apikey.NewStore(d.console)

	first, _, err := store.Authenticate(t.Context(), key)
	if err != nil || first.LastUsedAt == nil {
		t.Fatalf("Authenticate() = %+v, %v", first, err)
	}
	second, _, err := store.Authenticate(t.Context(), key)
	if err != nil || second.LastUsedAt == nil || !second.LastUsedAt.Equal(*first.LastUsedAt) {
		t.Errorf("second use: last used %v, want %v", second.LastUsedAt, first.LastUsedAt)
	}

	d.exec(t, `UPDATE api_keys SET created_at = created_at - $2::interval, last_used_at = last_used_at - $2::interval WHERE id = $1`,
		k.ID, apikey.TouchInterval)
	third, _, err := store.Authenticate(t.Context(), key)
	if err != nil || third.LastUsedAt == nil || !third.LastUsedAt.After(*first.LastUsedAt) {
		t.Errorf("use after the interval: last used %v, want after %v", third.LastUsedAt, first.LastUsedAt)
	}
}

// Expired keys do not count against the limit and are deleted when the user
// creates a key. The caller holds the lock of the account.
func TestStore_CreateLimitsKeysPerUser(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	id := createUser(t, d, "ada@example.com")
	for i := range apikey.MaxPerUser {
		create(t, d, id, spec("k"+string(rune('a'+i))))
	}
	err := pgx.BeginFunc(t.Context(), d.console, func(tx pgx.Tx) error {
		_, _, err := apikey.NewStore(tx).Create(t.Context(), id, spec("one too many"))
		return err
	})
	if !errors.Is(err, apikey.ErrTooManyKeys) {
		t.Fatalf("Create() beyond the limit: error = %v, want ErrTooManyKeys", err)
	}

	d.exec(t, `
UPDATE api_keys SET created_at = clock_timestamp() - interval '2 days', expires_at = clock_timestamp() - interval '1 day'
WHERE id = (SELECT id FROM api_keys WHERE user_id = $1 LIMIT 1)`, id)
	create(t, d, id, spec("replacement"))
	if n := d.count(t, `SELECT count(*) FROM api_keys WHERE user_id = $1`, id); n != apikey.MaxPerUser {
		t.Errorf("%d keys, want %d: the expired key is deleted", n, apikey.MaxPerUser)
	}
}

// The database bounds what the console stores, also if the application checks
// were bypassed.
func TestStore_CreateRejectsInvalidFields(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	id := createUser(t, d, "ada@example.com")
	for _, tt := range []struct {
		name   string
		modify func(*apikey.Spec)
		want   error
	}{
		{"expiry in the past", func(s *apikey.Spec) { s.ExpiresAt = time.Now().Add(-time.Minute) }, apikey.ErrInvalidExpiry},
		{"expiry beyond a year", func(s *apikey.Spec) { s.ExpiresAt = time.Now().Add(apikey.MaxLifetime + time.Hour) }, apikey.ErrInvalidExpiry},
		{"empty name", func(s *apikey.Spec) { s.Name = "" }, apikey.ErrInvalidName},
		{"long name", func(s *apikey.Spec) { s.Name = strings.Repeat("n", apikey.MaxNameLength+1) }, apikey.ErrInvalidName},
		{"no scopes", func(s *apikey.Spec) { s.Scopes = nil }, apikey.ErrInvalidScopes},
		{"duplicate scopes", func(s *apikey.Spec) { s.Scopes = []httpx.Permission{"audit:read", "audit:read"} }, apikey.ErrInvalidScopes},
		{"malformed scope", func(s *apikey.Spec) { s.Scopes = []httpx.Permission{"audit"} }, apikey.ErrInvalidScopes},
		{"wildcard scope", func(s *apikey.Spec) { s.Scopes = []httpx.Permission{"*:*"} }, apikey.ErrInvalidScopes},
	} {
		s := spec("k")
		tt.modify(&s)
		err := pgx.BeginFunc(t.Context(), d.console, func(tx pgx.Tx) error {
			_, _, err := apikey.NewStore(tx).Create(t.Context(), id, s)
			return err
		})
		if !errors.Is(err, tt.want) {
			t.Errorf("%s: error = %v, want %v", tt.name, err, tt.want)
		}
	}
}

func TestDeleteAll_RevokesEveryKeyOfTheUser(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	id := createUser(t, d, "ada@example.com")
	other := createUser(t, d, "bob@example.com")
	create(t, d, id, spec("a"))
	create(t, d, id, spec("b"))
	create(t, d, other, spec("c"))
	if err := apikey.DeleteAll(t.Context(), d.console, id); err != nil {
		t.Fatalf("DeleteAll() error = %v", err)
	}
	if n := d.count(t, `SELECT count(*) FROM api_keys WHERE user_id = $1`, id); n != 0 {
		t.Errorf("%d keys left, want 0", n)
	}
	if n := d.count(t, `SELECT count(*) FROM api_keys WHERE user_id = $1`, other); n != 1 {
		t.Errorf("%d keys of another user left, want 1", n)
	}
}

// Deleting a user deletes their keys; the audit entries of the keys remain,
// because they do not reference the key.
func TestDeletingAUser_DeletesTheirKeysAndKeepsTheirEntries(t *testing.T) {
	t.Parallel()

	d := newTestDB(t)
	// Another administrator remains.
	createUser(t, d, "bob@example.com")
	id := createUser(t, d, "ada@example.com")
	k, _ := create(t, d, id, spec("k"))
	err := audit.NewStore(d.console).Record(t.Context(), audit.Entry{
		Action: audit.ActionAuditRead, Outcome: audit.OutcomeSuccess,
		Actor: audit.Actor{Kind: audit.ActorUser, Method: audit.AuthAPIKey, UserID: id, APIKeyID: k.ID},
	})
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if _, err := d.console.Exec(t.Context(), `DELETE FROM users WHERE id = $1`, id); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if n := d.count(t, `SELECT count(*) FROM api_keys`); n != 0 {
		t.Errorf("%d keys left, want 0", n)
	}
	if n := d.count(t, `SELECT count(*) FROM audit_entries WHERE api_key_id = $1 AND actor_user_id IS NULL`, k.ID); n != 1 {
		t.Errorf("%d entries of the key, want 1", n)
	}
}

func TestValidateScopes(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		scopes []httpx.Permission
		role   user.Role
		ok     bool
	}{
		{[]httpx.Permission{"audit:read"}, user.RoleAdmin, true},
		{[]httpx.Permission{"audit:read"}, user.RoleViewer, false},
		{[]httpx.Permission{"users:read"}, user.RoleAdmin, false},
		{[]httpx.Permission{"users:write"}, user.RoleAdmin, false},
		{[]httpx.Permission{"audit:read", "audit:read"}, user.RoleAdmin, false},
		{nil, user.RoleAdmin, false},
		{[]httpx.Permission{"*:*"}, user.RoleAdmin, false},
	} {
		if err := apikey.ValidateScopes(tt.scopes, tt.role); (err == nil) != tt.ok {
			t.Errorf("ValidateScopes(%v, %s) error = %v, want ok %v", tt.scopes, tt.role, err, tt.ok)
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
