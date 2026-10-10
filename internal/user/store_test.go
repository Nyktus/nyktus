// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/platform/schematest"
)

// testHash has the format of an encoded Argon2id hash. Store tests do not need a
// real hash, and computing one would only slow them down.
const testHash = "$argon2id$v=19$m=65536,t=3,p=4$AAECAwQFBgcICQoLDA0ODw$hTsnKkTbFCHAKWJmmlXrCZTzyrOF7RxMeSU+7hm6tJ4"

var uuidFormat = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// newStore returns a store connected as the console's database role.
func newStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	_, consoleURL := schematest.Console(t)
	pool := schematest.Open(t, consoleURL)
	return NewStore(pool), pool
}

func TestCreate_WithoutPasswordCreatesPendingUser(t *testing.T) {
	t.Parallel()

	s, _ := newStore(t)
	u, err := s.Create(t.Context(), NewUser{Email: "Jane@Example.com", DisplayName: "Jane Doe", Role: RoleEditor})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if !uuidFormat.MatchString(u.ID) {
		t.Errorf("ID = %q, want a random UUID", u.ID)
	}
	if u.Email != "jane@example.com" || u.DisplayName != "Jane Doe" || u.Role != RoleEditor {
		t.Errorf("Create() = %+v, want the given fields with the address in lower case", u)
	}
	if u.Status != StatusPending || u.PasswordHash != "" {
		t.Errorf("status = %q, hash = %q, want pending without a hash", u.Status, u.PasswordHash)
	}
	if u.CreatedAt.IsZero() || u.CreatedAt.Location().String() != "UTC" || !u.UpdatedAt.Equal(u.CreatedAt) {
		t.Errorf("created_at = %v, updated_at = %v, want equal UTC timestamps", u.CreatedAt, u.UpdatedAt)
	}
}

func TestCreate_WithPasswordCreatesActiveUser(t *testing.T) {
	t.Parallel()

	s, _ := newStore(t)
	u, err := s.Create(t.Context(), NewUser{Email: "admin@example.com", DisplayName: "Admin", Role: RoleAdmin, PasswordHash: testHash})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if u.Status != StatusActive || u.PasswordHash != testHash {
		t.Errorf("status = %q, hash = %q, want active with the given hash", u.Status, u.PasswordHash)
	}
}

func TestCreate_RejectsTakenEmailInAnyCase(t *testing.T) {
	t.Parallel()

	s, _ := newStore(t)
	if _, err := s.Create(t.Context(), NewUser{Email: "jane@example.com", DisplayName: "Jane", Role: RoleViewer}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	_, err := s.Create(t.Context(), NewUser{Email: "JANE@example.com", DisplayName: "Other Jane", Role: RoleViewer})
	if !errors.Is(err, ErrEmailTaken) {
		t.Errorf("Create() with a taken address error = %v, want ErrEmailTaken", err)
	}
}

func TestCreate_RejectsInvalidInput(t *testing.T) {
	t.Parallel()

	s, _ := newStore(t)
	valid := NewUser{Email: "jane@example.com", DisplayName: "Jane", Role: RoleViewer}
	tests := []struct {
		name   string
		modify func(*NewUser)
		want   error
	}{
		{name: "email", modify: func(nu *NewUser) { nu.Email = "jane" }, want: ErrInvalidEmail},
		{name: "display name", modify: func(nu *NewUser) { nu.DisplayName = " " }, want: ErrInvalidDisplayName},
		{name: "role", modify: func(nu *NewUser) { nu.Role = "root" }, want: ErrInvalidRole},
		{name: "empty role", modify: func(nu *NewUser) { nu.Role = "" }, want: ErrInvalidRole},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nu := valid
			tt.modify(&nu)
			if _, err := s.Create(t.Context(), nu); !errors.Is(err, tt.want) {
				t.Errorf("Create() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestCreate_RejectsTakenEmailInOtherNormalization(t *testing.T) {
	t.Parallel()

	s, _ := newStore(t)
	if _, err := s.Create(t.Context(), NewUser{Email: "j\u00fcrgen@example.com", DisplayName: "J\u00fcrgen", Role: RoleViewer}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	_, err := s.Create(t.Context(), NewUser{Email: "ju\u0308rgen@example.com", DisplayName: "Other", Role: RoleViewer})
	if !errors.Is(err, ErrEmailTaken) {
		t.Errorf("Create() with the decomposed address error = %v, want ErrEmailTaken", err)
	}
	if _, err := s.GetByEmail(t.Context(), "ju\u0308rgen@example.com"); err != nil {
		t.Errorf("GetByEmail() with the decomposed address error = %v, want the account", err)
	}
}

// A plain-text password must never reach the database: PostgreSQL would write
// the failing row of the constraint violation to its server log.
func TestCreate_RejectsPlainTextPasswordBeforeTheDatabase(t *testing.T) {
	t.Parallel()

	s, pool := newStore(t)
	_, err := s.Create(t.Context(), NewUser{Email: "jane@example.com", DisplayName: "Jane", Role: RoleViewer, PasswordHash: "correct horse battery staple"})
	var pgErr *pgconn.PgError
	if !errors.Is(err, ErrInvalidPasswordHash) || errors.As(err, &pgErr) {
		t.Errorf("Create() error = %v, want ErrInvalidPasswordHash without a database error", err)
	}
	var n int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM users").Scan(&n); err != nil || n != 0 {
		t.Errorf("users = %d, %v, want none", n, err)
	}
}

func TestGet(t *testing.T) {
	t.Parallel()

	s, _ := newStore(t)
	created, err := s.Create(t.Context(), NewUser{Email: "jane@example.com", DisplayName: "Jane", Role: RoleViewer, PasswordHash: testHash})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	got, err := s.Get(t.Context(), created.ID)
	if err != nil || got != created {
		t.Errorf("Get() = %+v, %v, want %+v", got, err, created)
	}
	for _, id := range []string{"7a1e0e4c-2f8b-4f7e-9a51-1f0a3c4d5e6f", "not-a-uuid", ""} {
		if _, err := s.Get(t.Context(), id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%q) error = %v, want ErrNotFound", id, err)
		}
	}
}

func TestGetByEmail(t *testing.T) {
	t.Parallel()

	s, _ := newStore(t)
	created, err := s.Create(t.Context(), NewUser{Email: "jane@example.com", DisplayName: "Jane", Role: RoleViewer, PasswordHash: testHash})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	for _, email := range []string{"Jane@EXAMPLE.com", "jane@example.com"} {
		got, err := s.GetByEmail(t.Context(), email)
		if err != nil || got != created {
			t.Errorf("GetByEmail(%q) = %+v, %v, want %+v", email, got, err, created)
		}
	}
	for _, email := range []string{"joe@example.com", "jane", "Jane <jane@example.com>", ""} {
		if _, err := s.GetByEmail(t.Context(), email); !errors.Is(err, ErrNotFound) {
			t.Errorf("GetByEmail(%q) error = %v, want ErrNotFound", email, err)
		}
	}
}

// row is a users row written directly, without the validation of the store.
type row struct {
	email, displayName, role, status string
	hash                             any
}

func validRow() row {
	return row{email: "jane@example.com", displayName: "Jane", role: "viewer", status: "pending"}
}

func (r row) insert(t *testing.T, pool *pgxpool.Pool) error {
	t.Helper()
	_, err := pool.Exec(t.Context(),
		"INSERT INTO users (email, display_name, role, status, password_hash) VALUES ($1, $2, $3, $4, $5)",
		r.email, r.displayName, r.role, r.status, r.hash)
	return err
}

func TestAdminExists_CountsAdministratorsInEveryStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		role   Role
		status Status
		want   bool
	}{
		{name: "editor", role: RoleEditor, status: StatusActive, want: false},
		{name: "viewer", role: RoleViewer, status: StatusActive, want: false},
		{name: "active admin", role: RoleAdmin, status: StatusActive, want: true},
		{name: "pending admin", role: RoleAdmin, status: StatusPending, want: true},
		{name: "deactivated admin", role: RoleAdmin, status: StatusDeactivated, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s, pool := newStore(t)
			if exists, err := s.AdminExists(t.Context()); err != nil || exists {
				t.Fatalf("AdminExists() without users = %v, %v; want false, nil", exists, err)
			}
			r := validRow()
			r.role, r.status = string(tt.role), string(tt.status)
			if tt.status != StatusPending {
				r.hash = testHash
			}
			if err := r.insert(t, pool); err != nil {
				t.Fatalf("insert user: %v", err)
			}
			if exists, err := s.AdminExists(t.Context()); err != nil || exists != tt.want {
				t.Errorf("AdminExists() = %v, %v; want %v, nil", exists, err, tt.want)
			}
		})
	}
}

// The schema is the last line of defense, so its constraints are tested directly,
// as the console's database role.
func TestSchema_RejectsInvalidUsers(t *testing.T) {
	t.Parallel()

	_, pool := newStore(t)
	tests := []struct {
		name       string
		modify     func(*row)
		constraint string
	}{
		{name: "upper-case email", modify: func(r *row) { r.email = "Jane@example.com" }, constraint: "users_email_check"},
		{name: "email without at sign", modify: func(r *row) { r.email = "jane.example.com" }, constraint: "users_email_check"},
		{name: "email with two at signs", modify: func(r *row) { r.email = "jane@home@example.com" }, constraint: "users_email_check"},
		{name: "email with space", modify: func(r *row) { r.email = "jane doe@example.com" }, constraint: "users_email_check"},
		{name: "email with quote", modify: func(r *row) { r.email = `"jane"@example.com` }, constraint: "users_email_check"},
		{name: "decomposed email", modify: func(r *row) { r.email = "ju\u0308rgen@example.com" }, constraint: "users_email_check"},
		{name: "email with control character", modify: func(r *row) { r.email = "jane\t@example.com" }, constraint: "users_email_check"},
		{
			name:       "email too long",
			modify:     func(r *row) { r.email = strings.Repeat("a", 64) + "@" + strings.Repeat("b", 186) + ".org" },
			constraint: "users_email_check",
		},
		{name: "empty display name", modify: func(r *row) { r.displayName = "" }, constraint: "users_display_name_check"},
		{name: "display name too long", modify: func(r *row) { r.displayName = strings.Repeat("ä", MaxDisplayNameLength+1) }, constraint: "users_display_name_check"},
		{name: "display name with surrounding space", modify: func(r *row) { r.displayName = " Jane" }, constraint: "users_display_name_check"},
		{name: "display name with newline", modify: func(r *row) { r.displayName = "Jane\nDoe" }, constraint: "users_display_name_check"},
		{name: "unknown role", modify: func(r *row) { r.role = "root" }, constraint: "users_role_check"},
		{name: "unknown status", modify: func(r *row) { r.status = "locked" }, constraint: "users_status_check"},
		{name: "pending with hash", modify: func(r *row) { r.hash = testHash }, constraint: "users_password_check"},
		{name: "active without hash", modify: func(r *row) { r.status = "active" }, constraint: "users_password_check"},
		{
			name:       "plain-text password",
			modify:     func(r *row) { r.status, r.hash = "active", "correct horse battery staple" },
			constraint: "users_password_hash_check",
		},
		{
			name:       "argon2i hash",
			modify:     func(r *row) { r.status, r.hash = "active", strings.Replace(testHash, "argon2id", "argon2i", 1) },
			constraint: "users_password_hash_check",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validRow()
			tt.modify(&r)
			wantConstraint(t, r.insert(t, pool), tt.constraint)
		})
	}
}

func TestSchema_AllowsEveryValidStatus(t *testing.T) {
	t.Parallel()

	_, pool := newStore(t)
	tests := []struct {
		status string
		hash   any
	}{
		{status: "pending"},
		{status: "active", hash: testHash},
		{status: "deactivated"},
		{status: "deactivated", hash: testHash},
	}
	for i, tt := range tests {
		r := validRow()
		r.email = string(rune('a'+i)) + "@example.com"
		r.status, r.hash = tt.status, tt.hash
		if err := r.insert(t, pool); err != nil {
			t.Errorf("insert %s user with hash %v: error = %v, want nil", tt.status, tt.hash != nil, err)
		}
	}
}

func TestSchema_RejectsInvalidTransitions(t *testing.T) {
	t.Parallel()

	s, pool := newStore(t)
	u, err := s.Create(t.Context(), NewUser{Email: "jane@example.com", DisplayName: "Jane", Role: RoleViewer})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	_, err = pool.Exec(t.Context(), "UPDATE users SET status = 'active' WHERE id = $1", u.ID)
	wantConstraint(t, err, "users_password_check")

	_, err = pool.Exec(t.Context(), "UPDATE users SET updated_at = created_at - interval '1 second' WHERE id = $1", u.ID)
	wantConstraint(t, err, "users_updated_at_check")
}

func wantConstraint(t *testing.T, err error, constraint string) {
	t.Helper()
	var pgErr *pgconn.PgError
	// 23514 is check_violation.
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != constraint {
		t.Errorf("error = %v, want a violation of %s", err, constraint)
	}
}
