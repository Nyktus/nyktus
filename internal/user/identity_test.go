// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

var testIdentity = Identity{Issuer: "https://idp.example.com", Subject: "248289761001"}

// createOIDC creates an active viewer of the identity provider.
func createOIDC(t *testing.T, s *Store, id Identity) User {
	t.Helper()
	u, err := s.Create(t.Context(), NewUser{Email: "jane@example.com", DisplayName: "Jane", Role: RoleViewer, Identity: &id})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	return u
}

func TestCreate_WithIdentityCreatesActiveAccountWithoutPassword(t *testing.T) {
	t.Parallel()

	s, pool := newStore(t)
	u := createOIDC(t, s, testIdentity)
	if u.Status != StatusActive || u.PasswordHash != "" || u.Identity == nil || *u.Identity != testIdentity {
		t.Errorf("Create() = %+v, want an active account with the identity and without a password", u)
	}

	var locked User
	err := inTx(t, pool, func(s *Store) error {
		var err error
		locked, err = s.LockByIdentity(t.Context(), testIdentity)
		return err
	})
	if err != nil || locked.ID != u.ID || locked.Identity == nil || *locked.Identity != testIdentity {
		t.Errorf("LockByIdentity() = %+v, %v; want the account", locked, err)
	}
	for _, other := range []Identity{
		{Issuer: testIdentity.Issuer, Subject: "other"},
		{Issuer: "https://other.example.com", Subject: testIdentity.Subject},
	} {
		err := inTx(t, pool, func(s *Store) error {
			_, err := s.LockByIdentity(t.Context(), other)
			return err
		})
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("LockByIdentity(%+v) error = %v, want ErrNotFound", other, err)
		}
	}
	if got, err := s.Get(t.Context(), u.ID); err != nil || got.Identity == nil || got.SignInMethod() != SignInOIDC {
		t.Errorf("Get() = %+v, %v; want the identity", got, err)
	}
}

func TestCreate_RejectsInvalidIdentities(t *testing.T) {
	t.Parallel()

	s, _ := newStore(t)
	createOIDC(t, s, testIdentity)

	_, err := s.Create(t.Context(), NewUser{Email: "john@example.com", DisplayName: "John", Role: RoleViewer, Identity: &testIdentity})
	if !errors.Is(err, ErrIdentityTaken) {
		t.Errorf("Create() with a taken identity: error = %v, want ErrIdentityTaken", err)
	}
	other := Identity{Issuer: "https://other.example.com", Subject: testIdentity.Subject}
	if _, err := s.Create(t.Context(), NewUser{Email: "john@example.com", DisplayName: "John", Role: RoleViewer, Identity: &other}); err != nil {
		t.Errorf("Create() with the same subject of another issuer: error = %v, want nil", err)
	}
	for name, nu := range map[string]NewUser{
		"identity and password": {
			Email: "a@example.com", DisplayName: "A", Role: RoleViewer, PasswordHash: testHash,
			Identity: &Identity{Issuer: "https://idp.example.com", Subject: "a"},
		},
		"empty subject": {Email: "b@example.com", DisplayName: "B", Role: RoleViewer, Identity: &Identity{Issuer: "https://idp.example.com"}},
	} {
		if _, err := s.Create(t.Context(), nu); !errors.Is(err, ErrInvalidIdentity) {
			t.Errorf("%s: Create() error = %v, want ErrInvalidIdentity", name, err)
		}
	}
}

// The identity names the account for good: the console cannot move it to
// another account or change it.
func TestSchema_IdentityCannotBeChanged(t *testing.T) {
	t.Parallel()

	s, pool := newStore(t)
	u := createOIDC(t, s, testIdentity)
	for _, column := range []string{"oidc_issuer", "oidc_subject"} {
		_, err := pool.Exec(t.Context(), "UPDATE users SET "+column+" = 'other' WHERE id = $1", u.ID)
		var pgErr *pgconn.PgError
		// 42501 is insufficient_privilege.
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("update %s: error = %v, want a denied privilege", column, err)
		}
	}
}

// The role of an account of the identity provider follows its groups there.
// Only the sign-in through the provider sets it.
func TestUpdate_RoleOfAnAccountOfTheProvider(t *testing.T) {
	t.Parallel()

	s, pool, _ := manageDB(t)
	u := createOIDC(t, s, testIdentity)

	if _, _, err := update(t, pool, u.ID, Change{Role: ptr(RoleAdmin)}); !errors.Is(err, ErrOIDCAccount) {
		t.Errorf("change of role: error = %v, want ErrOIDCAccount", err)
	}
	if _, _, err := update(t, pool, u.ID, Change{Role: ptr(RoleViewer)}); err != nil {
		t.Errorf("role unchanged: error = %v, want nil", err)
	}
	if got, changed, err := update(t, pool, u.ID, Change{DisplayName: ptr("Jane Doe")}); err != nil || got.DisplayName != "Jane Doe" || len(changed) != 1 {
		t.Errorf("change of name = %+v, %v, %v; want it changed", got, changed, err)
	}
	if got, _, err := update(t, pool, u.ID, Change{Role: ptr(RoleAdmin), FromProvider: true}); err != nil || got.Role != RoleAdmin {
		t.Errorf("change of role from the provider = %+v, %v; want admin", got, err)
	}
}

// An account of the identity provider has no password and returns to active,
// not to pending, when it is reactivated.
func TestUpdate_ReactivatingAnAccountOfTheProviderMakesItActive(t *testing.T) {
	t.Parallel()

	s, pool, _ := manageDB(t)
	u := createOIDC(t, s, testIdentity)
	if _, _, err := update(t, pool, u.ID, Change{Status: ptr(StatusDeactivated)}); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if got, _, err := update(t, pool, u.ID, Change{Status: ptr(StatusActive)}); err != nil || got.Status != StatusActive {
		t.Errorf("reactivate = %s, %v; want active", got.Status, err)
	}
}
