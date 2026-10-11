// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package access

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/user"
)

func TestAllowed_FailsClosed(t *testing.T) {
	t.Parallel()

	for _, role := range []user.Role{user.RoleAdmin, user.RoleUser, user.RoleViewer, "", "root"} {
		for _, perm := range []httpx.Permission{"", "unknown:action", "*:*"} {
			if Allowed(role, perm) {
				t.Errorf("Allowed(%q, %q) = true, want false", role, perm)
			}
		}
	}
}

func TestGrants_CoverEveryRoleWithValidPermissions(t *testing.T) {
	t.Parallel()

	for _, role := range []user.Role{user.RoleAdmin, user.RoleUser, user.RoleViewer} {
		if _, ok := grants[role]; !ok {
			t.Errorf("role %s has no entry in the grants", role)
		}
	}
	for role, perms := range grants {
		if !role.Valid() {
			t.Errorf("grants name the unknown role %q", role)
		}
		for _, p := range perms {
			if !p.Valid() {
				t.Errorf("role %s grants the invalid permission %q", role, p)
			}
		}
	}
}

// A scope grants nothing beyond a role, so a scope that no role grants could
// never be used.
func TestKeyScopes_AreGrantedPermissions(t *testing.T) {
	t.Parallel()

	scopes := KeyScopes()
	if len(scopes) == 0 {
		t.Fatal("API keys may carry no scope")
	}
	for _, s := range scopes {
		if !slices.Contains(Permissions(), s) {
			t.Errorf("API keys may carry %s, which no role grants", s)
		}
	}
}

// A key holds its scopes, as far as keys may carry them, regardless of any
// role; a user holds the permissions of their role, regardless of scopes.
func TestPrincipal_AllowedForAPIKeyFollowsItsScopes(t *testing.T) {
	t.Parallel()

	key := func(scopes ...httpx.Permission) Principal {
		return Principal{Method: audit.AuthAPIKey, APIKeyID: "k1", Scopes: scopes}
	}
	for _, tt := range []struct {
		name string
		p    Principal
		perm httpx.Permission
		want bool
	}{
		{"scope", key("audit:read"), "audit:read", true},
		{"other scope", key("audit:read"), "users:read", false},
		{"no scopes", key(), "audit:read", false},
		{"scope that keys may not carry", key("users:write"), "users:write", false},
		{"role of a key", Principal{Role: user.RoleAdmin, Method: audit.AuthAPIKey, APIKeyID: "k1"}, "audit:read", false},
		{"session ignores scopes", Principal{Role: user.RoleAdmin, Method: audit.AuthSession, SessionID: "s1"}, "users:write", true},
		{"session without the role", Principal{Role: user.RoleViewer, Method: audit.AuthSession, SessionID: "s1", Scopes: []httpx.Permission{"audit:read"}}, "audit:read", false},
	} {
		if got := tt.p.Allowed(tt.perm); got != tt.want {
			t.Errorf("%s: Allowed(%s) = %v, want %v", tt.name, tt.perm, got, tt.want)
		}
	}
}

// Keys never manage accounts or keys.
func TestKeyScopes_ExcludeAccountsAndKeys(t *testing.T) {
	t.Parallel()

	for _, s := range KeyScopes() {
		if strings.HasPrefix(string(s), "users:") || strings.HasPrefix(string(s), "api_keys:") {
			t.Errorf("API keys may carry %s", s)
		}
	}
}

func TestPrincipal_ContextAndActor(t *testing.T) {
	t.Parallel()

	if _, ok := PrincipalFrom(t.Context()); ok {
		t.Error("an empty context carries a principal")
	}
	p := Principal{UserID: "u1", Role: user.RoleViewer, Method: audit.AuthSession, SessionID: "s1"}
	got, ok := PrincipalFrom(WithPrincipal(t.Context(), p))
	if !ok || !reflect.DeepEqual(got, p) {
		t.Errorf("PrincipalFrom() = %+v, %v; want %+v", got, ok, p)
	}
	if a := p.Actor(); a != (audit.Actor{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: "u1"}) {
		t.Errorf("Actor() = %+v", a)
	}
	k := Principal{Method: audit.AuthAPIKey, APIKeyID: "k1", Scopes: []httpx.Permission{"audit:read"}}
	if a := k.Actor(); a != (audit.Actor{Kind: audit.ActorAPIKey, Method: audit.AuthAPIKey, APIKeyID: "k1"}) {
		t.Errorf("Actor() of an API key = %+v", a)
	}
}

func TestPrincipal_HasSession(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		p    Principal
		want bool
	}{
		{Principal{Method: audit.AuthSession, SessionID: "s1"}, true},
		{Principal{Method: audit.AuthSession}, false},
		{Principal{Method: audit.AuthAPIKey, SessionID: "s1"}, false},
		{Principal{}, false},
	} {
		if got := tt.p.HasSession(); got != tt.want {
			t.Errorf("%+v.HasSession() = %v, want %v", tt.p, got, tt.want)
		}
	}
}

func TestPrincipal_AllowedFollowsTheRole(t *testing.T) {
	t.Parallel()

	for _, role := range []user.Role{user.RoleAdmin, user.RoleUser, user.RoleViewer, ""} {
		for _, perm := range Permissions() {
			if got := (Principal{Role: role}).Allowed(perm); got != Allowed(role, perm) {
				t.Errorf("Principal{Role: %q}.Allowed(%s) = %v, want %v", role, perm, got, !got)
			}
		}
	}
}

func TestDeniedAction(t *testing.T) {
	t.Parallel()

	if got := DeniedAction("audit:read"); got != "audit.read" {
		t.Errorf("DeniedAction() = %q, want audit.read", got)
	}
}
