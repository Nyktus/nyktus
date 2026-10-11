// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package access

import (
	"testing"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/user"
)

func TestAllowed_FailsClosed(t *testing.T) {
	t.Parallel()

	for _, role := range []user.Role{user.RoleAdmin, user.RoleEditor, user.RoleViewer, "", "root"} {
		for _, perm := range []httpx.Permission{"", "unknown:action", "*:*"} {
			if Allowed(role, perm) {
				t.Errorf("Allowed(%q, %q) = true, want false", role, perm)
			}
		}
	}
}

func TestGrants_CoverEveryRoleWithValidPermissions(t *testing.T) {
	t.Parallel()

	for _, role := range []user.Role{user.RoleAdmin, user.RoleEditor, user.RoleViewer} {
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

func TestPrincipal_ContextAndActor(t *testing.T) {
	t.Parallel()

	if _, ok := PrincipalFrom(t.Context()); ok {
		t.Error("an empty context carries a principal")
	}
	p := Principal{UserID: "u1", Role: user.RoleViewer, Method: audit.AuthSession, SessionID: "s1"}
	got, ok := PrincipalFrom(WithPrincipal(t.Context(), p))
	if !ok || got != p {
		t.Errorf("PrincipalFrom() = %+v, %v; want %+v", got, ok, p)
	}
	if a := p.Actor(); a != (audit.Actor{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: "u1"}) {
		t.Errorf("Actor() = %+v", a)
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

	for _, role := range []user.Role{user.RoleAdmin, user.RoleEditor, user.RoleViewer, ""} {
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
