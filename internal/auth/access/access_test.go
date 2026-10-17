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

// Keys never manage accounts, keys or alert channels.
func TestKeyScopes_ExcludeAccountsKeysAndAlertChannels(t *testing.T) {
	t.Parallel()

	for _, s := range KeyScopes() {
		if strings.HasPrefix(string(s), "users:") || strings.HasPrefix(string(s), "api_keys:") ||
			strings.HasPrefix(string(s), "alert_channels:") {
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

// Every role reads the honeytokens; only viewers cannot change them. A key
// with only the scope to read them cannot change them either.
func TestHoneytokens_ReadByEveryRoleWrittenByAdminsAndUsers(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		role        user.Role
		read, write bool
	}{
		{user.RoleAdmin, true, true},
		{user.RoleUser, true, true},
		{user.RoleViewer, true, false},
		{"", false, false},
	} {
		if got := Allowed(tt.role, "honeytokens:read"); got != tt.read {
			t.Errorf("Allowed(%q, honeytokens:read) = %v, want %v", tt.role, got, tt.read)
		}
		if got := Allowed(tt.role, "honeytokens:write"); got != tt.write {
			t.Errorf("Allowed(%q, honeytokens:write) = %v, want %v", tt.role, got, tt.write)
		}
	}
	// Viewers only read.
	for _, perm := range Permissions() {
		if Allowed(user.RoleViewer, perm) && !strings.HasSuffix(string(perm), ":read") {
			t.Errorf("viewers hold %s", perm)
		}
	}

	key := Principal{Method: audit.AuthAPIKey, APIKeyID: "k1", Scopes: []httpx.Permission{"honeytokens:read"}}
	if !key.Allowed("honeytokens:read") || key.Allowed("honeytokens:write") {
		t.Error("a key with honeytokens:read must read and not write honeytokens")
	}
}

// Every role reads the scenarios; only viewers cannot change them. A key with
// only the scope to read them cannot change them, and one that changes them
// must also read them.
func TestScenarios_ReadByEveryRoleWrittenByAdminsAndUsers(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		role        user.Role
		read, write bool
	}{
		{user.RoleAdmin, true, true},
		{user.RoleUser, true, true},
		{user.RoleViewer, true, false},
		{"", false, false},
	} {
		if got := Allowed(tt.role, "scenarios:read"); got != tt.read {
			t.Errorf("Allowed(%q, scenarios:read) = %v, want %v", tt.role, got, tt.read)
		}
		if got := Allowed(tt.role, "scenarios:write"); got != tt.write {
			t.Errorf("Allowed(%q, scenarios:write) = %v, want %v", tt.role, got, tt.write)
		}
	}

	key := Principal{Method: audit.AuthAPIKey, APIKeyID: "k1", Scopes: []httpx.Permission{"scenarios:read"}}
	if !key.Allowed("scenarios:read") || key.Allowed("scenarios:write") || key.Allowed("honeytokens:read") {
		t.Error("a key with scenarios:read must read scenarios and nothing else")
	}
	if got, ok := KeyScopeRequires("scenarios:write"); !ok || got != "scenarios:read" {
		t.Errorf("KeyScopeRequires(scenarios:write) = %s, %v", got, ok)
	}
}

// The catalog holds no inventory, so every role and every key with the scope
// reads it; nobody changes it, because it ships with the server.
func TestCatalog_ReadByEveryRoleAndKeysWithTheScope(t *testing.T) {
	t.Parallel()

	for _, role := range []user.Role{user.RoleAdmin, user.RoleUser, user.RoleViewer} {
		if !Allowed(role, "catalog:read") {
			t.Errorf("%s cannot read the catalog", role)
		}
	}
	if Allowed("", "catalog:read") {
		t.Error("an unknown role reads the catalog")
	}
	for _, perm := range Permissions() {
		if strings.HasPrefix(string(perm), "catalog:") && perm != "catalog:read" {
			t.Errorf("a role holds %s", perm)
		}
	}
	key := Principal{Method: audit.AuthAPIKey, APIKeyID: "k1", Scopes: []httpx.Permission{"catalog:read"}}
	if !key.Allowed("catalog:read") || key.Allowed("honeytokens:read") {
		t.Error("a key with catalog:read must read the catalog and nothing else")
	}
}

// Every role reads events and incidents; admins and users triage incidents,
// viewers do not. A key with only the scope to read incidents cannot triage
// them.
func TestIncidents_ReadByEveryRoleTriagedByAdminsAndUsers(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		role               user.Role
		read, write, event bool
	}{
		{user.RoleAdmin, true, true, true},
		{user.RoleUser, true, true, true},
		{user.RoleViewer, true, false, true},
		{"", false, false, false},
	} {
		if got := Allowed(tt.role, "incidents:read"); got != tt.read {
			t.Errorf("Allowed(%q, incidents:read) = %v, want %v", tt.role, got, tt.read)
		}
		if got := Allowed(tt.role, "incidents:write"); got != tt.write {
			t.Errorf("Allowed(%q, incidents:write) = %v, want %v", tt.role, got, tt.write)
		}
		if got := Allowed(tt.role, "events:read"); got != tt.event {
			t.Errorf("Allowed(%q, events:read) = %v, want %v", tt.role, got, tt.event)
		}
	}

	key := Principal{Method: audit.AuthAPIKey, APIKeyID: "k1", Scopes: []httpx.Permission{"incidents:read"}}
	if !key.Allowed("incidents:read") || key.Allowed("incidents:write") || key.Allowed("events:read") {
		t.Error("a key with incidents:read must read incidents and nothing else")
	}
	if got, ok := KeyScopeRequires("incidents:write"); !ok || got != "incidents:read" {
		t.Errorf("KeyScopeRequires(incidents:write) = %s, %v", got, ok)
	}
}

// A scope can only require a scope that keys may carry, or no key could carry
// the first one.
func TestKeyScopeRequires_NamesScopesKeysMayCarry(t *testing.T) {
	t.Parallel()

	for perm, required := range keyScopeRequires {
		if !slices.Contains(keyScopes, perm) || !slices.Contains(keyScopes, required) {
			t.Errorf("%s requires %s; both must be scopes that keys may carry", perm, required)
		}
	}
	if got, ok := KeyScopeRequires("honeytokens:write"); !ok || got != "honeytokens:read" {
		t.Errorf("KeyScopeRequires(honeytokens:write) = %s, %v", got, ok)
	}
}

// Only administrators manage alert channels: whoever changes them decides where
// alerts go, or whether they go anywhere.
func TestAlertChannels_ManagedByAdminsOnly(t *testing.T) {
	t.Parallel()

	for _, role := range []user.Role{user.RoleAdmin, user.RoleUser, user.RoleViewer, ""} {
		for _, perm := range []httpx.Permission{"alert_channels:read", "alert_channels:write"} {
			if got, want := Allowed(role, perm), role == user.RoleAdmin; got != want {
				t.Errorf("Allowed(%q, %s) = %v, want %v", role, perm, got, want)
			}
		}
	}
}

// Whether incidents are open tells an intruder whether they were noticed, so
// only administrators read the metrics.
func TestAllowed_MetricsOnlyForAdministrators(t *testing.T) {
	t.Parallel()

	for role, want := range map[user.Role]bool{user.RoleAdmin: true, user.RoleUser: false, user.RoleViewer: false} {
		if got := Allowed(role, "metrics:read"); got != want {
			t.Errorf("Allowed(%s, metrics:read) = %t, want %t", role, got, want)
		}
	}
}
