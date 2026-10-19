// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package access decides what an authenticated principal may do.
//
// Roles grant permissions of the form "resource:action". The grants are a fixed
// table in code, so that every change to them is reviewed. An unknown role or
// permission grants nothing: checks fail closed.
package access

import (
	"context"
	"slices"
	"strings"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/user"
)

// grants lists the permissions of each role. A permission appears here when the
// first route that requires it is added.
var grants = map[user.Role][]httpx.Permission{
	user.RoleAdmin: {
		"alert_channels:read", "alert_channels:write", "api_keys:read", "api_keys:write", "artifacts:read",
		"artifacts:write", "audit:read", "catalog:read", "events:read", "honeypots:read", "honeypots:write",
		"honeytokens:read", "honeytokens:write", "incidents:read", "incidents:write", "metrics:read", "scenarios:read",
		"scenarios:write", "users:read", "users:write",
	},
	user.RoleUser: {
		"artifacts:read", "artifacts:write", "catalog:read", "events:read", "honeypots:read", "honeypots:write",
		"honeytokens:read", "honeytokens:write", "incidents:read", "incidents:write", "scenarios:read",
		"scenarios:write",
	},
	user.RoleViewer: {
		"artifacts:read", "catalog:read", "events:read", "honeypots:read", "honeytokens:read", "incidents:read",
		"scenarios:read",
	},
}

// keyScopes lists the permissions that an API key may carry as scopes. Keys do
// not manage accounts or keys, not even by reading them: a leaked key with
// users:write could take over every account through password reset links, and
// one with api_keys:write could issue itself a successor. Keys may manage
// honeytokens, honeypots, scenarios and artifacts, so that they can be rolled
// out by script; reading them is reading the inventory, so integrations that
// only need other data get keys without these scopes. Keys may read events and
// incidents and triage incidents, so that a SIEM or a ticket system can follow
// them up. Keys may read the metrics, so that a monitoring system can collect
// them. Keys may read the catalog, which holds no inventory. Keys never manage
// alert channels: a leaked key could redirect the alerts to its holder or stop
// them.
var keyScopes = []httpx.Permission{
	"artifacts:read", "artifacts:write", "audit:read", "catalog:read", "events:read", "honeypots:read",
	"honeypots:write", "honeytokens:read", "honeytokens:write", "incidents:read", "incidents:write", "metrics:read",
	"scenarios:read", "scenarios:write",
}

// keyScopeRequires names the scopes that a key may carry only together with
// another one. A key that changes honeytokens, honeypots, scenarios, artifacts
// or incidents receives them in every response, also to a change that changes
// nothing, so it reads them anyway; requiring the scope to read them keeps the scopes of a
// key honest about what it can see. For the same reason, reading scenarios
// and artifacts requires reading honeytokens: the guide of a scenario, the
// answer to applying a deception and the content of an artifact name the URLs
// and host names of honeytokens.
var keyScopeRequires = map[httpx.Permission]httpx.Permission{
	"artifacts:read":    "honeytokens:read",
	"artifacts:write":   "artifacts:read",
	"honeypots:write":   "honeypots:read",
	"honeytokens:write": "honeytokens:read",
	"incidents:write":   "incidents:read",
	"scenarios:read":    "honeytokens:read",
	"scenarios:write":   "scenarios:read",
}

// KeyScopeRequires returns the scope that a key must carry as well to carry
// perm, if there is one.
func KeyScopeRequires(perm httpx.Permission) (httpx.Permission, bool) {
	required, ok := keyScopeRequires[perm]
	return required, ok
}

// KeyScopes returns the permissions that an API key may carry as scopes.
func KeyScopes() []httpx.Permission {
	return slices.Clone(keyScopes)
}

// Allowed reports whether role grants perm.
func Allowed(role user.Role, perm httpx.Permission) bool {
	return slices.Contains(grants[role], perm)
}

// Permissions returns every permission that some role grants.
func Permissions() []httpx.Permission {
	var all []httpx.Permission
	for _, perms := range grants {
		for _, p := range perms {
			if !slices.Contains(all, p) {
				all = append(all, p)
			}
		}
	}
	slices.Sort(all)
	return all
}

// Principal is the authenticated party of a request.
type Principal struct {
	// UserID and Role are those of the signed-in user. An API key belongs to
	// the team and has neither.
	UserID string
	Role   user.Role
	// Method is how the principal authenticated, such as with a session.
	Method audit.AuthMethod
	// SessionID identifies the session, if the principal authenticated with one.
	SessionID string
	// APIKeyID identifies the API key, if the principal authenticated with one.
	APIKeyID string
	// Scopes are the scopes of the API key, which grant its permissions.
	Scopes []httpx.Permission
}

// Allowed reports whether p holds perm. A user holds the permissions of their
// current role. An API key holds its scopes, as far as keys may carry them, so
// that a scope that keys may no longer carry grants nothing.
func (p Principal) Allowed(perm httpx.Permission) bool {
	if p.Method == audit.AuthAPIKey {
		return slices.Contains(p.Scopes, perm) && slices.Contains(keyScopes, perm)
	}
	return Allowed(p.Role, perm)
}

// HasSession reports whether p signed in with a session, as opposed to another
// credential such as an API key.
func (p Principal) HasSession() bool {
	return p.Method == audit.AuthSession && p.SessionID != ""
}

// Actor returns the principal as the actor of an audit entry.
func (p Principal) Actor() audit.Actor {
	if p.Method == audit.AuthAPIKey {
		return audit.Actor{Kind: audit.ActorAPIKey, Method: audit.AuthAPIKey, APIKeyID: p.APIKeyID}
	}
	return audit.Actor{Kind: audit.ActorUser, Method: p.Method, UserID: p.UserID}
}

type principalKey struct{}

// WithPrincipal returns a copy of ctx that carries p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the principal carried by ctx. ok is false for a request
// that has not been authenticated.
func PrincipalFrom(ctx context.Context) (p Principal, ok bool) {
	p, ok = ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// DeniedAction names the audit action of a request denied for lacking perm. The
// permission "audit:read" becomes the action "audit.read", so the entry says what
// the principal tried to do.
func DeniedAction(perm httpx.Permission) audit.Action {
	return audit.Action(strings.Replace(string(perm), ":", ".", 1))
}
