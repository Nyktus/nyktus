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
	user.RoleAdmin:  {"audit:read", "users:read", "users:write"},
	user.RoleEditor: {},
	user.RoleViewer: {},
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
	UserID string
	Role   user.Role
	// Method is how the principal authenticated, such as with a session.
	Method audit.AuthMethod
	// SessionID identifies the session, if the principal authenticated with one.
	SessionID string
}

// Actor returns the principal as the actor of an audit entry.
func (p Principal) Actor() audit.Actor {
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
