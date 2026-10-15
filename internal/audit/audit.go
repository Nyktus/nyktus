// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package audit records security-relevant actions in an append-only log.
//
// An entry names who acted and how they authenticated, what they did to which
// resource, when, and with what outcome. For updates it names the changed fields,
// never their values, so that the log does not become a second copy of the
// inventory. The console's database role can add and read entries, but never
// change or delete them.
package audit

import (
	"context"
	"net/netip"

	"nyktus.org/nyktus/internal/platform/request"
)

// Action names what was done, in the form "resource.verb", for example
// "user.create". Actions are declared as constants of this type, so that every
// name in the log is known to the code. The database rejects other formats.
type Action string

// Actions recorded in the audit log.
const (
	// ActionUserCreate records the creation of an account. The actor tells
	// whether an administrator or the holder of the setup token created it.
	ActionUserCreate Action = "user.create"
	// ActionUserUpdate records a change of an account, with the names of the
	// changed fields.
	ActionUserUpdate Action = "user.update"
	// ActionUserDelete records the deletion of an account.
	ActionUserDelete Action = "user.delete"
	// ActionUserActivate records that a user set their password through an
	// activation link.
	ActionUserActivate Action = "user.activate"
	// ActionUserPasswordChange records an attempt of a signed-in user to change
	// their own password, successful or not.
	ActionUserPasswordChange Action = "user.password_change"
	// ActionUserPasswordReset records that a user set a new password through a
	// password reset link.
	ActionUserPasswordReset Action = "user.password_reset"
	// ActionUserTOTPEnroll records the start of the setup of a TOTP factor,
	// successful or not, by the user of the account.
	ActionUserTOTPEnroll Action = "user.totp_enroll"
	// ActionUserTOTPEnable records that a user confirmed a TOTP factor with a
	// first code, successfully or not.
	ActionUserTOTPEnable Action = "user.totp_enable"
	// ActionUserTOTPDisable records the removal of the TOTP factor of an
	// account, by its user, an administrator or the command line.
	ActionUserTOTPDisable Action = "user.totp_disable"
	// ActionUserRecoveryCodesCreate records an attempt of a user to replace their
	// recovery codes, successful or not.
	ActionUserRecoveryCodesCreate Action = "user.recovery_codes_create"
	// ActionUsersRead records a read of accounts, which contain personal data. A
	// request denied for lacking the permission users:read has the same action.
	ActionUsersRead Action = "users.read"
	// ActionActivationLinkCreate records an activation link issued for an
	// account. The resource is the account.
	ActionActivationLinkCreate Action = "activation_link.create"
	// ActionPasswordResetLinkCreate records a password reset link issued for an
	// account, by an administrator or the command line. The resource is the
	// account.
	ActionPasswordResetLinkCreate Action = "password_reset_link.create"
	// ActionSessionCreate records a sign-in, successful or not. With a second
	// factor, it records the second step, with the method of the factor.
	ActionSessionCreate Action = "session.create"
	// ActionSignInChallengeCreate records that a correct password started a
	// sign-in that waits for the second factor.
	ActionSignInChallengeCreate Action = "sign_in_challenge.create"
	// ActionSessionDelete records a sign-out.
	ActionSessionDelete Action = "session.delete"
	// ActionSessionReauthenticate records that a user of the identity provider
	// signed in there again, to confirm sensitive actions of the session, or
	// failed to.
	ActionSessionReauthenticate Action = "session.reauthenticate"
	// ActionAPIKeyCreate records a new API key, and an attempt to issue one with
	// a wrong password or for a locked account. The resource is the key, or the
	// account if the attempt failed.
	ActionAPIKeyCreate Action = "api_key.create"
	// ActionAPIKeyRevoke records the revocation of an API key, by its user or an
	// administrator. The resource is the key.
	ActionAPIKeyRevoke Action = "api_key.revoke" //nolint:gosec // An audit action, not a credential.
	// ActionAuditRead records a read of the audit log, which contains personal
	// data. A request denied for lacking the permission audit:read has the same
	// action.
	ActionAuditRead Action = "audit.read"
	// ActionHoneytokenCreate records the creation of a honeytoken.
	ActionHoneytokenCreate Action = "honeytoken.create"
	// ActionHoneytokenUpdate records a change of a honeytoken, with the names of
	// the changed fields.
	ActionHoneytokenUpdate Action = "honeytoken.update"
	// ActionHoneytokenDelete records the deletion of a honeytoken.
	ActionHoneytokenDelete Action = "honeytoken.delete"
	// ActionAlertChannelCreate records the creation of an alert channel, and an
	// attempt whose confirmation with a password failed.
	ActionAlertChannelCreate Action = "alert_channel.create"
	// ActionAlertChannelUpdate records a change of an alert channel, with the
	// names of the changed fields, and an attempt whose confirmation with a
	// password failed.
	ActionAlertChannelUpdate Action = "alert_channel.update"
	// ActionAlertChannelDelete records the deletion of an alert channel.
	ActionAlertChannelDelete Action = "alert_channel.delete"
	// ActionAlertChannelTest records a request to send a test to an alert
	// channel.
	ActionAlertChannelTest Action = "alert_channel.test"
	// ActionAlertDeliveryRetry records that a dead delivery of an alert was
	// made pending again.
	ActionAlertDeliveryRetry Action = "alert_delivery.retry"
	// ActionIncidentUpdate records the triage of an incident, with the names of
	// the changed fields.
	ActionIncidentUpdate Action = "incident.update"
	// ActionEventsRead records a read of events, which contain personal data
	// such as the addresses of clients. A request denied for lacking the
	// permission events:read has the same action.
	ActionEventsRead Action = "events.read"
)

// Outcome is the result of an action.
type Outcome string

// Outcomes of an action.
const (
	OutcomeSuccess Outcome = "success"
	// OutcomeFailure means the action was attempted and failed, such as a sign-in
	// with a wrong password.
	OutcomeFailure Outcome = "failure"
	// OutcomeDenied means the principal lacked the required permission.
	OutcomeDenied Outcome = "denied"
)

// ActorKind is the kind of party that acted.
type ActorKind string

// Kinds of actors.
const (
	// ActorUser is a signed-in user.
	ActorUser ActorKind = "user"
	// ActorAPIKey is an API key. Keys belong to the team, not to a user, so a
	// key acts on its own. The entry keeps a copy of its name.
	ActorAPIKey ActorKind = "api_key"
	// ActorSetup is the holder of the setup token, before the first administrator
	// exists.
	ActorSetup ActorKind = "setup"
	// ActorSystem is the command line or a background job.
	ActorSystem ActorKind = "system"
	// ActorAnonymous is an unauthenticated caller, such as a failed sign-in.
	ActorAnonymous ActorKind = "anonymous"
)

// AuthMethod is how the actor authenticated.
type AuthMethod string

// Authentication methods. The database accepts only the methods that fit the kind
// of actor.
const (
	AuthPassword   AuthMethod = "password"
	AuthOIDC       AuthMethod = "oidc"
	AuthSession    AuthMethod = "session"
	AuthAPIKey     AuthMethod = "api_key"
	AuthSetupToken AuthMethod = "setup_token"
	// AuthActivationToken is used by a user who activates their account through
	// an activation link.
	AuthActivationToken AuthMethod = "activation_token"
	// AuthPasswordResetToken is used by a user who sets a new password through a
	// password reset link.
	AuthPasswordResetToken AuthMethod = "password_reset_token"
	// AuthTOTP and AuthRecoveryCode are used in the second step of a sign-in,
	// which always belongs to a known account.
	AuthTOTP         AuthMethod = "totp"
	AuthRecoveryCode AuthMethod = "recovery_code"
	AuthCLI          AuthMethod = "cli"
	// AuthNone is used by background jobs, which act without authenticating.
	AuthNone AuthMethod = "none"
)

// Actor is the party that acted.
type Actor struct {
	Kind   ActorKind
	Method AuthMethod
	// UserID identifies the account of a user. It is set only for ActorUser. The
	// entry keeps a copy of the address and display name of the account, so it
	// stays readable after the account is deleted.
	UserID string
	// APIKeyID identifies the key that acted. It is set if and only if Kind is
	// ActorAPIKey.
	APIKeyID string
}

// Resource identifies what an action affected. Only its type and identifier are
// recorded, never its name or content.
type Resource struct {
	Type string
	ID   string
}

// Entry describes an action to record.
type Entry struct {
	Action  Action
	Outcome Outcome
	Actor   Actor
	// Resource is the zero value if the action affects no single resource.
	Resource Resource
	// ChangedFields names the fields that an update changed, without their
	// values.
	ChangedFields []string
	// ClientIP is the address of the client, if the action came from one.
	ClientIP netip.Addr
	// RequestID links the entry to the logs of the request, if there was one.
	RequestID string
}

// WithRequest returns e with the client address and the request ID of the
// request that ctx belongs to, so that handlers and the services they call do not
// pass them on one by one. The HTTP middleware determines the client address from
// the socket and trusted proxies, never from a header alone. Outside a request,
// both stay empty.
func (e Entry) WithRequest(ctx context.Context) Entry {
	e.ClientIP = request.ClientIP(ctx)
	e.RequestID = request.ID(ctx)
	return e
}
