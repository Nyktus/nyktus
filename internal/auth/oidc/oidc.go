// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package oidc signs users in through an OpenID Connect provider, with the
// authorization code flow, PKCE and a nonce.
//
// An account of the provider is created at the first sign-in of its user and
// named by the issuer and subject of the provider, never by its address. Its
// role follows the groups of the user at the provider: it is set again with
// every sign-in, and a user in none of the configured groups cannot sign in and
// is deactivated. The account has no password and no second factor of its own;
// both belong to the provider.
//
// A sign-in leaves the console for the provider and returns with a code. Its
// state is kept in the database between the two requests, so that it works
// across console processes, and is bound to the browser that started it by a
// token in a cookie.
//
// A signed-in user of the provider confirms a sensitive action, which a local
// account confirms with its password, by signing in at the provider again: a
// reauthentication, which asks the provider to request the credentials again
// and marks the session for session.ReauthenticationWindow.
package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/auth/token"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/user"
)

// ErrInvalidSignIn covers a sign-in that does not prove an identity: an unknown,
// expired or used state, a state of another browser, and a code or token that
// the provider does not vouch for. Such a sign-in is not recorded in the audit
// log, because it names no user.
var ErrInvalidSignIn = errors.New("invalid sign-in through the identity provider")

// RejectedError means that the provider vouched for the identity, but the
// sign-in was rejected. It is recorded in the audit log.
type RejectedError struct {
	Identity user.Identity
	// Reason explains the rejection to the operator. The user learns only that
	// the sign-in failed.
	Reason string
}

func (e *RejectedError) Error() string {
	return "sign-in through the identity provider rejected: " + e.Reason
}

// LogValue names the identity, so that the operator can find the user at the
// provider.
func (e *RejectedError) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("reason", e.Reason),
		slog.String("issuer", e.Identity.Issuer),
		slog.String("subject", e.Identity.Subject),
	)
}

// DB runs queries and starts transactions. A connection pool and a transaction
// implement it; in a transaction, Begin starts a savepoint.
type DB interface {
	db.Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Groups map the groups of the provider to roles.
type Groups struct {
	// GroupsClaim names the claim of the ID token that lists the groups.
	GroupsClaim string
	// The groups whose members receive a role. The highest role wins.
	Admin, User, Viewer []string
}

// Service signs users in through the provider. It is safe for concurrent use.
type Service struct {
	db       DB
	provider *Provider
	sessions *session.Service
	groups   Groups
}

// NewService returns a Service that signs users in through provider and starts
// their sessions with sessions.
func NewService(d DB, provider *Provider, sessions *session.Service, groups Groups) *Service {
	if d == nil || provider == nil || sessions == nil || groups.GroupsClaim == "" {
		panic("oidc: service needs a database, a provider, a session service and the claim of the groups")
	}
	return &Service{db: d, provider: provider, sessions: sessions, groups: groups}
}

// Purposes of a sign-in at the provider.
const (
	purposeSignIn           = "sign_in"
	purposeReauthentication = "reauthentication"
)

// authTimeLeeway is how much earlier than the start of a reauthentication the
// provider may report the authentication, for clocks that differ.
const authTimeLeeway = time.Minute

// Begin starts a sign-in. previous is the token of the session that the
// browser holds, if any, which ends when the sign-in completes. It returns the
// URL of the provider, to which the browser is sent, and the token that binds
// the sign-in to the browser, which it keeps in a cookie. It returns
// ErrUnavailable if the provider has not been discovered yet.
func (s *Service) Begin(ctx context.Context, previous string) (redirect, browser string, err error) {
	var previousHash []byte
	if previous != "" {
		previousHash = token.Hash(previous)
	}
	return s.begin(ctx, login{purpose: purposeSignIn, previousHash: previousHash})
}

// BeginReauthentication starts a reauthentication of the session sess, whose
// account signs in through the provider. The provider is asked to request the
// credentials again. The browser returns to returnTo, a path of the console
// that ValidReturnTo accepts. It returns what Begin returns.
func (s *Service) BeginReauthentication(ctx context.Context, sess session.Session, returnTo string) (redirect, browser string, err error) {
	if !ValidReturnTo(returnTo) {
		return "", "", errors.New("oidc: invalid return path")
	}
	return s.begin(ctx, login{purpose: purposeReauthentication, sessionID: sess.ID, returnTo: returnTo},
		oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
}

// login is a sign-in at the provider between its start and its completion.
type login struct {
	purpose      string
	previousHash []byte
	sessionID    string
	returnTo     string
}

func (s *Service) begin(ctx context.Context, l login, opts ...oauth2.AuthCodeOption) (redirect, browser string, err error) {
	e, err := s.provider.endpoints()
	if err != nil {
		return "", "", err
	}
	var state, nonce, verifier string
	for _, v := range []*string{&state, &browser, &nonce, &verifier} {
		if *v, err = token.New(); err != nil {
			return "", "", err
		}
	}
	// The worker removes sign-ins that were abandoned.
	_, err = s.db.Exec(ctx, `
INSERT INTO oidc_logins (state_hash, browser_hash, nonce, code_verifier, purpose, previous_session_hash, session_id, return_to)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		token.Hash(state), token.Hash(browser), nonce, verifier, l.purpose, l.previousHash, nullable(l.sessionID), nullable(l.returnTo))
	if err != nil {
		return "", "", fmt.Errorf("insert sign-in: %w", err)
	}
	opts = append(opts, gooidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	return e.oauth.AuthCodeURL(state, opts...), browser, nil
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// maxReturnToLength bounds the path to which a reauthentication returns.
const maxReturnToLength = 512

// ValidReturnTo reports whether path is a path of the console to which a
// reauthentication may return: it starts with a single slash, so that it names
// neither another site nor a protocol-relative one, and consists of printable
// ASCII without backslashes, which some browsers read as slashes, and without
// a fragment, to which the console appends its own.
func ValidReturnTo(path string) bool {
	if len(path) > maxReturnToLength || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return false
	}
	for i := range len(path) {
		if c := path[i]; c <= ' ' || c > '~' || c == '\\' || c == '#' {
			return false
		}
	}
	return true
}

// Result is the outcome of a sign-in at the provider.
type Result struct {
	// ReturnTo is set for a reauthentication, also one that failed after its
	// state was found: the path to which the browser returns.
	ReturnTo string
	// Session is the new session of a sign-in, or the session that a
	// reauthentication confirmed. Token is the token of a new session.
	Session session.Session
	Token   string
}

// Complete completes the sign-in with the state and code with which the
// provider sent the browser back, and the token of the browser from its
// cookie. It starts a session of the account of the identity, which it creates
// at the first sign-in, and ends the session that the browser held when the
// sign-in began.
//
// A reauthentication instead confirms the session that started it, if the
// provider confirmed the same identity, with its current role, and asked for
// its credentials again.
//
// It returns ErrInvalidSignIn if the sign-in does not prove an identity, a
// *RejectedError if the identity may not sign in, and ErrUnavailable if the
// provider has not been discovered yet. The state is consumed in every case,
// so that it works once.
func (s *Service) Complete(ctx context.Context, state, browser, code string) (Result, error) {
	var (
		nonce, verifier, purpose string
		previous                 []byte
		sessionID, returnTo      *string
		startedAt                time.Time
	)
	err := s.db.QueryRow(ctx, `
DELETE FROM oidc_logins
WHERE state_hash = $1 AND browser_hash = $2 AND expires_at > clock_timestamp()
RETURNING nonce, code_verifier, purpose, previous_session_hash, session_id, return_to, created_at`,
		token.Hash(state), token.Hash(browser)).Scan(&nonce, &verifier, &purpose, &previous, &sessionID, &returnTo, &startedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{}, fmt.Errorf("%w: unknown, expired or used state, or another browser", ErrInvalidSignIn)
	}
	if err != nil {
		return Result{}, fmt.Errorf("consume sign-in: %w", err)
	}

	switch {
	case purpose == purposeReauthentication && sessionID != nil && returnTo != nil:
		res := Result{ReturnTo: *returnTo}
		c, err := s.verify(ctx, code, nonce, verifier)
		if err != nil {
			return res, err
		}
		res.Session, err = s.reauthenticate(ctx, c, *sessionID, startedAt)
		return res, err
	case purpose != purposeSignIn:
		// The schema rules this out; a reauthentication must never start a
		// session.
		return Result{}, fmt.Errorf("sign-in with purpose %q and incomplete fields", purpose)
	}
	c, err := s.verify(ctx, code, nonce, verifier)
	if err != nil {
		return Result{}, err
	}
	sess, tok, err := s.signIn(ctx, c, previous)
	return Result{Session: sess, Token: tok}, err
}

// claims are what the console takes from a verified ID token. Claims are taken
// only from the ID token, which the provider signs, and not from the userinfo
// endpoint.
type claims struct {
	identity user.Identity
	email    string
	// emailVerified is true only if the provider says that it verified the
	// address.
	emailVerified bool
	name          string
	groups        []string
	// authTime is when the user last entered their credentials at the
	// provider, or zero if the provider does not say.
	authTime time.Time
}

// verify exchanges code for the tokens of the user and verifies the ID token:
// its signature, issuer, audience, expiry and nonce.
func (s *Service) verify(ctx context.Context, code, nonce, verifier string) (claims, error) {
	e, err := s.provider.endpoints()
	if err != nil {
		return claims{}, err
	}
	ctx = s.provider.withClient(ctx)
	tok, err := e.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return claims{}, fmt.Errorf("%w: exchange code: %w", ErrInvalidSignIn, err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		return claims{}, fmt.Errorf("%w: the token response has no ID token", ErrInvalidSignIn)
	}
	idToken, err := e.verifier.Verify(ctx, raw)
	if err != nil {
		return claims{}, fmt.Errorf("%w: verify ID token: %w", ErrInvalidSignIn, err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		return claims{}, fmt.Errorf("%w: the ID token has another nonce", ErrInvalidSignIn)
	}

	var all map[string]json.RawMessage
	if err := idToken.Claims(&all); err != nil {
		return claims{}, fmt.Errorf("%w: read claims: %w", ErrInvalidSignIn, err)
	}
	// A token for several audiences must name the console as the party it was
	// issued to (OpenID Connect Core 1.0, section 3.1.3.7).
	azp, hasAZP := stringClaim(all, "azp")
	if (hasAZP && azp != s.provider.cfg.ClientID) || (!hasAZP && len(idToken.Audience) > 1) {
		return claims{}, fmt.Errorf("%w: the ID token was issued to another party", ErrInvalidSignIn)
	}

	c := claims{
		// The configured issuer, which the verifier compared with the token.
		identity: user.Identity{Issuer: s.provider.cfg.Issuer, Subject: idToken.Subject},
		groups:   groupsClaim(all[s.groups.GroupsClaim]),
	}
	if !c.identity.Valid() {
		return claims{}, fmt.Errorf("%w: the subject is empty, longer than %d characters or not printable ASCII",
			ErrInvalidSignIn, user.MaxSubjectLength)
	}
	var authTime int64
	if raw, ok := all["auth_time"]; ok && json.Unmarshal(raw, &authTime) == nil && authTime > 0 {
		c.authTime = time.Unix(authTime, 0)
	}
	c.email, _ = stringClaim(all, "email")
	c.name, _ = stringClaim(all, "name")
	if v, ok := all["email_verified"]; ok {
		// Some providers send the value as a string.
		c.emailVerified = string(v) == "true" || string(v) == `"true"`
	}
	return c, nil
}

func stringClaim(all map[string]json.RawMessage, name string) (string, bool) {
	var v string
	if raw, ok := all[name]; !ok || json.Unmarshal(raw, &v) != nil {
		return "", false
	}
	return v, true
}

// groupsClaim reads a list of groups, or a single group, which some providers
// send for a user with one group.
func groupsClaim(raw json.RawMessage) []string {
	var groups []string
	if json.Unmarshal(raw, &groups) == nil {
		return groups
	}
	var group string
	if json.Unmarshal(raw, &group) == nil {
		return []string{group}
	}
	return nil
}

// role returns the highest role of groups, or false if no group has a role.
func (s *Service) role(groups []string) (user.Role, bool) {
	for _, rg := range []struct {
		role   user.Role
		groups []string
	}{{user.RoleAdmin, s.groups.Admin}, {user.RoleUser, s.groups.User}, {user.RoleViewer, s.groups.Viewer}} {
		for _, g := range groups {
			if slices.Contains(rg.groups, g) {
				return rg.role, true
			}
		}
	}
	return "", false
}

// signIn signs the verified identity of c in, in one transaction with the
// creation or update of its account.
//
// The active administrators are locked first, in the order that every change of
// accounts takes, so that a change of role cannot remove the last one. The lock
// also serializes the first sign-ins of an identity, so that they create one
// account.
func (s *Service) signIn(ctx context.Context, c claims, previous []byte) (session.Session, string, error) {
	var (
		sess    session.Session
		tok     string
		outcome error
	)
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		users := user.NewStore(tx)
		admins, err := users.LockActiveAdmins(ctx)
		if err != nil {
			return err
		}
		// The first administrator is created with the setup token, which
		// proves access to the server. The provider must not take its place.
		if len(admins) == 0 {
			outcome = s.reject(c, "no administrator exists yet; complete the setup first")
			return recordFailure(ctx, tx, anonymous)
		}

		var (
			u   user.User
			rej *rejection
		)
		existing, err := users.LockByIdentity(ctx, c.identity)
		switch {
		case errors.Is(err, user.ErrNotFound):
			u, rej, err = s.create(ctx, tx, c)
		case err != nil:
			return err
		default:
			u, rej, err = s.update(ctx, tx, existing, c)
		}
		if err != nil {
			return err
		}
		if rej != nil {
			outcome = s.reject(c, rej.reason)
			return recordFailure(ctx, tx, rej.actor)
		}

		sess, tok, err = s.sessions.Start(ctx, tx, u, previous)
		if err != nil {
			return err
		}
		return audit.NewStore(tx).Record(ctx, audit.Entry{
			Action:   audit.ActionSessionCreate,
			Outcome:  audit.OutcomeSuccess,
			Actor:    actorOf(u.ID),
			Resource: audit.Resource{Type: "session", ID: sess.ID},
		}.WithRequest(ctx))
	})
	if err != nil {
		return session.Session{}, "", fmt.Errorf("sign in through the identity provider: %w", err)
	}
	if outcome != nil {
		return session.Session{}, "", outcome
	}
	return sess, tok, nil
}

// anonymous is the actor of a rejected sign-in of an identity without an
// account. The entry names neither the subject nor the address; the
// application log does.
var anonymous = audit.Actor{Kind: audit.ActorAnonymous, Method: audit.AuthOIDC}

func actorOf(id string) audit.Actor {
	return audit.Actor{Kind: audit.ActorUser, Method: audit.AuthOIDC, UserID: id}
}

func (s *Service) reject(c claims, reason string) error {
	return &RejectedError{Identity: c.identity, Reason: reason}
}

// rejection is why an identity may not sign in, and the actor under which the
// failure is recorded.
type rejection struct {
	reason string
	actor  audit.Actor
}

func recordFailure(ctx context.Context, q db.Querier, actor audit.Actor) error {
	return audit.NewStore(q).Record(ctx, audit.Entry{
		Action: audit.ActionSessionCreate, Outcome: audit.OutcomeFailure, Actor: actor,
	}.WithRequest(ctx))
}

// create creates the account of the identity of c at its first sign-in, or
// returns the reason why it may not sign in.
func (s *Service) create(ctx context.Context, tx pgx.Tx, c claims) (user.User, *rejection, error) {
	role, ok := s.role(c.groups)
	if !ok {
		return user.User{}, &rejection{"the user is in none of the groups of a role", anonymous}, nil
	}
	email, err := user.ParseEmail(c.email)
	if valid := err == nil && c.emailVerified; !valid {
		return user.User{}, &rejection{"the ID token has no valid, verified email address", anonymous}, nil
	}

	var created user.User
	// A savepoint, so that the transaction survives a rejected insert and can
	// record the rejection.
	err = pgx.BeginFunc(ctx, tx, func(sp pgx.Tx) error {
		created, err = user.NewStore(sp).Create(ctx, user.NewUser{
			Email: email, DisplayName: displayName(c.name, email), Role: role, Identity: &c.identity,
		})
		return err
	})
	if errors.Is(err, user.ErrEmailTaken) {
		// Accounts are never linked by their address: whoever controls the
		// address at the provider would take over the account.
		return user.User{}, &rejection{"another account has the email address", anonymous}, nil
	}
	if err != nil {
		return user.User{}, nil, err
	}
	err = audit.NewStore(tx).Record(ctx, audit.Entry{
		Action:   audit.ActionUserCreate,
		Outcome:  audit.OutcomeSuccess,
		Actor:    actorOf(created.ID),
		Resource: audit.Resource{Type: "user", ID: created.ID},
	}.WithRequest(ctx))
	return created, nil, err
}

// update brings the account u, which the caller has locked, in line with the
// groups and the name that the provider reports, or returns the reason why it
// may not sign in. A user in none of the groups is deactivated, so that the
// account stays locked out even if the user is added to a group again by
// mistake; an administrator reactivates it.
func (s *Service) update(ctx context.Context, tx pgx.Tx, u user.User, c claims) (user.User, *rejection, error) {
	users := user.NewStore(tx)
	actor := actorOf(u.ID)
	if u.Status != user.StatusActive {
		return user.User{}, &rejection{"the account is deactivated", actor}, nil
	}

	role, ok := s.role(c.groups)
	if !ok {
		deactivated := user.StatusDeactivated
		_, changed, err := users.Update(ctx, u.ID, user.Change{Status: &deactivated, FromProvider: true})
		if errors.Is(err, user.ErrLastActiveAdmin) {
			return user.User{}, &rejection{"the user is in none of the groups of a role, but is the last active administrator", actor}, nil
		}
		if err != nil {
			return user.User{}, nil, err
		}
		if err := session.RevokeAll(ctx, tx, u.ID); err != nil {
			return user.User{}, nil, err
		}
		if err := recordUpdate(ctx, tx, actor, u.ID, changed); err != nil {
			return user.User{}, nil, err
		}
		return user.User{}, &rejection{"the user is in none of the groups of a role; the account was deactivated", actor}, nil
	}

	change := user.Change{FromProvider: true}
	if role != u.Role {
		change.Role = &role
	}
	// The address stays as it was created: it may be the sign-in name of the
	// account in the audit log and in the list of accounts. A name that the
	// console would reject keeps the previous one.
	if name, err := user.ParseDisplayName(c.name); err == nil && name != u.DisplayName {
		change.DisplayName = &name
	}
	if change.Role == nil && change.DisplayName == nil {
		return u, nil, nil
	}
	updated, changed, err := users.Update(ctx, u.ID, change)
	if errors.Is(err, user.ErrLastActiveAdmin) {
		return user.User{}, &rejection{"the groups of the user would demote the last active administrator", actor}, nil
	}
	if err != nil {
		return user.User{}, nil, err
	}
	// A new role takes effect for the new session at once; the other sessions
	// of the account end, as with any change of role.
	if slices.Contains(changed, user.FieldRole) {
		if err := session.RevokeAll(ctx, tx, u.ID); err != nil {
			return user.User{}, nil, err
		}
	}
	return updated, nil, recordUpdate(ctx, tx, actor, u.ID, changed)
}

func recordUpdate(ctx context.Context, q db.Querier, actor audit.Actor, id string, changed []string) error {
	return audit.NewStore(q).Record(ctx, audit.Entry{
		Action:        audit.ActionUserUpdate,
		Outcome:       audit.OutcomeSuccess,
		Actor:         actor,
		Resource:      audit.Resource{Type: "user", ID: id},
		ChangedFields: changed,
	}.WithRequest(ctx))
}

// displayName returns the name of a new account: the name that the provider
// reports, or the address if the console would reject the name.
func displayName(name, email string) string {
	if valid, err := user.ParseDisplayName(name); err == nil {
		return valid
	}
	if utf8.RuneCountInString(email) <= user.MaxDisplayNameLength {
		return email
	}
	// Only the local part is cut. An address has no spaces, so the result is
	// a valid name.
	local, _, _ := strings.Cut(email, "@")
	return string([]rune(local)[:min(utf8.RuneCountInString(local), user.MaxDisplayNameLength)])
}

// reauthenticate confirms the session sessionID, whose reauthentication
// started at startedAt, with the verified identity of c.
//
// The provider must confirm the identity of the account of the session, with
// the role that the account has, and must report that it asked for the
// credentials after the reauthentication started. A role that the groups no
// longer give is changed only by the next sign-in, so a reauthentication with
// other groups is rejected rather than confirming the old role.
func (s *Service) reauthenticate(ctx context.Context, c claims, sessionID string, startedAt time.Time) (session.Session, error) {
	var (
		sess    session.Session
		outcome error
	)
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var userID string
		err := tx.QueryRow(ctx, `SELECT user_id FROM sessions WHERE id = $1`, sessionID).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			// The session ended meanwhile; nobody is left to confirm.
			outcome = fmt.Errorf("%w: the session ended", ErrInvalidSignIn)
			return nil
		}
		if err != nil {
			return fmt.Errorf("look up session: %w", err)
		}
		// The account is locked, so that its role and status hold until the
		// session is marked.
		u, err := user.NewStore(tx).Lock(ctx, userID)
		if err != nil {
			return err
		}
		role, inGroups := s.role(c.groups)
		var reason string
		switch {
		case u.Status != user.StatusActive:
			reason = "the account is not active"
		case u.Identity == nil || *u.Identity != c.identity:
			reason = "the provider confirmed another user than the one of the session"
		case c.authTime.IsZero() || c.authTime.Before(startedAt.Add(-authTimeLeeway)):
			reason = "the provider did not report that it asked for the credentials again"
		case !inGroups || role != u.Role:
			reason = "the groups of the user no longer give the role of the account; the user signs in again"
		}
		actor := actorOf(u.ID)
		resource := audit.Resource{Type: "session", ID: sessionID}
		if reason != "" {
			outcome = s.reject(c, reason)
			return audit.NewStore(tx).Record(ctx, audit.Entry{
				Action: audit.ActionSessionReauthenticate, Outcome: audit.OutcomeFailure, Actor: actor, Resource: resource,
			}.WithRequest(ctx))
		}
		if err := session.MarkReauthenticated(ctx, tx, sessionID, u.ID); err != nil {
			return err
		}
		sess = session.Session{ID: sessionID, User: u}
		return audit.NewStore(tx).Record(ctx, audit.Entry{
			Action: audit.ActionSessionReauthenticate, Outcome: audit.OutcomeSuccess, Actor: actor, Resource: resource,
		}.WithRequest(ctx))
	})
	if err != nil {
		return session.Session{}, fmt.Errorf("reauthenticate through the identity provider: %w", err)
	}
	if outcome != nil {
		return session.Session{}, outcome
	}
	return sess, nil
}
