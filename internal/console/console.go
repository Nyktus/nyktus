// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package console serves the API and the web console.
package console

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"nyktus.org/nyktus/internal/platform/httpx"
)

const readinessTimeout = 2 * time.Second

// hashDeadline bounds requests that hash a password. They wait for a free hashing
// slot, which takes long only while the server is overloaded.
const hashDeadline = 10 * time.Second

// Pinger reports whether the database is reachable.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Deps are the dependencies of the console.
type Deps struct {
	Logger *slog.Logger
	DB     Pinger
	// Setup creates the first administrator.
	Setup http.Handler
	// Authorizer authenticates requests to routes that are not public.
	Authorizer httpx.Authorizer
	// SignIn, Session and SignOut serve the session of the caller, and
	// ChangePassword the password of its account.
	SignIn, Session, SignOut, ChangePassword http.Handler
	// SecondFactor completes sign-ins and manages the second factor.
	SecondFactor SecondFactor
	// APIKeys manages the API keys of the team.
	APIKeys APIKeys
	// OIDC signs users in through the identity provider.
	OIDC OIDC
	// AuditEntries lists the audit log.
	AuditEntries http.Handler
	// Metrics reports the state of the queues, incidents and periodic tasks.
	Metrics http.Handler
	// Accounts manages accounts and activates them.
	Accounts Accounts
	// Catalog lists the deceptions of the catalog.
	Catalog Catalog
	// Honeytokens manages the honeytokens of the team.
	Honeytokens Honeytokens
	// Scenarios manages the scenarios of the team.
	Scenarios Scenarios
	// Artifacts serves the artifacts of the scenarios.
	Artifacts Artifacts
	// Incidents lists and triages the incidents of the team.
	Incidents Incidents
	// Events lists the events of the honeytokens.
	Events Events
	// AlertChannels manages the channels that alerts are delivered to.
	AlertChannels AlertChannels
	// Origin is the origin under which users reach the console, such as
	// "https://nyktus.example.com". Requests that change state must come from it.
	Origin string
	// TrustedProxies are the address ranges of reverse proxies whose
	// X-Forwarded-For header determines the client address.
	TrustedProxies []netip.Prefix
}

// Accounts are the handlers of the management and activation of accounts and
// of the reset of passwords.
type Accounts struct {
	List, Get, Create, Update, Delete, IssueLink, Activate, IssueResetLink, ResetPassword http.Handler
}

// SecondFactor are the handlers of the second step of a sign-in and of the
// management of the TOTP factor of the caller.
type SecondFactor struct {
	CompleteSignIn, Begin, Confirm, ReplaceRecoveryCodes, Remove http.Handler
}

// APIKeys are the handlers of the management of the API keys of the team.
type APIKeys struct {
	List, Create, Revoke http.Handler
}

// Catalog are the handlers of the catalog.
type Catalog struct {
	List, Get http.Handler
}

func (c Catalog) complete() bool {
	return c.List != nil && c.Get != nil
}

// Honeytokens are the handlers of the management of the honeytokens.
type Honeytokens struct {
	List, Get, Create, Update, Delete http.Handler
	// AssignScenario and DetachScenario change the scenario of a honeytoken.
	AssignScenario, DetachScenario http.Handler
}

func (h Honeytokens) complete() bool {
	return h.List != nil && h.Get != nil && h.Create != nil && h.Update != nil && h.Delete != nil &&
		h.AssignScenario != nil && h.DetachScenario != nil
}

// Scenarios are the handlers of the management of the scenarios.
type Scenarios struct {
	List, Get, Create, Update, Delete http.Handler
	// Apply creates a scenario from a deception of the catalog, and Guide
	// reads the guide that applying it rendered.
	Apply, Guide http.Handler
}

func (h Scenarios) complete() bool {
	return h.List != nil && h.Get != nil && h.Create != nil && h.Update != nil && h.Delete != nil &&
		h.Apply != nil && h.Guide != nil
}

// Artifacts are the handlers of the artifacts: their metadata, the download
// of their content, their placement notes and their deletion.
type Artifacts struct {
	List, Get, Download, Update, Delete http.Handler
}

func (h Artifacts) complete() bool {
	return h.List != nil && h.Get != nil && h.Download != nil && h.Update != nil && h.Delete != nil
}

// Incidents are the handlers of the incidents and their triage.
type Incidents struct {
	List, Get, Update http.Handler
}

func (h Incidents) complete() bool {
	return h.List != nil && h.Get != nil && h.Update != nil
}

// Events are the handlers of the events.
type Events struct {
	List, Get http.Handler
}

func (h Events) complete() bool {
	return h.List != nil && h.Get != nil
}

// AlertChannels are the handlers of the management of the alert channels.
type AlertChannels struct {
	List, Get, Create, Update, Delete, Test http.Handler
	// GetDelivery, RetryDelivery and IncidentDeliveries serve the deliveries
	// of alerts and tests.
	GetDelivery, RetryDelivery, IncidentDeliveries http.Handler
}

func (c AlertChannels) complete() bool {
	return c.List != nil && c.Get != nil && c.Create != nil && c.Update != nil && c.Delete != nil && c.Test != nil &&
		c.GetDelivery != nil && c.RetryDelivery != nil && c.IncidentDeliveries != nil
}

// OIDC are the handlers of the sign-in through the identity provider: the
// start, which sends the browser to the provider, the start of a
// reauthentication, and the callback, to which the provider sends it back.
type OIDC struct {
	Authorize, Reauthenticate, Callback http.Handler
}

func (o OIDC) complete() bool {
	return o.Authorize != nil && o.Reauthenticate != nil && o.Callback != nil
}

func (k APIKeys) complete() bool {
	return k.List != nil && k.Create != nil && k.Revoke != nil
}

func (f SecondFactor) complete() bool {
	return f.CompleteSignIn != nil && f.Begin != nil && f.Confirm != nil && f.ReplaceRecoveryCodes != nil && f.Remove != nil
}

func (a Accounts) complete() bool {
	return a.List != nil && a.Get != nil && a.Create != nil && a.Update != nil &&
		a.Delete != nil && a.IssueLink != nil && a.Activate != nil && a.IssueResetLink != nil && a.ResetPassword != nil
}

// NewRouter registers the console routes. It panics if a dependency is missing,
// so that a wiring mistake stops the process at startup.
func NewRouter(d Deps) *httpx.Router {
	if d.Logger == nil || d.DB == nil || d.Setup == nil || d.Authorizer == nil ||
		d.SignIn == nil || d.Session == nil || d.SignOut == nil || d.ChangePassword == nil || !d.SecondFactor.complete() || !d.APIKeys.complete() || !d.OIDC.complete() || d.AuditEntries == nil || d.Metrics == nil || !d.Accounts.complete() || !d.Catalog.complete() || !d.Honeytokens.complete() || !d.Scenarios.complete() || !d.Artifacts.complete() || !d.Incidents.complete() || !d.Events.complete() || !d.AlertChannels.complete() {
		panic("console: router needs a logger, a database, an authorizer and the setup, session, OIDC, API key, audit, metrics, account, catalog, honeytoken, scenario, artifact, incident, event and alert channel handlers")
	}
	rt := httpx.NewRouter(d.Logger, d.Authorizer)
	// The session itself and how the account signs in are managed only with a
	// session, so that a leaked API key can neither sign the user out nor take
	// over the account.
	session := httpx.Authenticated.SessionOnly()
	rt.Handle(http.MethodGet, "/livez", httpx.Public, http.HandlerFunc(live))
	rt.Handle(http.MethodGet, "/readyz", httpx.Public, ready(d.Logger, d.DB))
	rt.Handle(http.MethodPost, "/api/v1/setup", httpx.Public, httpx.Deadline(hashDeadline)(d.Setup))
	rt.Handle(http.MethodPost, "/api/v1/session", httpx.Public, httpx.Deadline(hashDeadline)(d.SignIn))
	rt.Handle(http.MethodGet, "/api/v1/session", session, d.Session)
	rt.Handle(http.MethodDelete, "/api/v1/session", session, d.SignOut)
	rt.Handle(http.MethodPut, "/api/v1/session/password", session, httpx.Deadline(hashDeadline)(d.ChangePassword))
	rt.Handle(http.MethodPost, "/api/v1/session/second-factor", httpx.Public, d.SecondFactor.CompleteSignIn)
	rt.Handle(http.MethodGet, "/api/v1/oidc/authorize", httpx.Public, d.OIDC.Authorize)
	rt.Handle(http.MethodGet, "/api/v1/oidc/callback", httpx.Public, d.OIDC.Callback)
	rt.Handle(http.MethodGet, "/api/v1/oidc/reauthenticate", session, d.OIDC.Reauthenticate)
	rt.Handle(http.MethodPost, "/api/v1/session/totp", session, httpx.Deadline(hashDeadline)(d.SecondFactor.Begin))
	rt.Handle(http.MethodDelete, "/api/v1/session/totp", session, httpx.Deadline(hashDeadline)(d.SecondFactor.Remove))
	rt.Handle(http.MethodPost, "/api/v1/session/totp/confirmation", session, d.SecondFactor.Confirm)
	rt.Handle(http.MethodPost, "/api/v1/session/totp/recovery-codes", session,
		httpx.Deadline(hashDeadline)(d.SecondFactor.ReplaceRecoveryCodes))
	// Keys never manage keys, so that a leaked key cannot issue itself a
	// successor.
	rt.Handle(http.MethodGet, "/api/v1/api-keys", httpx.Require("api_keys:read").SessionOnly(), d.APIKeys.List)
	rt.Handle(http.MethodPost, "/api/v1/api-keys", httpx.Require("api_keys:write").SessionOnly(), httpx.Deadline(hashDeadline)(d.APIKeys.Create))
	rt.Handle(http.MethodDelete, "/api/v1/api-keys/{id}", httpx.Require("api_keys:write").SessionOnly(), d.APIKeys.Revoke)
	rt.Handle(http.MethodGet, "/api/v1/audit-entries", httpx.Require("audit:read"), d.AuditEntries)
	// Only administrators read the metrics: whether incidents are open tells an
	// intruder whether they were noticed.
	rt.Handle(http.MethodGet, "/api/v1/metrics", httpx.Require("metrics:read"), d.Metrics)
	rt.Handle(http.MethodGet, "/api/v1/users", httpx.Require("users:read"), d.Accounts.List)
	rt.Handle(http.MethodPost, "/api/v1/users", httpx.Require("users:write"), d.Accounts.Create)
	rt.Handle(http.MethodGet, "/api/v1/users/{id}", httpx.Require("users:read"), d.Accounts.Get)
	rt.Handle(http.MethodPatch, "/api/v1/users/{id}", httpx.Require("users:write"), httpx.Deadline(hashDeadline)(d.Accounts.Update))
	rt.Handle(http.MethodDelete, "/api/v1/users/{id}", httpx.Require("users:write"), d.Accounts.Delete)
	rt.Handle(http.MethodPost, "/api/v1/users/{id}/activation-link", httpx.Require("users:write"), d.Accounts.IssueLink)
	rt.Handle(http.MethodPost, "/api/v1/activation", httpx.Public, httpx.Deadline(hashDeadline)(d.Accounts.Activate))
	rt.Handle(http.MethodPost, "/api/v1/users/{id}/password-reset-link", httpx.Require("users:write"), d.Accounts.IssueResetLink)
	rt.Handle(http.MethodPost, "/api/v1/password-reset", httpx.Public, httpx.Deadline(hashDeadline)(d.Accounts.ResetPassword))
	rt.Handle(http.MethodGet, "/api/v1/catalog/deceptions", httpx.Require("catalog:read"), d.Catalog.List)
	rt.Handle(http.MethodGet, "/api/v1/catalog/deceptions/{id}", httpx.Require("catalog:read"), d.Catalog.Get)
	// Applying a deception creates a scenario with its honeytokens and
	// artifacts; the catalog stays as it is.
	rt.Handle(http.MethodPost, "/api/v1/catalog/deceptions/{id}/apply", httpx.Require("scenarios:write"), d.Scenarios.Apply)
	rt.Handle(http.MethodGet, "/api/v1/honeytokens", httpx.Require("honeytokens:read"), d.Honeytokens.List)
	rt.Handle(http.MethodPost, "/api/v1/honeytokens", httpx.Require("honeytokens:write"), d.Honeytokens.Create)
	rt.Handle(http.MethodGet, "/api/v1/honeytokens/{id}", httpx.Require("honeytokens:read"), d.Honeytokens.Get)
	rt.Handle(http.MethodPatch, "/api/v1/honeytokens/{id}", httpx.Require("honeytokens:write"), d.Honeytokens.Update)
	rt.Handle(http.MethodDelete, "/api/v1/honeytokens/{id}", httpx.Require("honeytokens:write"), d.Honeytokens.Delete)
	// The scenario of a honeytoken is a change of the honeytoken, which
	// decides how its events are correlated; the scenario stays as it is.
	rt.Handle(http.MethodPut, "/api/v1/honeytokens/{id}/scenario", httpx.Require("honeytokens:write"),
		d.Honeytokens.AssignScenario)
	rt.Handle(http.MethodDelete, "/api/v1/honeytokens/{id}/scenario", httpx.Require("honeytokens:write"),
		d.Honeytokens.DetachScenario)
	rt.Handle(http.MethodGet, "/api/v1/scenarios", httpx.Require("scenarios:read"), d.Scenarios.List)
	rt.Handle(http.MethodPost, "/api/v1/scenarios", httpx.Require("scenarios:write"), d.Scenarios.Create)
	rt.Handle(http.MethodGet, "/api/v1/scenarios/{id}", httpx.Require("scenarios:read"), d.Scenarios.Get)
	rt.Handle(http.MethodGet, "/api/v1/scenarios/{id}/guide", httpx.Require("scenarios:read"), d.Scenarios.Guide)
	rt.Handle(http.MethodPatch, "/api/v1/scenarios/{id}", httpx.Require("scenarios:write"), d.Scenarios.Update)
	rt.Handle(http.MethodDelete, "/api/v1/scenarios/{id}", httpx.Require("scenarios:write"), d.Scenarios.Delete)
	rt.Handle(http.MethodGet, "/api/v1/artifacts", httpx.Require("artifacts:read"), d.Artifacts.List)
	rt.Handle(http.MethodGet, "/api/v1/artifacts/{id}", httpx.Require("artifacts:read"), d.Artifacts.Get)
	rt.Handle(http.MethodGet, "/api/v1/artifacts/{id}/content", httpx.Require("artifacts:read"), d.Artifacts.Download)
	rt.Handle(http.MethodPatch, "/api/v1/artifacts/{id}", httpx.Require("artifacts:write"), d.Artifacts.Update)
	rt.Handle(http.MethodDelete, "/api/v1/artifacts/{id}", httpx.Require("artifacts:write"), d.Artifacts.Delete)
	rt.Handle(http.MethodGet, "/api/v1/incidents", httpx.Require("incidents:read"), d.Incidents.List)
	rt.Handle(http.MethodGet, "/api/v1/incidents/{id}", httpx.Require("incidents:read"), d.Incidents.Get)
	rt.Handle(http.MethodPatch, "/api/v1/incidents/{id}", httpx.Require("incidents:write"), d.Incidents.Update)
	rt.Handle(http.MethodGet, "/api/v1/events", httpx.Require("events:read"), d.Events.List)
	rt.Handle(http.MethodGet, "/api/v1/events/{id}", httpx.Require("events:read"), d.Events.Get)
	// Keys never manage alert channels, so that a leaked key can neither
	// redirect nor stop the alerts; changes that do are confirmed with the
	// password of the administrator, which needs a session.
	rt.Handle(http.MethodGet, "/api/v1/alert-channels", httpx.Require("alert_channels:read").SessionOnly(), d.AlertChannels.List)
	rt.Handle(http.MethodPost, "/api/v1/alert-channels", httpx.Require("alert_channels:write").SessionOnly(),
		httpx.Deadline(hashDeadline)(d.AlertChannels.Create))
	rt.Handle(http.MethodGet, "/api/v1/alert-channels/{id}", httpx.Require("alert_channels:read").SessionOnly(), d.AlertChannels.Get)
	rt.Handle(http.MethodPatch, "/api/v1/alert-channels/{id}", httpx.Require("alert_channels:write").SessionOnly(),
		httpx.Deadline(hashDeadline)(d.AlertChannels.Update))
	rt.Handle(http.MethodDelete, "/api/v1/alert-channels/{id}", httpx.Require("alert_channels:write").SessionOnly(),
		d.AlertChannels.Delete)
	rt.Handle(http.MethodPost, "/api/v1/alert-channels/{id}/test", httpx.Require("alert_channels:write").SessionOnly(),
		d.AlertChannels.Test)
	rt.Handle(http.MethodGet, "/api/v1/alert-deliveries/{id}", httpx.Require("alert_channels:read").SessionOnly(),
		d.AlertChannels.GetDelivery)
	rt.Handle(http.MethodPost, "/api/v1/alert-deliveries/{id}/retry", httpx.Require("alert_channels:write").SessionOnly(),
		d.AlertChannels.RetryDelivery)
	// Whoever reads incidents may see whether their alerts went out.
	rt.Handle(http.MethodGet, "/api/v1/incidents/{id}/deliveries", httpx.Require("incidents:read"),
		d.AlertChannels.IncidentDeliveries)
	return rt
}

// NewHandler returns the console HTTP handler with the shared middleware.
func NewHandler(d Deps) http.Handler {
	return httpx.Chain(NewRouter(d),
		httpx.RequestID,
		httpx.ClientIP(d.TrustedProxies),
		httpx.AccessLog(d.Logger),
		httpx.Recover(d.Logger),
		httpx.SameOrigin(d.Origin),
	)
}

type status struct {
	Status string `json:"status"`
}

// live reports that the process is running. It deliberately checks no dependencies,
// so that an orchestrator does not restart the process because the database is down.
func live(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, status{Status: "ok"})
}

// ready reports whether the console can serve requests.
func ready(logger *slog.Logger, db Pinger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
		defer cancel()
		if err := db.Ping(ctx); err != nil {
			httpx.Unavailable(w, r, logger, "readiness: database unreachable", err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, status{Status: "ok"})
	})
}
