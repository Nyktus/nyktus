// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package scenarioapi serves the scenarios of the team, applies the deceptions
// of the catalog, which creates scenarios, and adds deceptions of the catalog
// to scenarios that exist, or removes them. The routes must require the
// permissions scenarios:read and scenarios:write; creating the resources that a
// deception asks for needs those of the resources as well.
package scenarioapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/honeypot/honeypotapi"
	"nyktus.org/nyktus/internal/honeytoken/honeytokenapi"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/platform/secretbox"
	"nyktus.org/nyktus/internal/scenario"
)

// Error codes of applying a deception.
const (
	// codeDNSNotConfigured answers a deception with a DNS honeytoken while
	// the console knows no zone of the DNS role, as for honeytokens.
	codeDNSNotConfigured = "dns_not_configured"
	// codeDeceptionAdded answers a deception that is part of the scenario
	// already.
	codeDeceptionAdded = "deception_already_added"
)

// defaultPageSize is the page size if the request names none.
const defaultPageSize = 50

// maxBodyBytes bounds the requests: notes of 2000 characters, even with every
// character escaped in JSON, and the activities fit with room to spare.
const maxBodyBytes = 64 << 10

// paramHoneytokens and paramHoneypots choose what the deletion of a scenario
// does with its honeytokens and honeypots.
const (
	paramHoneytokens = "honeytokens"
	paramHoneypots   = "honeypots"
)

// Handler serves the scenarios.
type Handler struct {
	logger  *slog.Logger
	db      scenario.DB
	catalog *catalog.Catalog
	// triggerURL is the public address of the trigger, and dnsZones are the
	// zones of the DNS role, as for honeytokens.
	triggerURL string
	dnsZones   []string
	// keys seal the secrets of the honeypots that applying a deception
	// creates.
	keys *secretbox.Keyring
}

// NewHandler returns the handlers of the scenarios. Deceptions of c are
// applied, if asked, with honeytokens whose URLs start with triggerURL, the
// public address of the trigger, and whose names, of DNS honeytokens, are
// under the first of dnsZones, the zones of the DNS role in lower case without
// a trailing dot, or none. The secrets of the honeypots that are created are
// sealed with keys.
func NewHandler(logger *slog.Logger, d scenario.DB, c *catalog.Catalog, triggerURL string, dnsZones []string, keys *secretbox.Keyring) *Handler {
	if logger == nil || d == nil || c == nil || keys == nil {
		panic("scenarioapi: handler needs a logger, a database, a catalog and keys")
	}
	return &Handler{logger: logger, db: d, catalog: c, triggerURL: triggerURL, dnsZones: dnsZones, keys: keys}
}

// response is the representation of a scenario. Its resources are listed
// through their own lists, filtered by the scenario.
type response struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	Notes            string         `json:"notes"`
	EngageActivities []string       `json:"engage_activities"`
	Deceptions       []deceptionRef `json:"deceptions"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

// deceptionRef is a deception that joined a scenario. Its guide, files and
// slots are read from the catalog.
type deceptionRef struct {
	DeceptionID string    `json:"deception_id"`
	CreatedAt   time.Time `json:"created_at"`
}

func toResponse(s scenario.Scenario) response {
	activities := s.EngageActivities
	if activities == nil {
		activities = []string{}
	}
	deceptions := make([]deceptionRef, 0, len(s.Deceptions))
	for _, d := range s.Deceptions {
		deceptions = append(deceptions, deceptionRef{DeceptionID: d.DeceptionID, CreatedAt: d.CreatedAt})
	}
	return response{
		ID:               s.ID,
		Name:             s.Name,
		Notes:            s.Notes,
		EngageActivities: activities,
		Deceptions:       deceptions,
		CreatedAt:        s.CreatedAt,
		UpdatedAt:        s.UpdatedAt,
	}
}

type listResponse struct {
	Scenarios  []response `json:"scenarios"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

// List handles GET /api/v1/scenarios.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q, ok := httpx.DecodeListQuery(w, r, defaultPageSize, scenario.MaxPageSize)
	if !ok {
		return
	}
	var after *scenario.Cursor
	if q.After != nil {
		after = &scenario.Cursor{CreatedAt: q.After.Time, ID: q.After.ID}
	}
	list, next, err := scenario.NewStore(h.db).List(r.Context(), q.Limit, after)
	if err != nil {
		httpx.ServerError(w, r, h.logger, "scenario: list", err)
		return
	}
	resp := listResponse{Scenarios: make([]response, 0, len(list))}
	for _, s := range list {
		resp.Scenarios = append(resp.Scenarios, toResponse(s))
	}
	if next != nil {
		resp.NextCursor = httpx.EncodeCursor(httpx.Cursor{Time: next.CreatedAt, ID: next.ID})
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/scenarios/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	s, err := scenario.NewStore(h.db).Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeError(w, r, "scenario: get", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toResponse(s))
}

// createRequest is the request to create a scenario. The optional members
// reject null, as in a change, so that null never silently means the default.
// The deceptions are not among them: only a deception of the catalog adds to
// them.
type createRequest struct {
	Name             string                   `json:"name"`
	Notes            httpx.Optional[string]   `json:"notes"`
	EngageActivities httpx.Optional[[]string] `json:"engage_activities"`
}

// Create handles POST /api/v1/scenarios.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var req createRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	s, err := scenario.Create(r.Context(), h.db, p.Actor(), scenario.Spec{
		Name:             req.Name,
		Notes:            req.Notes.Value,
		EngageActivities: req.EngageActivities.Value,
	})
	if err != nil {
		h.writeError(w, r, "scenario: create", err)
		return
	}
	h.logger.InfoContext(r.Context(), "scenario: created", slog.Any("scenario", s))
	httpx.WriteJSON(w, http.StatusCreated, toResponse(s))
}

// updateRequest lists every field that a change may contain. The deceptions are
// not among them, and neither are the resources of the scenario, which join and
// leave it through operations of their own.
type updateRequest struct {
	Name             httpx.Optional[string]   `json:"name"`
	Notes            httpx.Optional[string]   `json:"notes"`
	EngageActivities httpx.Optional[[]string] `json:"engage_activities"`
}

// Update handles PATCH /api/v1/scenarios/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var req updateRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	c := scenario.Change{
		Name:                req.Name.Ptr(),
		Notes:               req.Notes.Ptr(),
		EngageActivities:    req.EngageActivities.Value,
		SetEngageActivities: req.EngageActivities.Set,
	}
	if c.IsEmpty() {
		invalid(w, r, "request must change name, notes or engage_activities")
		return
	}
	s, err := scenario.Update(r.Context(), h.db, p.Actor(), r.PathValue("id"), c)
	if err != nil {
		h.writeError(w, r, "scenario: update", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toResponse(s))
}

// Delete handles DELETE /api/v1/scenarios/{id}. The parameters honeytokens and
// honeypots choose whether its honeytokens and honeypots are deleted with it or
// stay alone, which is the default: a deleted honeytoken that is still placed
// or a deleted honeypot whose sensor still runs records nothing. Deleting the
// honeypots also requires honeypots:write: only that permission puts them into
// a scenario.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	query, ok := httpx.DecodeQuery(w, r, paramHoneytokens, paramHoneypots)
	if !ok {
		return
	}
	removals := scenario.ResourceRemovals{Honeytokens: scenario.RemovalKeep, Honeypots: scenario.RemovalKeep}
	if v, ok := query[paramHoneytokens]; ok {
		removals.Honeytokens = scenario.Removal(v)
	}
	if v, ok := query[paramHoneypots]; ok {
		removals.Honeypots = scenario.Removal(v)
	}
	if removals.Honeypots == scenario.RemovalDelete && !h.allowed(w, r, p, deleteHoneypots) {
		return
	}
	removed, err := scenario.Delete(r.Context(), h.db, p.Actor(), r.PathValue("id"), removals)
	if err != nil {
		h.writeError(w, r, "scenario: delete", err)
		return
	}
	h.logger.InfoContext(r.Context(), "scenario: deleted", slog.String("scenario_id", r.PathValue("id")),
		slog.Int("honeytokens_deleted", len(removed.DeletedHoneytokens)),
		slog.Int("honeytokens_detached", len(removed.DetachedHoneytokens)),
		slog.Int("honeypots_deleted", len(removed.DeletedHoneypots)),
		slog.Int("honeypots_detached", len(removed.DetachedHoneypots)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// Permissions that a request needs beyond the one of its route: deleting the
// honeypots of a scenario with it, and creating the resources of a deception.
const (
	deleteHoneypots  httpx.Permission = "honeypots:write"
	createHoneytoken httpx.Permission = "honeytokens:write"
	createHoneypot   httpx.Permission = "honeypots:write"
)

// allowed reports whether p holds perm, which the request needs beyond the
// permission of its route. A denial is recorded and answered as the authorizer
// does it, before anything is loaded, so that it reveals nothing about the
// scenario.
func (h *Handler) allowed(w http.ResponseWriter, r *http.Request, p access.Principal, perm httpx.Permission) bool {
	if p.Allowed(perm) {
		return true
	}
	err := audit.NewStore(h.db).RecordUnlessRepeated(r.Context(), audit.Entry{
		Action:  access.DeniedAction(perm),
		Outcome: audit.OutcomeDenied,
		Actor:   p.Actor(),
	}.WithRequest(r.Context()))
	if err != nil {
		httpx.ServerError(w, r, h.logger, "scenario: record denied request", err)
		return false
	}
	httpx.WriteError(w, r, http.StatusForbidden, httpx.CodeForbidden, "permission denied")
	return false
}

// principal returns the principal that the authorizer attached to the request.
// Without one, the route was registered without authentication, which is a
// wiring mistake.
func (h *Handler) principal(w http.ResponseWriter, r *http.Request) (access.Principal, bool) {
	p, ok := access.PrincipalFrom(r.Context())
	if !ok {
		httpx.ServerError(w, r, h.logger, "scenario: read principal", errors.New("no principal in the request context"))
	}
	return p, ok
}

// Rules of the fields, as the error responses state them.
var (
	nameRule       = fmt.Sprintf("name must have 1 to %d printable characters without leading or trailing spaces", scenario.MaxNameLength)
	notesRule      = fmt.Sprintf("notes must have at most %d characters; line breaks and tabs are the only control characters allowed", scenario.MaxNotesLength)
	activitiesRule = fmt.Sprintf("engage_activities must list at most %d distinct engagement activities of MITRE Engage, such as EAC0005", scenario.MaxEngageActivities)
	removalRule    = "honeytokens and honeypots must be keep or delete"
	languageRule   = "language must be one of " + strings.Join(catalog.Languages, ", ")
)

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, scenario.ErrNotFound), errors.Is(err, scenario.ErrDeceptionNotAdded):
		httpx.NotFound(w, r)
	case errors.Is(err, scenario.ErrInvalidName):
		invalid(w, r, nameRule)
	case errors.Is(err, scenario.ErrInvalidNotes):
		invalid(w, r, notesRule)
	case errors.Is(err, scenario.ErrInvalidEngageActivities):
		invalid(w, r, activitiesRule)
	case errors.Is(err, scenario.ErrInvalidRemoval):
		invalid(w, r, removalRule)
	case errors.Is(err, scenario.ErrInvalidLanguage):
		invalid(w, r, languageRule)
	case errors.Is(err, scenario.ErrDeceptionAdded):
		httpx.WriteError(w, r, http.StatusConflict, codeDeceptionAdded, "the deception is part of the scenario already")
	case errors.Is(err, scenario.ErrDNSNotConfigured):
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, codeDNSNotConfigured,
			"the deception has a DNS honeytoken, which needs the zones of the DNS role; set NYKTUS_DNS_ZONES for the console")
	default:
		httpx.ServerError(w, r, h.logger, op, err)
	}
}

func invalid(w http.ResponseWriter, r *http.Request, message string) {
	httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, message)
}

// applyRequest is the request to apply a deception. The optional members
// reject null, as everywhere.
type applyRequest struct {
	Name  string                 `json:"name"`
	Notes httpx.Optional[string] `json:"notes"`
	// Language is the language of the names of the resources that are created.
	Language httpx.Optional[string] `json:"language"`
	// CreateResources creates the honeytokens and honeypots that the deception
	// asks for, in the scenario. Left out, they are not created.
	CreateResources httpx.Optional[bool] `json:"create_resources"`
}

// applyResponse is what applying a deception created: the scenario and, if the
// resources were asked for, those. A honeypot comes without its secret, which
// is read through its own route.
type applyResponse struct {
	Scenario    response                 `json:"scenario"`
	Honeytokens []honeytokenapi.Response `json:"honeytokens"`
	Honeypots   []honeypotapi.Response   `json:"honeypots"`
}

// defaultLanguage is the language of an application that names none.
const defaultLanguage = "en"

// Apply handles POST /api/v1/catalog/deceptions/{id}/apply. It creates a
// scenario with the deception and, if asked, with the honeytokens and
// honeypots that the deception asks for.
func (h *Handler) Apply(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var req applyRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	if !h.mayCreate(w, r, p, req.CreateResources) {
		return
	}
	d, ok := h.catalog.Lookup(r.PathValue("id"))
	if !ok {
		httpx.NotFound(w, r)
		return
	}
	a := scenario.Application{Join: h.join(d, req.Language, req.CreateResources), Name: req.Name, Notes: req.Notes.Value}
	applied, err := scenario.Apply(r.Context(), h.db, p.Actor(), a)
	if err != nil {
		h.writeError(w, r, "scenario: apply deception", err)
		return
	}
	h.logger.InfoContext(r.Context(), "scenario: applied deception", slog.String("deception", d.ID),
		slog.Any("scenario", applied.Scenario), slog.Int("honeytokens", len(applied.Honeytokens)),
		slog.Int("honeypots", len(applied.Honeypots)))
	httpx.WriteJSON(w, http.StatusCreated, h.toApplyResponse(applied))
}

// mayCreate reports whether p may create the resources of a deception if the
// request asks for them. Creating them needs the permissions of both
// resources, whatever the deception asks for, so that the answer does not
// depend on the deception and no key writes honeypots with scenarios:write
// alone. A denial is answered before anything is loaded.
func (h *Handler) mayCreate(w http.ResponseWriter, r *http.Request, p access.Principal, create httpx.Optional[bool]) bool {
	if !create.Value {
		return true
	}
	return h.allowed(w, r, p, createHoneytoken) && h.allowed(w, r, p, createHoneypot)
}

// join returns how the deception d joins a scenario from the optional members
// of a request.
func (h *Handler) join(d catalog.Deception, language httpx.Optional[string], create httpx.Optional[bool]) scenario.Join {
	lang := defaultLanguage
	if language.Set {
		lang = language.Value
	}
	j := scenario.Join{Deception: d, Language: lang, CreateResources: create.Value, Keys: h.keys}
	// A DNS honeytoken has a name under every zone of the DNS role, so it needs
	// one.
	j.DNSConfigured = len(h.dnsZones) > 0
	return j
}

func (h *Handler) toApplyResponse(applied scenario.Applied) applyResponse {
	resp := applyResponse{
		Scenario:    toResponse(applied.Scenario),
		Honeytokens: make([]honeytokenapi.Response, 0, len(applied.Honeytokens)),
		Honeypots:   make([]honeypotapi.Response, 0, len(applied.Honeypots)),
	}
	for _, t := range applied.Honeytokens {
		resp.Honeytokens = append(resp.Honeytokens, honeytokenapi.NewResponse(t, h.triggerURL, h.dnsZones))
	}
	for _, hp := range applied.Honeypots {
		resp.Honeypots = append(resp.Honeypots, honeypotapi.NewResponse(hp))
	}
	return resp
}

// addDeceptionRequest is the request to add a deception to a scenario. The
// optional members reject null, as everywhere.
type addDeceptionRequest struct {
	DeceptionID     string                 `json:"deception_id"`
	Language        httpx.Optional[string] `json:"language"`
	CreateResources httpx.Optional[bool]   `json:"create_resources"`
}

// AddDeception handles POST /api/v1/scenarios/{id}/deceptions. It adds a
// deception of the catalog to the scenario and, if asked, creates the
// honeytokens and honeypots that the deception asks for.
func (h *Handler) AddDeception(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var req addDeceptionRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	if !h.mayCreate(w, r, p, req.CreateResources) {
		return
	}
	d, ok := h.catalog.Lookup(req.DeceptionID)
	if !ok {
		invalid(w, r, "deception_id must be a deception of the catalog")
		return
	}
	applied, err := scenario.AddDeception(r.Context(), h.db, p.Actor(), scenario.Addition{
		ScenarioID: r.PathValue("id"),
		Join:       h.join(d, req.Language, req.CreateResources),
	})
	if err != nil {
		h.writeError(w, r, "scenario: add deception", err)
		return
	}
	h.logger.InfoContext(r.Context(), "scenario: added deception", slog.String("deception", d.ID),
		slog.Any("scenario", applied.Scenario), slog.Int("honeytokens", len(applied.Honeytokens)),
		slog.Int("honeypots", len(applied.Honeypots)))
	httpx.WriteJSON(w, http.StatusCreated, h.toApplyResponse(applied))
}

// RemoveDeception handles DELETE /api/v1/scenarios/{id}/deceptions/{deception_id}.
// It ends the assignment only: the honeytokens and honeypots of the deception
// stay in the scenario, so that a slip costs neither them nor the scenario. The
// deception need not be in the catalog any more.
func (h *Handler) RemoveDeception(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	sc, err := scenario.RemoveDeception(r.Context(), h.db, p.Actor(), r.PathValue("id"), r.PathValue("deception_id"))
	if err != nil {
		h.writeError(w, r, "scenario: remove deception", err)
		return
	}
	h.logger.InfoContext(r.Context(), "scenario: removed deception", slog.String("deception", r.PathValue("deception_id")),
		slog.Any("scenario", sc))
	httpx.WriteJSON(w, http.StatusOK, toResponse(sc))
}
