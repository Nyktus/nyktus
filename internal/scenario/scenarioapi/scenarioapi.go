// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package scenarioapi serves the scenarios of the team, applies the deceptions
// of the catalog, which creates scenarios, and adds deceptions and artifacts of
// the catalog to scenarios that exist. The routes must require the permissions
// scenarios:read and scenarios:write.
package scenarioapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"nyktus.org/nyktus/internal/artifact"
	"nyktus.org/nyktus/internal/artifact/artifactapi"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/honeytoken/honeytokenapi"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/scenario"
)

// Error codes of applying a deception.
const (
	// codeDNSNotConfigured answers a deception with a DNS honeytoken while
	// the console knows no zone of the DNS role, as for honeytokens.
	codeDNSNotConfigured = "dns_not_configured"
	// codeArtifactReveals answers an application whose values make an
	// artifact name the product or what it is.
	codeArtifactReveals = "artifact_reveals_decoy"
	// codePersonaConflict answers a value of the persona that differs from
	// the one the scenario has. The persona only grows.
	codePersonaConflict = "persona_conflict"
	// codeDeceptionAdded answers a deception that is part of the scenario
	// already.
	codeDeceptionAdded = "deception_already_added"
	// codeScenarioLimit answers an addition to a scenario that holds the most
	// deceptions or artifacts it may.
	codeScenarioLimit = "scenario_limit"
)

// defaultPageSize is the page size if the request names none.
const defaultPageSize = 50

// maxBodyBytes bounds the requests: notes of 2000 characters, even with every
// character escaped in JSON, and the activities fit with room to spare.
const maxBodyBytes = 64 << 10

// paramHoneytokens, paramHoneypots and paramArtifacts choose what the deletion
// of a scenario does with its honeytokens, honeypots and artifacts.
const (
	paramHoneytokens = "honeytokens"
	paramHoneypots   = "honeypots"
	paramArtifacts   = "artifacts"
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
}

// NewHandler returns the handlers of the scenarios. Deceptions of c are
// applied with honeytokens whose URLs start with triggerURL, the public
// address of the trigger, and whose names, of DNS honeytokens, are under the
// first of dnsZones, the zones of the DNS role in lower case without a
// trailing dot, or none.
func NewHandler(logger *slog.Logger, d scenario.DB, c *catalog.Catalog, triggerURL string, dnsZones []string) *Handler {
	if logger == nil || d == nil || c == nil {
		panic("scenarioapi: handler needs a logger, a database and a catalog")
	}
	return &Handler{logger: logger, db: d, catalog: c, triggerURL: triggerURL, dnsZones: dnsZones}
}

// response is the representation of a scenario. Its resources are listed
// through their own lists, filtered by the scenario.
type response struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Notes            string            `json:"notes"`
	EngageActivities []string          `json:"engage_activities"`
	Deceptions       []deceptionRef    `json:"deceptions"`
	Persona          map[string]string `json:"persona"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

// deceptionRef is a deception that joined a scenario.
type deceptionRef struct {
	DeceptionID string    `json:"deception_id"`
	Language    string    `json:"language"`
	CreatedAt   time.Time `json:"created_at"`
}

func toResponse(s scenario.Scenario) response {
	activities := s.EngageActivities
	if activities == nil {
		activities = []string{}
	}
	deceptions := make([]deceptionRef, 0, len(s.Deceptions))
	for _, d := range s.Deceptions {
		deceptions = append(deceptions, deceptionRef{DeceptionID: d.DeceptionID, Language: d.Language, CreatedAt: d.CreatedAt})
	}
	persona := s.Persona
	if persona == nil {
		persona = map[string]string{}
	}
	return response{
		ID:               s.ID,
		Name:             s.Name,
		Notes:            s.Notes,
		EngageActivities: activities,
		Deceptions:       deceptions,
		Persona:          persona,
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
// Neither the deceptions nor the persona are among them: only a deception or an
// artifact of the catalog adds to them.
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

// updateRequest lists every field that a change may contain. The deceptions and
// the persona are not among them, and neither are the resources of the
// scenario, which join and leave it through operations of their own.
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

// Delete handles DELETE /api/v1/scenarios/{id}. The parameters honeytokens,
// honeypots and artifacts choose whether its honeytokens, honeypots and
// artifacts are deleted with it or stay alone, which is the default: a
// deleted honeytoken that is still placed or a deleted honeypot whose sensor
// still runs records nothing, and a kept artifact helps to find what was
// placed. Deleting the honeypots also requires honeypots:write: unlike
// honeytokens and artifacts, applying a deception never creates them, so
// only that permission puts them into a scenario.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	query, ok := httpx.DecodeQuery(w, r, paramHoneytokens, paramHoneypots, paramArtifacts)
	if !ok {
		return
	}
	removals := scenario.ResourceRemovals{
		Honeytokens: scenario.RemovalKeep, Honeypots: scenario.RemovalKeep, Artifacts: scenario.RemovalKeep,
	}
	if v, ok := query[paramHoneytokens]; ok {
		removals.Honeytokens = scenario.Removal(v)
	}
	if v, ok := query[paramHoneypots]; ok {
		removals.Honeypots = scenario.Removal(v)
	}
	if removals.Honeypots == scenario.RemovalDelete && !h.allowed(w, r, p, deleteHoneypots) {
		return
	}
	if v, ok := query[paramArtifacts]; ok {
		removals.Artifacts = scenario.Removal(v)
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
		slog.Int("honeypots_detached", len(removed.DetachedHoneypots)),
		slog.Int("artifacts_deleted", len(removed.DeletedArtifacts)),
		slog.Int("artifacts_detached", len(removed.DetachedArtifacts)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// deleteHoneypots is the permission to delete the honeypots of a scenario with
// it.
const deleteHoneypots httpx.Permission = "honeypots:write"

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
	removalRule    = "honeytokens, honeypots and artifacts must be keep or delete"
	languageRule   = "language must be one of " + strings.Join(catalog.Languages, ", ")
	selectionRule  = "artifacts must name artifacts that the deception recommends, each once"
)

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, op string, err error) {
	var (
		personaErr  *catalog.PersonaError
		conflictErr *catalog.PersonaConflictError
		bindingErr  *scenario.BindingError
		revealErr   *catalog.RevealError
	)
	switch {
	case errors.Is(err, scenario.ErrNotFound):
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
	case errors.As(err, &personaErr):
		invalid(w, r, personaErr.Error())
	case errors.As(err, &conflictErr):
		httpx.WriteError(w, r, http.StatusConflict, codePersonaConflict, conflictErr.Error()+
			"; the persona of a scenario only grows, so use the value it has or leave it out")
	case errors.Is(err, scenario.ErrDeceptionAdded):
		httpx.WriteError(w, r, http.StatusConflict, codeDeceptionAdded,
			"the deception is part of the scenario already; apply it to another scenario for other values of the persona")
	case errors.Is(err, scenario.ErrTooManyDeceptions), errors.Is(err, artifact.ErrLimit):
		httpx.WriteError(w, r, http.StatusConflict, codeScenarioLimit, fmt.Sprintf(
			"a scenario holds at most %d deceptions and %d artifacts", scenario.MaxDeceptions, artifact.MaxPerScenario))
	case errors.Is(err, scenario.ErrInvalidSelection):
		invalid(w, r, selectionRule)
	case errors.As(err, &bindingErr):
		invalid(w, r, bindingErr.Error())
	case errors.Is(err, scenario.ErrDNSNotConfigured):
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, codeDNSNotConfigured,
			"the deception has a DNS honeytoken, which needs the zones of the DNS role; set NYKTUS_DNS_ZONES for the console")
	case errors.As(err, &revealErr):
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, codeArtifactReveals,
			fmt.Sprintf("the artifact %s would contain %q, which reveals what it is; check the persona and the zones of the DNS role",
				revealErr.Artifact, revealErr.Marker))
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
	Name     string                            `json:"name"`
	Notes    httpx.Optional[string]            `json:"notes"`
	Language httpx.Optional[string]            `json:"language"`
	Persona  httpx.Optional[map[string]string] `json:"persona"`
	// Artifacts name the artifacts of the deception to create; left out, they
	// are those that the deception recommends.
	Artifacts httpx.Optional[[]string] `json:"artifacts"`
}

// applyResponse is what applying a deception created.
type applyResponse struct {
	Scenario    response                 `json:"scenario"`
	Honeytokens []honeytokenapi.Response `json:"honeytokens"`
	Artifacts   []artifactapi.Response   `json:"artifacts"`
}

// defaultLanguage is the language of an application that names none.
const defaultLanguage = "en"

// Apply handles POST /api/v1/catalog/deceptions/{id}/apply. It creates a
// scenario with the honeytokens, the artifacts and the guide of the
// deception.
func (h *Handler) Apply(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	d, ok := h.catalog.Lookup(r.PathValue("id"))
	if !ok {
		httpx.NotFound(w, r)
		return
	}
	var req applyRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	a := scenario.Application{
		Join: h.join(d, req.Language, req.Persona, req.Artifacts),
		Name: req.Name, Notes: req.Notes.Value,
	}
	applied, err := scenario.Apply(r.Context(), h.db, p.Actor(), a)
	if err != nil {
		h.writeError(w, r, "scenario: apply deception", err)
		return
	}
	h.logger.InfoContext(r.Context(), "scenario: applied deception", slog.String("deception", d.ID),
		slog.Any("scenario", applied.Scenario), slog.Int("honeytokens", len(applied.Honeytokens)),
		slog.Int("artifacts", len(applied.Artifacts)))
	httpx.WriteJSON(w, http.StatusCreated, h.toApplyResponse(applied))
}

// join returns how the deception d joins a scenario from the optional members
// of a request.
func (h *Handler) join(d catalog.Deception, language httpx.Optional[string], persona httpx.Optional[map[string]string],
	artifacts httpx.Optional[[]string],
) scenario.Join {
	lang := defaultLanguage
	if language.Set {
		lang = language.Value
	}
	j := scenario.Join{
		Deception: d, Language: lang, Persona: persona.Value, TriggerURL: h.triggerURL,
	}
	if artifacts.Set {
		j.Artifacts = artifacts.Value
		if j.Artifacts == nil {
			j.Artifacts = []string{}
		}
	}
	// DNS honeytokens are placed under the first zone; they have a name
	// under every other zone as well.
	if len(h.dnsZones) > 0 {
		j.DNSZone = h.dnsZones[0]
	}
	return j
}

func (h *Handler) toApplyResponse(applied scenario.Applied) applyResponse {
	resp := applyResponse{
		Scenario:    toResponse(applied.Scenario),
		Honeytokens: make([]honeytokenapi.Response, 0, len(applied.Honeytokens)),
		Artifacts:   make([]artifactapi.Response, 0, len(applied.Artifacts)),
	}
	for _, t := range applied.Honeytokens {
		resp.Honeytokens = append(resp.Honeytokens, honeytokenapi.NewResponse(t, h.triggerURL, h.dnsZones))
	}
	for _, art := range applied.Artifacts {
		resp.Artifacts = append(resp.Artifacts, artifactapi.NewResponse(art))
	}
	return resp
}

// addDeceptionRequest is the request to add a deception to a scenario. The
// optional members reject null, as everywhere.
type addDeceptionRequest struct {
	DeceptionID string                            `json:"deception_id"`
	Language    httpx.Optional[string]            `json:"language"`
	Persona     httpx.Optional[map[string]string] `json:"persona"`
	Artifacts   httpx.Optional[[]string]          `json:"artifacts"`
}

// AddDeception handles POST /api/v1/scenarios/{id}/deceptions. It adds a
// deception of the catalog to the scenario, with its honeytokens, artifacts
// and guide. The persona of the scenario keeps its values and grows by the
// keys that the deception asks for and the scenario lacks.
func (h *Handler) AddDeception(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var req addDeceptionRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	d, ok := h.catalog.Lookup(req.DeceptionID)
	if !ok {
		invalid(w, r, "deception_id must be a deception of the catalog")
		return
	}
	applied, err := scenario.AddDeception(r.Context(), h.db, p.Actor(), scenario.Addition{
		ScenarioID: r.PathValue("id"),
		Join:       h.join(d, req.Language, req.Persona, req.Artifacts),
	})
	if err != nil {
		h.writeError(w, r, "scenario: add deception", err)
		return
	}
	h.logger.InfoContext(r.Context(), "scenario: added deception", slog.String("deception", d.ID),
		slog.Any("scenario", applied.Scenario), slog.Int("honeytokens", len(applied.Honeytokens)),
		slog.Int("artifacts", len(applied.Artifacts)))
	httpx.WriteJSON(w, http.StatusCreated, h.toApplyResponse(applied))
}

// addArtifactRequest is the request to add an artifact of the catalog to a
// scenario.
type addArtifactRequest struct {
	CatalogArtifact string                            `json:"catalog_artifact"`
	Language        httpx.Optional[string]            `json:"language"`
	Persona         httpx.Optional[map[string]string] `json:"persona"`
	// Bindings name the honeytoken of the scenario for each slot, by the key
	// of the slot.
	Bindings httpx.Optional[map[string]string] `json:"bindings"`
}

// addArtifactResponse is the artifact that was added and the scenario after
// it.
type addArtifactResponse struct {
	Scenario response             `json:"scenario"`
	Artifact artifactapi.Response `json:"artifact"`
}

// AddArtifact handles POST /api/v1/scenarios/{id}/artifacts. It adds an
// artifact of the catalog to the scenario, rendered with the persona of the
// scenario and the honeytokens that fill its slots.
func (h *Handler) AddArtifact(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var req addArtifactRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	a, ok := h.catalog.LookupArtifact(req.CatalogArtifact)
	if !ok {
		invalid(w, r, "catalog_artifact must be an artifact of the catalog")
		return
	}
	lang := defaultLanguage
	if req.Language.Set {
		lang = req.Language.Value
	}
	add := scenario.ArtifactAddition{
		ScenarioID: r.PathValue("id"), Artifact: a, Language: lang, Persona: req.Persona.Value,
		Bindings: req.Bindings.Value, TriggerURL: h.triggerURL,
	}
	if len(h.dnsZones) > 0 {
		add.DNSZone = h.dnsZones[0]
	}
	applied, err := scenario.AddArtifact(r.Context(), h.db, p.Actor(), add)
	if err != nil {
		h.writeError(w, r, "scenario: add artifact", err)
		return
	}
	h.logger.InfoContext(r.Context(), "scenario: added artifact", slog.String("artifact", a.ID),
		slog.Any("scenario", applied.Scenario))
	httpx.WriteJSON(w, http.StatusCreated, addArtifactResponse{
		Scenario: toResponse(applied.Scenario), Artifact: artifactapi.NewResponse(applied.Artifacts[0]),
	})
}

// guideResponse is the guide of a deception of a scenario.
type guideResponse struct {
	DeceptionID string `json:"deception_id"`
	Language    string `json:"language"`
	Content     string `json:"content"`
}

// guidesResponse lists the guides of a scenario, in the order its deceptions
// joined.
type guidesResponse struct {
	Guides []guideResponse `json:"guides"`
}

// Guide handles GET /api/v1/scenarios/{id}/guide. A scenario put together by
// hand has no deception and so no guide.
func (h *Handler) Guide(w http.ResponseWriter, r *http.Request) {
	guides, err := scenario.NewStore(h.db).Guides(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeError(w, r, "scenario: get guide", err)
		return
	}
	resp := guidesResponse{Guides: make([]guideResponse, 0, len(guides))}
	for _, g := range guides {
		resp.Guides = append(resp.Guides, guideResponse{DeceptionID: g.DeceptionID, Language: g.Language, Content: g.Content})
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}
