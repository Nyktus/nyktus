// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package scenarioapi serves the scenarios of the team, and applies the
// deceptions of the catalog, which creates scenarios. The routes must require
// the permissions scenarios:read and scenarios:write.
package scenarioapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"nyktus.org/nyktus/internal/artifact/artifactapi"
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
)

// defaultPageSize is the page size if the request names none.
const defaultPageSize = 50

// maxBodyBytes bounds the requests: notes of 2000 characters, even with every
// character escaped in JSON, and the activities fit with room to spare.
const maxBodyBytes = 64 << 10

// paramHoneytokens and paramArtifacts choose what the deletion of a scenario
// does with its honeytokens and artifacts.
const (
	paramHoneytokens = "honeytokens"
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
	DeceptionID      *string           `json:"deception_id"`
	Language         *string           `json:"language"`
	Persona          map[string]string `json:"persona"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

func toResponse(s scenario.Scenario) response {
	activities := s.EngageActivities
	if activities == nil {
		activities = []string{}
	}
	return response{
		ID:               s.ID,
		Name:             s.Name,
		Notes:            s.Notes,
		EngageActivities: activities,
		DeceptionID:      s.DeceptionID,
		Language:         s.Language,
		Persona:          s.Persona,
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
// The deception is not among them: only applying a deception sets it.
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

// updateRequest lists every field that a change may contain. The deception is
// not among them, and neither are the resources of the scenario, which join
// and leave it through operations of their own.
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

// Delete handles DELETE /api/v1/scenarios/{id}. The parameters honeytokens
// and artifacts choose whether its honeytokens and artifacts are deleted with
// it or stay alone, which is the default: a deleted honeytoken that is still
// placed records nothing, and a kept artifact helps to find what was placed.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	query, ok := httpx.DecodeQuery(w, r, paramHoneytokens, paramArtifacts)
	if !ok {
		return
	}
	removals := scenario.ResourceRemovals{Honeytokens: scenario.RemovalKeep, Artifacts: scenario.RemovalKeep}
	if v, ok := query[paramHoneytokens]; ok {
		removals.Honeytokens = scenario.Removal(v)
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
		slog.Int("artifacts_deleted", len(removed.DeletedArtifacts)),
		slog.Int("artifacts_detached", len(removed.DetachedArtifacts)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
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
	removalRule    = "honeytokens and artifacts must be keep or delete"
	languageRule   = "language must be one of " + strings.Join(catalog.Languages, ", ")
)

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, op string, err error) {
	var (
		personaErr *catalog.PersonaError
		revealErr  *catalog.RevealError
	)
	switch {
	case errors.Is(err, scenario.ErrNotFound), errors.Is(err, scenario.ErrNoGuide):
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
	lang := defaultLanguage
	if req.Language.Set {
		lang = req.Language.Value
	}
	a := scenario.Application{
		Deception: d, Name: req.Name, Notes: req.Notes.Value, Language: lang, Persona: req.Persona.Value,
		TriggerURL: h.triggerURL,
	}
	// DNS honeytokens are placed under the first zone; they have a name
	// under every other zone as well.
	if len(h.dnsZones) > 0 {
		a.DNSZone = h.dnsZones[0]
	}
	applied, err := scenario.Apply(r.Context(), h.db, p.Actor(), a)
	if err != nil {
		h.writeError(w, r, "scenario: apply deception", err)
		return
	}
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
	h.logger.InfoContext(r.Context(), "scenario: applied deception", slog.String("deception", d.ID),
		slog.Any("scenario", applied.Scenario), slog.Int("honeytokens", len(applied.Honeytokens)),
		slog.Int("artifacts", len(applied.Artifacts)))
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

// guideResponse is the guide of a scenario.
type guideResponse struct {
	Language string `json:"language"`
	Content  string `json:"content"`
}

// Guide handles GET /api/v1/scenarios/{id}/guide. A scenario put together by
// hand has no guide and answers 404 like an unknown one.
func (h *Handler) Guide(w http.ResponseWriter, r *http.Request) {
	lang, guide, err := scenario.NewStore(h.db).Guide(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeError(w, r, "scenario: get guide", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, guideResponse{Language: lang, Content: guide})
}
