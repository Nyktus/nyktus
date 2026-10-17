// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package scenarioapi serves the scenarios of the team. The routes must
// require the permissions scenarios:read and scenarios:write.
package scenarioapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/scenario"
)

// defaultPageSize is the page size if the request names none.
const defaultPageSize = 50

// maxBodyBytes bounds the requests: notes of 2000 characters, even with every
// character escaped in JSON, and the activities fit with room to spare.
const maxBodyBytes = 64 << 10

// paramHoneytokens chooses what the deletion of a scenario does with its
// honeytokens.
const paramHoneytokens = "honeytokens"

// Handler serves the scenarios.
type Handler struct {
	logger *slog.Logger
	db     scenario.DB
}

// NewHandler returns the handlers of the scenarios.
func NewHandler(logger *slog.Logger, d scenario.DB) *Handler {
	if logger == nil || d == nil {
		panic("scenarioapi: handler needs a logger and a database")
	}
	return &Handler{logger: logger, db: d}
}

// response is the representation of a scenario. Its resources are listed
// through their own lists, filtered by the scenario.
type response struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Notes            string    `json:"notes"`
	EngageActivities []string  `json:"engage_activities"`
	DeceptionID      *string   `json:"deception_id"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
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

// Delete handles DELETE /api/v1/scenarios/{id}. The parameter honeytokens
// chooses whether its honeytokens are deleted with it or stay alone, which is
// the default, because a deleted honeytoken that is still placed records
// nothing.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	query, ok := httpx.DecodeQuery(w, r, paramHoneytokens)
	if !ok {
		return
	}
	honeytokens := scenario.RemovalKeep
	if v, ok := query[paramHoneytokens]; ok {
		honeytokens = scenario.Removal(v)
	}
	removed, err := scenario.Delete(r.Context(), h.db, p.Actor(), r.PathValue("id"), honeytokens)
	if err != nil {
		h.writeError(w, r, "scenario: delete", err)
		return
	}
	h.logger.InfoContext(r.Context(), "scenario: deleted", slog.String("scenario_id", r.PathValue("id")),
		slog.Int("honeytokens_deleted", len(removed.DeletedHoneytokens)),
		slog.Int("honeytokens_detached", len(removed.DetachedHoneytokens)))
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
	removalRule    = "honeytokens must be keep or delete"
)

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, op string, err error) {
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
	default:
		httpx.ServerError(w, r, h.logger, op, err)
	}
}

func invalid(w http.ResponseWriter, r *http.Request, message string) {
	httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, message)
}
