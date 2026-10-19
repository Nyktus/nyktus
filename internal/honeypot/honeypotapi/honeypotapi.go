// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package honeypotapi serves the honeypots of the team. The routes must
// require the permissions honeypots:read and honeypots:write.
package honeypotapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/honeypot"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/severity"
)

// Error codes of the honeypots.
const (
	// codeScenarioNotFound answers the assignment to a scenario that does not
	// exist.
	codeScenarioNotFound = "scenario_not_found"
	// codeInScenario answers the assignment of a honeypot that belongs to
	// another scenario.
	codeInScenario = "honeypot_in_scenario"
)

// defaultPageSize is the page size if the request names none.
const defaultPageSize = 50

// maxBodyBytes bounds the requests: notes of 2000 characters, even with every
// character escaped in JSON, fit with room to spare.
const maxBodyBytes = 64 << 10

// Filter parameters of the list.
const (
	filterService    = "service"
	filterEnabled    = "enabled"
	filterScenarioID = "scenario_id"
)

// Handler serves the honeypots.
type Handler struct {
	logger *slog.Logger
	db     honeypot.DB
}

// NewHandler returns the handlers of the honeypots.
func NewHandler(logger *slog.Logger, d honeypot.DB) *Handler {
	if logger == nil || d == nil {
		panic("honeypotapi: handler needs a logger and a database")
	}
	return &Handler{logger: logger, db: d}
}

// Response is the representation of a honeypot. It never holds the secret.
type Response struct {
	ID            string           `json:"id"`
	Service       honeypot.Service `json:"service"`
	Name          string           `json:"name"`
	Notes         string           `json:"notes"`
	Enabled       bool             `json:"enabled"`
	Techniques    []string         `json:"techniques"`
	Severity      severity.Level   `json:"severity"`
	ScenarioID    *string          `json:"scenario_id"`
	Status        honeypot.Status  `json:"status"`
	LastSeenAt    *time.Time       `json:"last_seen_at"`
	SensorVersion *string          `json:"sensor_version"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

// NewResponse returns the representation of h.
func NewResponse(h honeypot.Honeypot) Response {
	techniques := h.Techniques
	if techniques == nil {
		techniques = []string{}
	}
	return Response{
		ID:            h.ID,
		Service:       h.Service,
		Name:          h.Name,
		Notes:         h.Notes,
		Enabled:       h.Enabled,
		Techniques:    techniques,
		Severity:      h.Severity,
		ScenarioID:    h.ScenarioID,
		Status:        h.Status,
		LastSeenAt:    h.LastSeenAt,
		SensorVersion: h.SensorVersion,
		CreatedAt:     h.CreatedAt,
		UpdatedAt:     h.UpdatedAt,
	}
}

// createdResponse is the representation of a honeypot with its new secret,
// which only the creation and the replacement of the secret return.
type createdResponse struct {
	Response
	Secret string `json:"secret"`
}

// LogValue keeps the secret out of logs.
func (r createdResponse) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", r.ID), slog.String("service", string(r.Service)))
}

// writeCreated writes c with its secret. httpx.WriteJSON sends it with
// Cache-Control: no-store, so that no cache on the way keeps the secret.
func writeCreated(w http.ResponseWriter, status int, c honeypot.Created) {
	httpx.WriteJSON(w, status, createdResponse{Response: NewResponse(c.Honeypot), Secret: string(c.Secret)})
}

type listResponse struct {
	Honeypots  []Response `json:"honeypots"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

// List handles GET /api/v1/honeypots.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q, ok := httpx.DecodeListQuery(w, r, defaultPageSize, honeypot.MaxPageSize, filterService, filterEnabled, filterScenarioID)
	if !ok {
		return
	}
	var f honeypot.Filter
	if s, ok := q.Filters[filterService]; ok {
		sv := honeypot.Service(s)
		if !sv.Valid() {
			invalid(w, r, serviceRule)
			return
		}
		f.Service = &sv
	}
	if s, ok := q.Filters[filterEnabled]; ok {
		if s != "true" && s != "false" {
			invalid(w, r, "enabled must be true or false")
			return
		}
		enabled := s == "true"
		f.Enabled = &enabled
	}
	if s, ok := q.Filters[filterScenarioID]; ok {
		if !httpx.ValidID(s) {
			invalid(w, r, "scenario_id must be a UUID in lower case")
			return
		}
		f.ScenarioID = s
	}
	var after *honeypot.Cursor
	if q.After != nil {
		after = &honeypot.Cursor{CreatedAt: q.After.Time, ID: q.After.ID}
	}
	list, next, err := honeypot.NewStore(h.db).List(r.Context(), f, q.Limit, after)
	if err != nil {
		httpx.ServerError(w, r, h.logger, "honeypot: list", err)
		return
	}
	resp := listResponse{Honeypots: make([]Response, 0, len(list))}
	for _, p := range list {
		resp.Honeypots = append(resp.Honeypots, NewResponse(p))
	}
	if next != nil {
		resp.NextCursor = httpx.EncodeCursor(httpx.Cursor{Time: next.CreatedAt, ID: next.ID})
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/honeypots/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	p, err := honeypot.NewStore(h.db).Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeError(w, r, "honeypot: get", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, NewResponse(p))
}

// createRequest is the request to create a honeypot. The optional members
// reject null, as in a change, so that null never silently means the default.
type createRequest struct {
	Service    honeypot.Service         `json:"service"`
	Name       string                   `json:"name"`
	Notes      httpx.Optional[string]   `json:"notes"`
	Enabled    httpx.Optional[bool]     `json:"enabled"`
	Techniques httpx.Optional[[]string] `json:"techniques"`
	// Severity is the severity of the honeypot; without it, the default of its
	// service.
	Severity httpx.Optional[severity.Level] `json:"severity"`
}

// Create handles POST /api/v1/honeypots.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var req createRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	spec := honeypot.Spec{
		Service:    req.Service,
		Name:       req.Name,
		Notes:      req.Notes.Value,
		Enabled:    !req.Enabled.Set || req.Enabled.Value,
		Techniques: req.Techniques.Value,
		Severity:   req.Severity.Ptr(),
	}
	c, err := honeypot.Create(r.Context(), h.db, p.Actor(), spec)
	if err != nil {
		h.writeError(w, r, "honeypot: create", err)
		return
	}
	h.logger.InfoContext(r.Context(), "honeypot: created", slog.Any("honeypot", c.Honeypot))
	writeCreated(w, http.StatusCreated, c)
}

// updateRequest lists every field that a change may contain. The service is
// not among them: the sensor is configured for it.
type updateRequest struct {
	Name       httpx.Optional[string]         `json:"name"`
	Notes      httpx.Optional[string]         `json:"notes"`
	Enabled    httpx.Optional[bool]           `json:"enabled"`
	Techniques httpx.Optional[[]string]       `json:"techniques"`
	Severity   httpx.Optional[severity.Level] `json:"severity"`
}

// Update handles PATCH /api/v1/honeypots/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var req updateRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	c := honeypot.Change{
		Name:          req.Name.Ptr(),
		Notes:         req.Notes.Ptr(),
		Enabled:       req.Enabled.Ptr(),
		Techniques:    req.Techniques.Value,
		SetTechniques: req.Techniques.Set,
		Severity:      req.Severity.Ptr(),
	}
	if c.IsEmpty() {
		invalid(w, r, "request must change name, notes, enabled, techniques or severity")
		return
	}
	hp, err := honeypot.Update(r.Context(), h.db, p.Actor(), r.PathValue("id"), c)
	if err != nil {
		h.writeError(w, r, "honeypot: update", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, NewResponse(hp))
}

// ReplaceSecret handles POST /api/v1/honeypots/{id}/secret. The old secret
// stops working at once, so a sensor that still uses it is shut out until it
// is configured with the new one.
func (h *Handler) ReplaceSecret(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	c, err := honeypot.ReplaceSecret(r.Context(), h.db, p.Actor(), r.PathValue("id"))
	if err != nil {
		h.writeError(w, r, "honeypot: replace secret", err)
		return
	}
	h.logger.InfoContext(r.Context(), "honeypot: replaced secret", slog.Any("honeypot", c.Honeypot))
	writeCreated(w, http.StatusOK, c)
}

// Delete handles DELETE /api/v1/honeypots/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	if err := honeypot.Delete(r.Context(), h.db, p.Actor(), r.PathValue("id")); err != nil {
		h.writeError(w, r, "honeypot: delete", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// scenarioRequest is the request to assign a honeypot to a scenario.
type scenarioRequest struct {
	ScenarioID string `json:"scenario_id"`
}

// AssignScenario handles PUT /api/v1/honeypots/{id}/scenario. A honeypot that
// belongs to another scenario must leave it first, so that a script cannot
// take honeypots from a scenario by mistake.
func (h *Handler) AssignScenario(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var req scenarioRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	if !httpx.ValidID(req.ScenarioID) {
		invalid(w, r, "scenario_id must be a UUID in lower case")
		return
	}
	h.setScenario(w, r, p, req.ScenarioID)
}

// DetachScenario handles DELETE /api/v1/honeypots/{id}/scenario. The honeypot
// stays and stands alone.
func (h *Handler) DetachScenario(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	h.setScenario(w, r, p, "")
}

func (h *Handler) setScenario(w http.ResponseWriter, r *http.Request, p access.Principal, scenarioID string) {
	hp, err := honeypot.SetScenario(r.Context(), h.db, p.Actor(), r.PathValue("id"), scenarioID)
	switch {
	case errors.Is(err, honeypot.ErrScenarioNotFound):
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, codeScenarioNotFound, "the scenario does not exist")
		return
	case errors.Is(err, honeypot.ErrInOtherScenario):
		httpx.WriteError(w, r, http.StatusConflict, codeInScenario,
			"the honeypot belongs to another scenario; remove it from that scenario first")
		return
	case err != nil:
		h.writeError(w, r, "honeypot: set scenario", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, NewResponse(hp))
}

// principal returns the principal that the authorizer attached to the request.
// Without one, the route was registered without authentication, which is a
// wiring mistake.
func (h *Handler) principal(w http.ResponseWriter, r *http.Request) (access.Principal, bool) {
	p, ok := access.PrincipalFrom(r.Context())
	if !ok {
		httpx.ServerError(w, r, h.logger, "honeypot: read principal", errors.New("no principal in the request context"))
	}
	return p, ok
}

// Rules of the fields, as the error responses state them.
var (
	serviceRule    = "service must be one of " + services()
	nameRule       = fmt.Sprintf("name must have 1 to %d printable characters without leading or trailing spaces", honeypot.MaxNameLength)
	notesRule      = fmt.Sprintf("notes must have at most %d characters; line breaks and tabs are the only control characters allowed", honeypot.MaxNotesLength)
	severityRule   = "severity must be one of " + levels()
	techniquesRule = fmt.Sprintf("techniques must list at most %d distinct ATT&CK technique identifiers, such as T1078 or T1003.001", honeypot.MaxTechniques)
)

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, honeypot.ErrNotFound):
		httpx.NotFound(w, r)
	case errors.Is(err, honeypot.ErrInvalidService):
		invalid(w, r, serviceRule)
	case errors.Is(err, honeypot.ErrInvalidName):
		invalid(w, r, nameRule)
	case errors.Is(err, honeypot.ErrInvalidNotes):
		invalid(w, r, notesRule)
	case errors.Is(err, honeypot.ErrInvalidTechniques):
		invalid(w, r, techniquesRule)
	case errors.Is(err, honeypot.ErrInvalidSeverity):
		invalid(w, r, severityRule)
	default:
		httpx.ServerError(w, r, h.logger, op, err)
	}
}

func invalid(w http.ResponseWriter, r *http.Request, message string) {
	httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, message)
}

// services lists the services for the rule of the field.
func services() string {
	names := make([]string, len(honeypot.Services))
	for i, s := range honeypot.Services {
		names[i] = string(s)
	}
	return strings.Join(names, ", ")
}

// levels lists the severities of a honeypot for the rule of the field.
func levels() string {
	names := make([]string, len(severity.Suggested))
	for i, l := range severity.Suggested {
		names[i] = string(l)
	}
	return strings.Join(names, ", ")
}
