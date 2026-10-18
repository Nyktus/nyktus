// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package honeytokenapi serves the honeytokens of the team. The routes must
// require the permissions honeytokens:read and honeytokens:write.
package honeytokenapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/severity"
)

// Error codes of the honeytokens.
const (
	// codeDNSNotConfigured answers the creation of a DNS honeytoken while the
	// console knows no zone of the DNS role.
	codeDNSNotConfigured = "dns_not_configured"
	// codeScenarioNotFound answers the assignment to a scenario that does not
	// exist.
	codeScenarioNotFound = "scenario_not_found"
	// codeInScenario answers the assignment of a honeytoken that belongs to
	// another scenario.
	codeInScenario = "honeytoken_in_scenario"
)

// defaultPageSize is the page size if the request names none.
const defaultPageSize = 50

// maxBodyBytes bounds the requests: notes of 2000 characters and a URL of 2048,
// even with every character escaped in JSON, fit with room to spare.
const maxBodyBytes = 64 << 10

// Filter parameters of the list.
const (
	filterType       = "type"
	filterEnabled    = "enabled"
	filterScenarioID = "scenario_id"
)

// Handler serves the honeytokens.
type Handler struct {
	logger *slog.Logger
	db     honeytoken.DB
	// triggerURL is the public address of the trigger, such as
	// "https://t.example.com", to which the trigger value of a honeytoken is
	// appended.
	triggerURL string
	// dnsZones are the zones of the DNS role, under which the trigger value of
	// a DNS honeytoken is a name. Without them, DNS honeytokens cannot be
	// created.
	dnsZones []string
}

// NewHandler returns the handlers of the honeytokens. triggerURL is the public
// address of the trigger, with scheme, host and port only; dnsZones are the
// zones of the DNS role, in lower case without a trailing dot, or none.
func NewHandler(logger *slog.Logger, d honeytoken.DB, triggerURL string, dnsZones []string) *Handler {
	if logger == nil || d == nil || triggerURL == "" {
		panic("honeytokenapi: handler needs a logger, a database and the address of the trigger")
	}
	return &Handler{logger: logger, db: d, triggerURL: triggerURL, dnsZones: dnsZones}
}

// response is the representation of a honeytoken. The trigger value is not a
// secret towards the readers of the inventory: it is part of the URL or name
// that they place, and they need it again for every placement.
type response struct {
	ID           string          `json:"id"`
	Type         honeytoken.Type `json:"type"`
	Name         string          `json:"name"`
	Notes        string          `json:"notes"`
	Enabled      bool            `json:"enabled"`
	RedirectURL  *string         `json:"redirect_url"`
	Techniques   []string        `json:"techniques"`
	Severity     severity.Level  `json:"severity"`
	TriggerValue string          `json:"trigger_value"`
	TriggerURL   *string         `json:"trigger_url"`
	TriggerNames []string        `json:"trigger_names"`
	ScenarioID   *string         `json:"scenario_id"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

func (h *Handler) response(t honeytoken.Honeytoken) response {
	techniques := t.Techniques
	if techniques == nil {
		techniques = []string{}
	}
	var triggerURL *string
	if path := t.TriggerPath(); path != "" {
		triggerURL = new(h.triggerURL + path)
	}
	return response{
		ID:           t.ID,
		Type:         t.Type,
		Name:         t.Name,
		Notes:        t.Notes,
		Enabled:      t.Enabled,
		RedirectURL:  t.RedirectURL,
		Techniques:   techniques,
		Severity:     t.Severity,
		TriggerValue: t.TriggerValue,
		TriggerURL:   triggerURL,
		TriggerNames: t.TriggerNames(h.dnsZones),
		ScenarioID:   t.ScenarioID,
		CreatedAt:    t.CreatedAt,
		UpdatedAt:    t.UpdatedAt,
	}
}

type listResponse struct {
	Honeytokens []response `json:"honeytokens"`
	NextCursor  string     `json:"next_cursor,omitempty"`
}

// List handles GET /api/v1/honeytokens.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q, ok := httpx.DecodeListQuery(w, r, defaultPageSize, honeytoken.MaxPageSize, filterType, filterEnabled, filterScenarioID)
	if !ok {
		return
	}
	var f honeytoken.Filter
	if s, ok := q.Filters[filterType]; ok {
		t := honeytoken.Type(s)
		if !t.Valid() {
			invalid(w, r, typeRule)
			return
		}
		f.Type = &t
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
	var after *honeytoken.Cursor
	if q.After != nil {
		after = &honeytoken.Cursor{CreatedAt: q.After.Time, ID: q.After.ID}
	}
	list, next, err := honeytoken.NewStore(h.db).List(r.Context(), f, q.Limit, after)
	if err != nil {
		httpx.ServerError(w, r, h.logger, "honeytoken: list", err)
		return
	}
	resp := listResponse{Honeytokens: make([]response, 0, len(list))}
	for _, t := range list {
		resp.Honeytokens = append(resp.Honeytokens, h.response(t))
	}
	if next != nil {
		resp.NextCursor = httpx.EncodeCursor(httpx.Cursor{Time: next.CreatedAt, ID: next.ID})
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/honeytokens/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	t, err := honeytoken.NewStore(h.db).Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeError(w, r, "honeytoken: get", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.response(t))
}

// createRequest is the request to create a honeytoken. The optional members
// reject null, as in a change, so that null never silently means the default.
type createRequest struct {
	Type        honeytoken.Type          `json:"type"`
	Name        string                   `json:"name"`
	Notes       httpx.Optional[string]   `json:"notes"`
	Enabled     httpx.Optional[bool]     `json:"enabled"`
	RedirectURL httpx.Optional[string]   `json:"redirect_url"`
	Techniques  httpx.Optional[[]string] `json:"techniques"`
	// Severity is the severity of the honeytoken; without it, the default of
	// its type.
	Severity httpx.Optional[severity.Level] `json:"severity"`
}

// Create handles POST /api/v1/honeytokens.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var req createRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	if req.Type == honeytoken.TypeDNS && len(h.dnsZones) == 0 {
		// A DNS honeytoken without a zone would have no name to place.
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, codeDNSNotConfigured,
			"DNS honeytokens need the zones of the DNS role; set NYKTUS_DNS_ZONES for the console")
		return
	}
	spec := honeytoken.Spec{
		Type:        req.Type,
		Name:        req.Name,
		Notes:       req.Notes.Value,
		Enabled:     !req.Enabled.Set || req.Enabled.Value,
		RedirectURL: req.RedirectURL.Ptr(),
		Techniques:  req.Techniques.Value,
		Severity:    req.Severity.Ptr(),
	}
	t, err := honeytoken.Create(r.Context(), h.db, p.Actor(), spec)
	if err != nil {
		h.writeError(w, r, "honeytoken: create", err)
		return
	}
	h.logger.InfoContext(r.Context(), "honeytoken: created", slog.Any("honeytoken", t))
	httpx.WriteJSON(w, http.StatusCreated, h.response(t))
}

// updateRequest lists every field that a change may contain. The type and the
// trigger value are not among them: both are placed and cannot change.
type updateRequest struct {
	Name        httpx.Optional[string]         `json:"name"`
	Notes       httpx.Optional[string]         `json:"notes"`
	Enabled     httpx.Optional[bool]           `json:"enabled"`
	RedirectURL httpx.Nullable[string]         `json:"redirect_url"`
	Techniques  httpx.Optional[[]string]       `json:"techniques"`
	Severity    httpx.Optional[severity.Level] `json:"severity"`
}

// Update handles PATCH /api/v1/honeytokens/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var req updateRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	c := honeytoken.Change{
		Name:          req.Name.Ptr(),
		Notes:         req.Notes.Ptr(),
		Enabled:       req.Enabled.Ptr(),
		Techniques:    req.Techniques.Value,
		SetTechniques: req.Techniques.Set,
		Severity:      req.Severity.Ptr(),
	}
	switch {
	case req.RedirectURL.Null:
		// The change removes the redirect with an empty string.
		c.RedirectURL = new(string)
	case req.RedirectURL.Set && req.RedirectURL.Value == "":
		invalid(w, r, redirectURLRule+"; null removes it")
		return
	case req.RedirectURL.Set:
		c.RedirectURL = &req.RedirectURL.Value
	}
	if c.IsEmpty() {
		invalid(w, r, "request must change name, notes, enabled, redirect_url, techniques or severity")
		return
	}
	t, err := honeytoken.Update(r.Context(), h.db, p.Actor(), r.PathValue("id"), c)
	if err != nil {
		h.writeError(w, r, "honeytoken: update", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.response(t))
}

// Delete handles DELETE /api/v1/honeytokens/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	if err := honeytoken.Delete(r.Context(), h.db, p.Actor(), r.PathValue("id")); err != nil {
		h.writeError(w, r, "honeytoken: delete", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// scenarioRequest is the request to assign a honeytoken to a scenario.
type scenarioRequest struct {
	ScenarioID string `json:"scenario_id"`
}

// AssignScenario handles PUT /api/v1/honeytokens/{id}/scenario. A honeytoken
// that belongs to another scenario must leave it first, so that a script
// cannot take honeytokens from a scenario by mistake.
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

// DetachScenario handles DELETE /api/v1/honeytokens/{id}/scenario. The
// honeytoken stays and stands alone.
func (h *Handler) DetachScenario(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	h.setScenario(w, r, p, "")
}

func (h *Handler) setScenario(w http.ResponseWriter, r *http.Request, p access.Principal, scenarioID string) {
	t, err := honeytoken.SetScenario(r.Context(), h.db, p.Actor(), r.PathValue("id"), scenarioID)
	switch {
	case errors.Is(err, honeytoken.ErrScenarioNotFound):
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, codeScenarioNotFound, "the scenario does not exist")
		return
	case errors.Is(err, honeytoken.ErrInOtherScenario):
		httpx.WriteError(w, r, http.StatusConflict, codeInScenario,
			"the honeytoken belongs to another scenario; remove it from that scenario first")
		return
	case err != nil:
		h.writeError(w, r, "honeytoken: set scenario", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.response(t))
}

// principal returns the principal that the authorizer attached to the request.
// Without one, the route was registered without authentication, which is a
// wiring mistake.
func (h *Handler) principal(w http.ResponseWriter, r *http.Request) (access.Principal, bool) {
	p, ok := access.PrincipalFrom(r.Context())
	if !ok {
		httpx.ServerError(w, r, h.logger, "honeytoken: read principal", errors.New("no principal in the request context"))
	}
	return p, ok
}

// Rules of the fields, as the error responses state them.
var (
	typeRule        = "type must be web_url, web_image or dns"
	nameRule        = fmt.Sprintf("name must have 1 to %d printable characters without leading or trailing spaces", honeytoken.MaxNameLength)
	notesRule       = fmt.Sprintf("notes must have at most %d characters; line breaks and tabs are the only control characters allowed", honeytoken.MaxNotesLength)
	redirectURLRule = fmt.Sprintf("redirect_url must be an http or https URL of at most %d characters with a host name, not an IP address, and without user information", honeytoken.MaxRedirectURLLength)
	severityRule    = "severity must be one of " + levels()
	techniquesRule  = fmt.Sprintf("techniques must list at most %d distinct ATT&CK technique identifiers, such as T1078 or T1003.001", honeytoken.MaxTechniques)
)

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, honeytoken.ErrNotFound):
		httpx.NotFound(w, r)
	case errors.Is(err, honeytoken.ErrInvalidType):
		invalid(w, r, typeRule)
	case errors.Is(err, honeytoken.ErrInvalidName):
		invalid(w, r, nameRule)
	case errors.Is(err, honeytoken.ErrInvalidNotes):
		invalid(w, r, notesRule)
	case errors.Is(err, honeytoken.ErrInvalidRedirectURL):
		invalid(w, r, redirectURLRule)
	case errors.Is(err, honeytoken.ErrRedirectNotAllowed):
		invalid(w, r, "redirect_url is only allowed for a honeytoken of the type web_url")
	case errors.Is(err, honeytoken.ErrInvalidTechniques):
		invalid(w, r, techniquesRule)
	case errors.Is(err, honeytoken.ErrInvalidSeverity):
		invalid(w, r, severityRule)
	default:
		httpx.ServerError(w, r, h.logger, op, err)
	}
}

func invalid(w http.ResponseWriter, r *http.Request, message string) {
	httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, message)
}

// levels lists the severities of a honeytoken for the rule of the field.
func levels() string {
	names := make([]string, len(severity.Suggested))
	for i, l := range severity.Suggested {
		names[i] = string(l)
	}
	return strings.Join(names, ", ")
}
