// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package incidentapi serves the incidents and the events of the team. The
// routes of incidents must require the permissions incidents:read and
// incidents:write, those of events the permission events:read.
//
// Events contain personal data, such as the addresses of clients, so every
// read of events is recorded in the audit log, at most once per user or key
// and audit.RepeatWindow. The entry is written before the response; without
// it, the reader receives no data. Incidents contain none.
package incidentapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/incident"
	"nyktus.org/nyktus/internal/platform/httpx"
)

// codeInvalidState answers a change that would move the status of an incident
// back, as for accounts that cannot take a status.
const codeInvalidState = "invalid_state"

// defaultPageSize is the page size if the request names none.
const defaultPageSize = 50

// maxBodyBytes bounds the requests: notes of 10000 characters, even with every
// character escaped in JSON, fit with room to spare.
const maxBodyBytes = 128 << 10

// Filter parameters of the lists.
const (
	filterStatus     = "status"
	filterResourceID = "resource_id"
	filterIncidentID = "incident_id"
)

// Handler serves incidents and events.
type Handler struct {
	logger *slog.Logger
	db     incident.DB
}

// NewHandler returns the handlers of incidents and events.
func NewHandler(logger *slog.Logger, d incident.DB) *Handler {
	if logger == nil || d == nil {
		panic("incidentapi: handler needs a logger and a database")
	}
	return &Handler{logger: logger, db: d}
}

type incidentResponse struct {
	ID                 string             `json:"id"`
	ResourceType       string             `json:"resource_type"`
	ResourceID         string             `json:"resource_id"`
	Status             incident.Status    `json:"status"`
	Severity           incident.Severity  `json:"severity"`
	EventSeverity      incident.Severity  `json:"event_severity"`
	SeverityOverride   *incident.Severity `json:"severity_override"`
	Techniques         []string           `json:"techniques"`
	EventTechniques    []string           `json:"event_techniques"`
	TechniquesOverride []string           `json:"techniques_override"`
	Notes              string             `json:"notes"`
	EventCount         int                `json:"event_count"`
	FirstEventAt       time.Time          `json:"first_event_at"`
	LastEventAt        time.Time          `json:"last_event_at"`
	OpenedAt           time.Time          `json:"opened_at"`
	AcknowledgedAt     *time.Time         `json:"acknowledged_at"`
	ClosedAt           *time.Time         `json:"closed_at"`
}

func newIncidentResponse(i incident.Incident) incidentResponse {
	// The specification requires arrays, also when they are empty; only the
	// override is null when there is none.
	nonNil := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	return incidentResponse{
		ID:                 i.ID,
		ResourceType:       i.ResourceType,
		ResourceID:         i.ResourceID,
		Status:             i.Status,
		Severity:           i.Severity(),
		EventSeverity:      i.EventSeverity,
		SeverityOverride:   i.SeverityOverride,
		Techniques:         nonNil(i.Techniques()),
		EventTechniques:    nonNil(i.EventTechniques),
		TechniquesOverride: i.TechniquesOverride,
		Notes:              i.Notes,
		EventCount:         i.EventCount,
		FirstEventAt:       i.FirstEventAt.UTC(),
		LastEventAt:        i.LastEventAt.UTC(),
		OpenedAt:           i.OpenedAt.UTC(),
		AcknowledgedAt:     utc(i.AcknowledgedAt),
		ClosedAt:           utc(i.ClosedAt),
	}
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

type incidentListResponse struct {
	Incidents  []incidentResponse `json:"incidents"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

// ListIncidents handles GET /api/v1/incidents.
func (h *Handler) ListIncidents(w http.ResponseWriter, r *http.Request) {
	q, ok := httpx.DecodeListQuery(w, r, defaultPageSize, incident.MaxPageSize, filterStatus, filterResourceID)
	if !ok {
		return
	}
	var f incident.Filter
	if s, ok := q.Filters[filterStatus]; ok {
		for name := range strings.SplitSeq(s, ",") {
			status := incident.Status(name)
			if !slices.Contains(incident.Statuses, status) {
				invalid(w, r, "status must list open, acknowledged or closed, separated by commas")
				return
			}
			f.Statuses = append(f.Statuses, status)
		}
	}
	if s, ok := q.Filters[filterResourceID]; ok {
		if !httpx.ValidID(s) {
			invalid(w, r, "resource_id must be a UUID in lower case")
			return
		}
		f.ResourceID = s
	}
	list, next, err := incident.ListIncidents(r.Context(), h.db, f, q.Limit, cursor(q))
	if err != nil {
		httpx.ServerError(w, r, h.logger, "incident: list", err)
		return
	}
	resp := incidentListResponse{Incidents: make([]incidentResponse, 0, len(list))}
	for _, i := range list {
		resp.Incidents = append(resp.Incidents, newIncidentResponse(i))
	}
	if next != nil {
		resp.NextCursor = httpx.EncodeCursor(httpx.Cursor{Time: next.Time, ID: next.ID})
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// GetIncident handles GET /api/v1/incidents/{id}.
func (h *Handler) GetIncident(w http.ResponseWriter, r *http.Request) {
	i, err := incident.GetIncident(r.Context(), h.db, r.PathValue("id"))
	if err != nil {
		h.writeError(w, r, "incident: get", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, newIncidentResponse(i))
}

// updateRequest lists every field of the triage. What the events suggest is
// not among them: the analyst overrides it instead.
type updateRequest struct {
	Status             httpx.Optional[incident.Status]   `json:"status"`
	Notes              httpx.Optional[string]            `json:"notes"`
	SeverityOverride   httpx.Nullable[incident.Severity] `json:"severity_override"`
	TechniquesOverride httpx.Nullable[[]string]          `json:"techniques_override"`
}

// UpdateIncident handles PATCH /api/v1/incidents/{id}.
func (h *Handler) UpdateIncident(w http.ResponseWriter, r *http.Request) {
	p, ok := access.PrincipalFrom(r.Context())
	if !ok {
		httpx.ServerError(w, r, h.logger, "incident: read principal", errors.New("no principal in the request context"))
		return
	}
	var req updateRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	c := incident.Change{
		Status:                req.Status.Ptr(),
		Notes:                 req.Notes.Ptr(),
		SetSeverityOverride:   req.SeverityOverride.Set,
		SetTechniquesOverride: req.TechniquesOverride.Set,
	}
	if req.SeverityOverride.Set && !req.SeverityOverride.Null {
		c.SeverityOverride = &req.SeverityOverride.Value
	}
	if req.TechniquesOverride.Set && !req.TechniquesOverride.Null {
		// An empty list decodes to an empty slice, not nil, so it sets an
		// override without techniques instead of removing it.
		c.TechniquesOverride = req.TechniquesOverride.Value
	}
	if c.IsEmpty() {
		invalid(w, r, "request must change status, notes, severity_override or techniques_override")
		return
	}
	i, err := incident.Triage(r.Context(), h.db, p.Actor(), r.PathValue("id"), c)
	if err != nil {
		h.writeError(w, r, "incident: triage", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, newIncidentResponse(i))
}

type httpResponse struct {
	Method         string `json:"method"`
	UserAgent      string `json:"user_agent"`
	Referer        string `json:"referer"`
	AcceptLanguage string `json:"accept_language"`
}

type dnsResponse struct {
	Zone      string `json:"zone"`
	Prefix    string `json:"prefix"`
	QType     string `json:"qtype"`
	Transport string `json:"transport"`
}

type eventResponse struct {
	ID             string        `json:"id"`
	ResourceType   string        `json:"resource_type"`
	ResourceID     string        `json:"resource_id"`
	HoneytokenType *string       `json:"honeytoken_type"`
	Techniques     []string      `json:"techniques"`
	IncidentID     *string       `json:"incident_id"`
	OccurredAt     time.Time     `json:"occurred_at"`
	RecordedAt     time.Time     `json:"recorded_at"`
	Channel        string        `json:"channel"`
	ClientIP       *string       `json:"client_ip"`
	HTTP           *httpResponse `json:"http"`
	DNS            *dnsResponse  `json:"dns"`
}

func newEventResponse(e incident.Event) eventResponse {
	out := eventResponse{
		ID:           e.ID,
		ResourceType: e.ResourceType,
		ResourceID:   e.ResourceID,
		Techniques:   e.Techniques,
		IncidentID:   e.IncidentID,
		OccurredAt:   e.OccurredAt.UTC(),
		RecordedAt:   e.RecordedAt.UTC(),
		Channel:      e.Channel,
	}
	if out.Techniques == nil {
		out.Techniques = []string{}
	}
	if e.HoneytokenType != "" {
		out.HoneytokenType = &e.HoneytokenType
	}
	if e.ClientIP.IsValid() {
		out.ClientIP = new(e.ClientIP.String())
	}
	switch e.Channel {
	case incident.ChannelHTTP:
		out.HTTP = &httpResponse{Method: e.Method, UserAgent: e.UserAgent, Referer: e.Referer, AcceptLanguage: e.AcceptLanguage}
	case incident.ChannelDNS:
		out.DNS = &dnsResponse{Zone: e.DNSZone, Prefix: e.DNSPrefix, QType: e.DNSQType, Transport: e.DNSTransport}
	}
	return out
}

type eventListResponse struct {
	Events     []eventResponse `json:"events"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

// ListEvents handles GET /api/v1/events.
func (h *Handler) ListEvents(w http.ResponseWriter, r *http.Request) {
	q, ok := httpx.DecodeListQuery(w, r, defaultPageSize, incident.MaxPageSize, filterIncidentID)
	if !ok {
		return
	}
	var f incident.EventFilter
	if s, ok := q.Filters[filterIncidentID]; ok {
		if !httpx.ValidID(s) {
			invalid(w, r, "incident_id must be a UUID in lower case")
			return
		}
		f.IncidentID = s
	}
	list, next, err := incident.ListEvents(r.Context(), h.db, f, q.Limit, cursor(q))
	if err != nil {
		httpx.ServerError(w, r, h.logger, "incident: list events", err)
		return
	}
	if !h.recordEventsRead(w, r) {
		return
	}
	resp := eventListResponse{Events: make([]eventResponse, 0, len(list))}
	for _, e := range list {
		resp.Events = append(resp.Events, newEventResponse(e))
	}
	if next != nil {
		resp.NextCursor = httpx.EncodeCursor(httpx.Cursor{Time: next.Time, ID: next.ID})
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// GetEvent handles GET /api/v1/events/{id}.
func (h *Handler) GetEvent(w http.ResponseWriter, r *http.Request) {
	e, err := incident.GetEvent(r.Context(), h.db, r.PathValue("id"))
	if err != nil {
		h.writeError(w, r, "incident: get event", err)
		return
	}
	if !h.recordEventsRead(w, r) {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, newEventResponse(e))
}

// recordEventsRead records that the principal reads events. On failure, it
// writes the error response and returns false: without the entry, the reader
// receives no data.
func (h *Handler) recordEventsRead(w http.ResponseWriter, r *http.Request) bool {
	p, ok := access.PrincipalFrom(r.Context())
	if !ok {
		httpx.ServerError(w, r, h.logger, "incident: record read of events", errors.New("no principal in the request context"))
		return false
	}
	err := audit.NewStore(h.db).RecordUnlessRepeated(r.Context(), audit.Entry{
		Action:  audit.ActionEventsRead,
		Outcome: audit.OutcomeSuccess,
		Actor:   p.Actor(),
	}.WithRequest(r.Context()))
	if err != nil {
		httpx.ServerError(w, r, h.logger, "incident: record read of events", err)
		return false
	}
	return true
}

func cursor(q httpx.ListQuery) *incident.Cursor {
	if q.After == nil {
		return nil
	}
	return &incident.Cursor{Time: q.After.Time, ID: q.After.ID}
}

// Rules of the fields, as the error responses state them.
var (
	statusRule     = "status must be open, acknowledged or closed"
	severityRule   = "severity_override must be info, low, medium, high, critical or null"
	notesRule      = fmt.Sprintf("notes must have at most %d characters; line breaks and tabs are the only control or format characters allowed", incident.MaxNotesLength)
	techniquesRule = fmt.Sprintf("techniques_override must list at most %d distinct ATT&CK technique identifiers, such as T1078 or T1003.001, or be null", honeytoken.MaxTechniques)
)

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, incident.ErrNotFound), errors.Is(err, incident.ErrEventNotFound):
		httpx.NotFound(w, r)
	case errors.Is(err, incident.ErrStatusBackward):
		httpx.WriteError(w, r, http.StatusConflict, codeInvalidState,
			"the status of an incident only moves forward, from open over acknowledged to closed; a closed incident stays closed")
	case errors.Is(err, incident.ErrInvalidStatus):
		invalid(w, r, statusRule)
	case errors.Is(err, incident.ErrInvalidSeverity):
		invalid(w, r, severityRule)
	case errors.Is(err, incident.ErrInvalidNotes):
		invalid(w, r, notesRule)
	case errors.Is(err, incident.ErrInvalidTechniques):
		invalid(w, r, techniquesRule)
	default:
		httpx.ServerError(w, r, h.logger, op, err)
	}
}

func invalid(w http.ResponseWriter, r *http.Request, message string) {
	httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, message)
}
