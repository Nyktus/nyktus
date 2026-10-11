// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package auditapi serves the audit log over HTTP. It is separate from the audit
// package, which records entries for every server role and does not depend on
// HTTP.
package auditapi

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/httpx"
)

// defaultPageSize is the page size if the request names none.
const defaultPageSize = 50

type handler struct {
	logger *slog.Logger
	store  *audit.Store
}

// NewHandler returns the handler of GET /api/v1/audit-entries. The route must
// require the permission to read the audit log.
//
// Entries contain personal data, so every read is recorded in the audit log
// itself, at most once per user and audit.RepeatWindow. The entry is written
// before the response; without it, the reader receives no data.
func NewHandler(logger *slog.Logger, q db.Querier) http.Handler {
	if logger == nil || q == nil {
		panic("auditapi: handler needs a logger and a database")
	}
	return &handler{logger: logger, store: audit.NewStore(q)}
}

type actorResponse struct {
	Kind        audit.ActorKind  `json:"kind"`
	AuthMethod  audit.AuthMethod `json:"auth_method"`
	UserID      string           `json:"user_id,omitempty"`
	Email       string           `json:"email,omitempty"`
	DisplayName string           `json:"display_name,omitempty"`
	APIKeyID    string           `json:"api_key_id,omitempty"`
}

type resourceResponse struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type entryResponse struct {
	ID            string            `json:"id"`
	OccurredAt    time.Time         `json:"occurred_at"`
	Action        audit.Action      `json:"action"`
	Outcome       audit.Outcome     `json:"outcome"`
	Actor         actorResponse     `json:"actor"`
	Resource      *resourceResponse `json:"resource,omitempty"`
	ChangedFields []string          `json:"changed_fields"`
	ClientIP      string            `json:"client_ip,omitempty"`
	RequestID     string            `json:"request_id,omitempty"`
}

type listResponse struct {
	Entries    []entryResponse `json:"entries"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q, ok := httpx.DecodeListQuery(w, r, defaultPageSize, audit.MaxPageSize)
	if !ok {
		return
	}
	var after *audit.Cursor
	if q.After != nil {
		after = &audit.Cursor{OccurredAt: q.After.Time, ID: q.After.ID}
	}
	entries, next, err := h.store.List(r.Context(), q.Limit, after)
	if err != nil {
		httpx.ServerError(w, r, h.logger, "audit: list entries", err)
		return
	}
	p, ok := access.PrincipalFrom(r.Context())
	if !ok {
		httpx.ServerError(w, r, h.logger, "audit: record read", errors.New("no principal in the request context"))
		return
	}
	err = h.store.RecordUnlessRepeated(r.Context(), audit.Entry{
		Action:  audit.ActionAuditRead,
		Outcome: audit.OutcomeSuccess,
		Actor:   p.Actor(),
	}.WithRequest(r.Context()))
	if err != nil {
		httpx.ServerError(w, r, h.logger, "audit: record read", err)
		return
	}

	resp := listResponse{Entries: make([]entryResponse, 0, len(entries))}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, newEntryResponse(e))
	}
	if next != nil {
		resp.NextCursor = httpx.EncodeCursor(httpx.Cursor{Time: next.OccurredAt, ID: next.ID})
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func newEntryResponse(e audit.StoredEntry) entryResponse {
	out := entryResponse{
		ID:         e.ID,
		OccurredAt: e.OccurredAt,
		Action:     e.Action,
		Outcome:    e.Outcome,
		Actor: actorResponse{
			Kind:        e.Actor.Kind,
			AuthMethod:  e.Actor.Method,
			UserID:      e.Actor.UserID,
			Email:       e.ActorEmail,
			DisplayName: e.ActorDisplayName,
			APIKeyID:    e.Actor.APIKeyID,
		},
		ChangedFields: e.ChangedFields,
		RequestID:     e.RequestID,
	}
	// The specification requires an array, also for entries without changed
	// fields.
	if out.ChangedFields == nil {
		out.ChangedFields = []string{}
	}
	if e.Resource.Type != "" {
		out.Resource = &resourceResponse{Type: e.Resource.Type, ID: e.Resource.ID}
	}
	if e.ClientIP.IsValid() {
		out.ClientIP = e.ClientIP.String()
	}
	return out
}
