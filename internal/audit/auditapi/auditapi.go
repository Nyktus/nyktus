// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package auditapi serves the audit log over HTTP. It is separate from the audit
// package, which records entries for every server role and does not depend on
// HTTP.
package auditapi

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/httpx"
)

// defaultPageSize is the page size if the request names none.
const defaultPageSize = 50

var limitFormat = regexp.MustCompile(`^[1-9][0-9]{0,8}$`)

var uuidFormat = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

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
	size, after, err := parseQuery(r)
	if err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, err.Error())
		return
	}
	entries, next, err := h.store.List(r.Context(), size, after)
	if errors.Is(err, audit.ErrInvalidPageSize) {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, errInvalidLimit.Error())
		return
	}
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
		resp.NextCursor = encodeCursor(*next)
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

// parseQuery reads the page size and the cursor. Unknown and repeated parameters
// are rejected, as unknown fields of a request body are, and so is a query that
// cannot be parsed, which url.URL.Query would silently drop.
func parseQuery(r *http.Request) (int, *audit.Cursor, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return 0, nil, errors.New("query string is invalid")
	}
	// The messages do not repeat the parameter names, which the client chose.
	for name, values := range query {
		if name != "limit" && name != "cursor" {
			return 0, nil, errors.New("unknown query parameter; use limit and cursor")
		}
		if len(values) != 1 {
			return 0, nil, errors.New("query parameters must be given once")
		}
	}

	size := defaultPageSize
	if s, ok := query["limit"]; ok {
		// One spelling per number: no sign and no leading zeros, which
		// strconv.Atoi would accept. The store checks the range, so that the
		// bounds are defined once.
		if !limitFormat.MatchString(s[0]) {
			return 0, nil, errInvalidLimit
		}
		n, err := strconv.Atoi(s[0])
		if err != nil {
			return 0, nil, errInvalidLimit
		}
		size = n
	}
	var after *audit.Cursor
	if s, ok := query["cursor"]; ok {
		c, err := decodeCursor(s[0])
		if err != nil {
			return 0, nil, err
		}
		after = &c
	}
	return size, after, nil
}

var (
	errInvalidCursor = errors.New("cursor is invalid; use the next_cursor of a previous response")
	errInvalidLimit  = errors.New("limit must be a number from 1 to " + strconv.Itoa(audit.MaxPageSize))
)

// A cursor is opaque to clients. It encodes the time and the identifier of the
// last entry of a page, which the next page continues after.
func encodeCursor(c audit.Cursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(c.OccurredAt.UTC().Format(time.RFC3339Nano) + "|" + c.ID))
}

func decodeCursor(s string) (audit.Cursor, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return audit.Cursor{}, errInvalidCursor
	}
	at, id, ok := strings.Cut(string(raw), "|")
	if !ok || !uuidFormat.MatchString(id) {
		return audit.Cursor{}, errInvalidCursor
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return audit.Cursor{}, errInvalidCursor
	}
	return audit.Cursor{OccurredAt: t, ID: id}, nil
}
