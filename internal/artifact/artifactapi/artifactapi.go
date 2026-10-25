// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package artifactapi serves the artifacts of the team: their metadata, the
// download of their content, and their placement notes. Downloads are
// recorded in the audit log, at most once per user or key and minute.
package artifactapi

import (
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"time"

	"nyktus.org/nyktus/internal/artifact"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/platform/httpx"
)

// Response is the representation of an artifact without its content, which
// is downloaded on its own.
type Response struct {
	ID              string            `json:"id"`
	ScenarioID      *string           `json:"scenario_id"`
	CatalogArtifact string            `json:"catalog_artifact"`
	FileName        string            `json:"file_name"`
	Format          catalog.Format    `json:"format"`
	MediaType       string            `json:"media_type"`
	Size            int               `json:"size"`
	Placing         string            `json:"placing"`
	Bindings        map[string]string `json:"bindings"`
	PlacementNotes  string            `json:"placement_notes"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// NewResponse returns the representation of a.
func NewResponse(a artifact.Artifact) Response {
	bindings := a.Bindings
	if bindings == nil {
		bindings = map[string]string{}
	}
	return Response{
		ID:              a.ID,
		ScenarioID:      a.ScenarioID,
		CatalogArtifact: a.CatalogArtifact,
		FileName:        a.FileName,
		Format:          a.Format,
		MediaType:       artifact.MediaType(a.Format),
		Size:            a.Size,
		Placing:         a.Placing,
		Bindings:        bindings,
		PlacementNotes:  a.PlacementNotes,
		CreatedAt:       a.CreatedAt,
		UpdatedAt:       a.UpdatedAt,
	}
}

// defaultPageSize is the page size if the request names none.
const defaultPageSize = 50

// maxBodyBytes bounds the requests: placement notes of 2000 characters, even
// with every character escaped in JSON, fit with room to spare.
const maxBodyBytes = 64 << 10

// filterScenarioID narrows the list to the artifacts of a scenario.
const filterScenarioID = "scenario_id"

// Handler serves the artifacts. Its routes must require the permissions
// artifacts:read and artifacts:write.
type Handler struct {
	logger *slog.Logger
	db     artifact.DB
}

// NewHandler returns the handlers of the artifacts.
func NewHandler(logger *slog.Logger, d artifact.DB) *Handler {
	if logger == nil || d == nil {
		panic("artifactapi: handler needs a logger and a database")
	}
	return &Handler{logger: logger, db: d}
}

type listResponse struct {
	Artifacts  []Response `json:"artifacts"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

// List handles GET /api/v1/artifacts.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q, ok := httpx.DecodeListQuery(w, r, defaultPageSize, artifact.MaxPageSize, filterScenarioID)
	if !ok {
		return
	}
	var f artifact.Filter
	if s, ok := q.Filters[filterScenarioID]; ok {
		if !httpx.ValidID(s) {
			invalid(w, r, "scenario_id must be a UUID in lower case")
			return
		}
		f.ScenarioID = s
	}
	var after *artifact.Cursor
	if q.After != nil {
		after = &artifact.Cursor{CreatedAt: q.After.Time, ID: q.After.ID}
	}
	list, next, err := artifact.NewStore(h.db).List(r.Context(), f, q.Limit, after)
	if err != nil {
		httpx.ServerError(w, r, h.logger, "artifact: list", err)
		return
	}
	resp := listResponse{Artifacts: make([]Response, 0, len(list))}
	for _, a := range list {
		resp.Artifacts = append(resp.Artifacts, NewResponse(a))
	}
	if next != nil {
		resp.NextCursor = httpx.EncodeCursor(httpx.Cursor{Time: next.CreatedAt, ID: next.ID})
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/artifacts/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	a, err := artifact.NewStore(h.db).Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeError(w, r, "artifact: get", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, NewResponse(a))
}

// Download handles GET /api/v1/artifacts/{id}/content. The file is offered as
// an attachment that the browser saves instead of showing: an artifact may be
// an HTML page, which must never run in the origin of the console. The read is
// recorded in the audit log before the content is sent.
func (h *Handler) Download(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	a, content, err := artifact.NewStore(h.db).Content(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeError(w, r, "artifact: download", err)
		return
	}
	err = audit.NewStore(h.db).RecordUnlessRepeated(r.Context(), audit.Entry{
		Action:  audit.ActionArtifactsRead,
		Outcome: audit.OutcomeSuccess,
		Actor:   p.Actor(),
	}.WithRequest(r.Context()))
	if err != nil {
		httpx.ServerError(w, r, h.logger, "artifact: record download", err)
		return
	}
	hdr := w.Header()
	hdr.Set("Content-Type", artifact.MediaType(a.Format))
	// The catalog allows only names of letters, digits, spaces, dots,
	// hyphens and underscores; FormatMediaType quotes them all the same.
	hdr.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": a.FileName}))
	hdr.Set("Content-Length", strconv.Itoa(len(content)))
	hdr.Set("X-Content-Type-Options", "nosniff")
	// A client that renders the file anyway runs it without scripts, in an
	// origin of its own, and loads nothing, so that opening it reveals
	// nothing to a third party either.
	hdr.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	hdr.Set("Cache-Control", "no-store")
	// A server answers HEAD without the body that the handler writes.
	_, _ = w.Write(content) //nolint:gosec // G705: an attachment with nosniff and CSP sandbox, which a browser saves instead of rendering.
}

// updateRequest lists every field that a change may contain: only the
// placement notes. What an artifact contains and where it belongs is decided
// when the deception is applied.
type updateRequest struct {
	PlacementNotes httpx.Optional[string] `json:"placement_notes"`
}

// Update handles PATCH /api/v1/artifacts/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var req updateRequest
	if !httpx.DecodeJSON(w, r, &req, maxBodyBytes) {
		return
	}
	if !req.PlacementNotes.Set {
		invalid(w, r, "request must change placement_notes")
		return
	}
	a, err := artifact.SetPlacementNotes(r.Context(), h.db, p.Actor(), r.PathValue("id"), req.PlacementNotes.Value)
	if err != nil {
		h.writeError(w, r, "artifact: update", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, NewResponse(a))
}

// Delete handles DELETE /api/v1/artifacts/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	if err := artifact.Delete(r.Context(), h.db, p.Actor(), r.PathValue("id")); err != nil {
		h.writeError(w, r, "artifact: delete", err)
		return
	}
	h.logger.InfoContext(r.Context(), "artifact: deleted", slog.String("artifact_id", r.PathValue("id")))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// principal returns the principal that the authorizer attached to the request.
// Without one, the route was registered without authentication, which is a
// wiring mistake.
func (h *Handler) principal(w http.ResponseWriter, r *http.Request) (access.Principal, bool) {
	p, ok := access.PrincipalFrom(r.Context())
	if !ok {
		httpx.ServerError(w, r, h.logger, "artifact: read principal", errors.New("no principal in the request context"))
	}
	return p, ok
}

// notesRule is the rule of the placement notes, as the error responses state
// it.
var notesRule = fmt.Sprintf("placement_notes must have at most %d characters; line breaks and tabs are the only control characters allowed", artifact.MaxPlacementNotesLength)

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, artifact.ErrNotFound):
		httpx.NotFound(w, r)
	case errors.Is(err, artifact.ErrInvalidPlacementNotes):
		invalid(w, r, notesRule)
	default:
		httpx.ServerError(w, r, h.logger, op, err)
	}
}

func invalid(w http.ResponseWriter, r *http.Request, message string) {
	httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, message)
}
