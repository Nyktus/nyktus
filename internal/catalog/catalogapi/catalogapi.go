// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package catalogapi serves the deceptions of the catalog: their guides, the
// slots they ask for and their example files. The routes must require the
// permission catalog:read. The catalog is the same in every installation and
// holds no inventory, so every role reads it.
package catalogapi

import (
	"mime"
	"net/http"
	"slices"
	"strconv"

	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/engage"
	"nyktus.org/nyktus/internal/honeypot"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/severity"
)

// paramLang selects the language of the texts. Without it, they are English.
const paramLang = "lang"

// defaultLang is the language of the texts if the request names none.
const defaultLang = "en"

// Handler serves the deceptions of the catalog.
type Handler struct {
	catalog *catalog.Catalog
}

// NewHandler returns the handlers of the catalog c.
func NewHandler(c *catalog.Catalog) *Handler {
	if c == nil {
		panic("catalogapi: handler needs a catalog")
	}
	return &Handler{catalog: c}
}

// summary is a deception as the list shows it.
type summary struct {
	ID               string           `json:"id"`
	Category         catalog.Category `json:"category"`
	Title            string           `json:"title"`
	Summary          string           `json:"summary"`
	Techniques       []string         `json:"techniques"`
	EngageActivities []string         `json:"engage_activities"`
}

// detail is a deception with its guide, the slots it asks for and its files.
type detail struct {
	summary
	Guide       string               `json:"guide"`
	Honeytokens []honeytokenResponse `json:"honeytokens"`
	Honeypots   []honeypotResponse   `json:"honeypots"`
	Files       []fileResponse       `json:"files"`
}

type (
	honeytokenResponse struct {
		Label      string          `json:"label"`
		Type       honeytoken.Type `json:"type"`
		Techniques []string        `json:"techniques"`
		Severity   severity.Level  `json:"severity"`
	}
	honeypotResponse struct {
		Label   string           `json:"label"`
		Service honeypot.Service `json:"service"`
	}
	// fileResponse is an example file; its content is downloaded through its
	// own route.
	fileResponse struct {
		Name   string         `json:"name"`
		Format catalog.Format `json:"format"`
		Size   int            `json:"size"`
	}
)

func toSummary(d catalog.Deception, lang string) summary {
	return summary{
		ID: d.ID, Category: d.Category, Title: d.Title[lang], Summary: d.Summary[lang],
		Techniques: nonNil(d.Techniques), EngageActivities: nonNil(d.EngageActivities),
	}
}

func toDetail(d catalog.Deception, lang string) detail {
	resp := detail{
		summary:     toSummary(d, lang),
		Guide:       d.Guide[lang],
		Honeytokens: make([]honeytokenResponse, 0, len(d.Honeytokens)),
		Honeypots:   make([]honeypotResponse, 0, len(d.Honeypots)),
		Files:       make([]fileResponse, 0, len(d.Files)),
	}
	for _, h := range d.Honeytokens {
		resp.Honeytokens = append(resp.Honeytokens, honeytokenResponse{
			Label: h.Label[lang], Type: h.Type, Techniques: nonNil(h.Techniques), Severity: h.Severity,
		})
	}
	for _, h := range d.Honeypots {
		resp.Honeypots = append(resp.Honeypots, honeypotResponse{Label: h.Label[lang], Service: h.Service})
	}
	for _, f := range d.Files {
		resp.Files = append(resp.Files, fileResponse{Name: f.Name, Format: f.Format, Size: len(f.Content)})
	}
	return resp
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type listResponse struct {
	Deceptions []summary `json:"deceptions"`
}

// List handles GET /api/v1/catalog/deceptions. The catalog is small and
// fixed at build time, so the list is not paged.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	lang, ok := decodeLang(w, r)
	if !ok {
		return
	}
	resp := listResponse{Deceptions: []summary{}}
	for _, d := range h.catalog.Deceptions() {
		resp.Deceptions = append(resp.Deceptions, toSummary(d, lang))
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/catalog/deceptions/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	lang, ok := decodeLang(w, r)
	if !ok {
		return
	}
	d, found := h.catalog.Lookup(r.PathValue("id"))
	if !found {
		httpx.NotFound(w, r)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toDetail(d, lang))
}

type engageActivity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type engageResponse struct {
	Activities []engageActivity `json:"activities"`
}

// Engage handles GET /api/v1/catalog/engage: the names of the Engage activities
// that scenarios and deceptions refer to by identifier, so that the console can
// show a name beside it. The list is embedded reference data of MITRE, in
// English only, and takes no query.
func (h *Handler) Engage(w http.ResponseWriter, r *http.Request) {
	if _, ok := httpx.DecodeQuery(w, r); !ok {
		return
	}
	resp := engageResponse{Activities: []engageActivity{}}
	for _, a := range engage.All() {
		resp.Activities = append(resp.Activities, engageActivity{ID: a.ID, Name: a.Name})
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// File handles GET /api/v1/catalog/deceptions/{id}/files/{name}: an example file
// as it stands in the catalog, as an attachment. The catalog is public to
// everyone who may read it, so the download is not audited.
func (h *Handler) File(w http.ResponseWriter, r *http.Request) {
	if _, ok := httpx.DecodeQuery(w, r); !ok {
		return
	}
	d, found := h.catalog.Lookup(r.PathValue("id"))
	if !found {
		httpx.NotFound(w, r)
		return
	}
	f, found := d.File(r.PathValue("name"))
	if !found {
		httpx.NotFound(w, r)
		return
	}
	hdr := w.Header()
	hdr.Set("Content-Type", catalog.MediaType(f.Format))
	// The catalog allows only names of letters, digits, spaces, dots, hyphens
	// and underscores; FormatMediaType quotes them all the same.
	hdr.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": f.Name}))
	hdr.Set("Content-Length", strconv.Itoa(len(f.Content)))
	hdr.Set("X-Content-Type-Options", "nosniff")
	// A client that renders the file anyway runs it without scripts, in an
	// origin of its own, and loads nothing, so that opening it reveals nothing
	// to a third party either.
	hdr.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	hdr.Set("Cache-Control", "no-store")
	// A server answers HEAD without the body that the handler writes.
	_, _ = w.Write(f.Content)
}

// decodeLang returns the language that the query selects, the default
// without one. It rejects other parameters, a repeated parameter and an
// unknown language with 400.
func decodeLang(w http.ResponseWriter, r *http.Request) (string, bool) {
	query, ok := httpx.DecodeQuery(w, r, paramLang)
	if !ok {
		return "", false
	}
	lang, ok := query[paramLang]
	if !ok {
		return defaultLang, true
	}
	if !slices.Contains(catalog.Languages, lang) {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeInvalidRequest, "lang must be en or de")
		return "", false
	}
	return lang, true
}
