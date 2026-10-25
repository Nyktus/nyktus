// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package catalogapi serves the deceptions and the artifacts of the catalog.
// The routes must
// require the permission catalog:read. The catalog is the same in every
// installation and holds no inventory, so every role reads it.
package catalogapi

import (
	"net/http"
	"slices"

	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/severity"
)

// paramLang selects the language of the texts. Without it, they are English.
const paramLang = "lang"

// defaultLang is the language of the texts if the request names none.
const defaultLang = "en"

// Handler serves the deceptions and the artifacts of the catalog.
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

// detail is a deception with what applying it creates and asks for.
type detail struct {
	summary
	Honeytokens []honeytokenResponse `json:"honeytokens"`
	Persona     []personaResponse    `json:"persona"`
	Secrets     []secretResponse     `json:"secrets"`
	Artifacts   []artifactResponse   `json:"artifacts"`
}

type (
	honeytokenResponse struct {
		Key        string          `json:"key"`
		Type       honeytoken.Type `json:"type"`
		Label      string          `json:"label"`
		Techniques []string        `json:"techniques"`
		Severity   severity.Level  `json:"severity"`
	}
	personaResponse struct {
		Key     string       `json:"key"`
		Kind    catalog.Kind `json:"kind"`
		Label   string       `json:"label"`
		Example string       `json:"example"`
	}
	// artifactResponse is an artifact that a deception recommends; its key
	// is the identifier of the artifact in the catalog.
	artifactResponse struct {
		Key      string         `json:"key"`
		FileName string         `json:"file_name"`
		Format   catalog.Format `json:"format"`
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
		Honeytokens: make([]honeytokenResponse, 0, len(d.Honeytokens)),
		Persona:     make([]personaResponse, 0, len(d.Persona)),
		Secrets:     []secretResponse{},
		Artifacts:   make([]artifactResponse, 0, len(d.Artifacts)),
	}
	for _, h := range d.Honeytokens {
		resp.Honeytokens = append(resp.Honeytokens, honeytokenResponse{
			Key: h.Key, Type: h.Type, Label: h.Label[lang], Techniques: nonNil(h.Techniques), Severity: h.Severity,
		})
	}
	for _, p := range d.Persona {
		resp.Persona = append(resp.Persona, personaResponse{Key: p.Key, Kind: p.Kind, Label: p.Label[lang], Example: p.Example})
	}
	for _, a := range d.Artifacts {
		resp.Artifacts = append(resp.Artifacts, artifactResponse{Key: a.ID, FileName: a.FileName, Format: a.Format})
		// The deception lists the secrets of its artifacts by key, in order, so
		// that a key stays unique as it was when the deception held them. Every
		// artifact that names a key generates its own value.
		for _, s := range a.Secrets {
			if !slices.ContainsFunc(resp.Secrets, func(r secretResponse) bool { return r.Key == s.Key }) {
				resp.Secrets = append(resp.Secrets, secretResponse(s))
			}
		}
	}
	return resp
}

// artifactSummary is an artifact as the list shows it.
type artifactSummary struct {
	ID       string           `json:"id"`
	Category catalog.Category `json:"category"`
	Title    string           `json:"title"`
	Summary  string           `json:"summary"`
}

// artifactDetail is an artifact with the file it renders and what it asks for.
type artifactDetail struct {
	artifactSummary
	FileName string            `json:"file_name"`
	Format   catalog.Format    `json:"format"`
	Slots    []slotResponse    `json:"slots"`
	Persona  []personaResponse `json:"persona"`
	Secrets  []secretResponse  `json:"secrets"`
}

type (
	slotResponse struct {
		Key      string            `json:"key"`
		Accepts  []honeytoken.Type `json:"accepts"`
		Optional bool              `json:"optional"`
	}
	secretResponse struct {
		Key    string `json:"key"`
		Length int    `json:"length"`
	}
)

func toArtifactSummary(a catalog.Artifact, lang string) artifactSummary {
	return artifactSummary{
		ID: a.ID, Category: a.Category, Title: a.Title[lang], Summary: a.Summary[lang],
	}
}

func toArtifactDetail(a catalog.Artifact, lang string) artifactDetail {
	resp := artifactDetail{
		artifactSummary: toArtifactSummary(a, lang),
		FileName:        a.FileName, Format: a.Format,
		Slots:   make([]slotResponse, 0, len(a.Slots)),
		Persona: make([]personaResponse, 0, len(a.Persona)),
		Secrets: make([]secretResponse, 0, len(a.Secrets)),
	}
	for _, s := range a.Slots {
		resp.Slots = append(resp.Slots, slotResponse{Key: s.Key, Accepts: slices.Clone(s.Accepts), Optional: s.Optional})
	}
	for _, p := range a.Persona {
		resp.Persona = append(resp.Persona, personaResponse{Key: p.Key, Kind: p.Kind, Label: p.Label[lang], Example: p.Example})
	}
	for _, s := range a.Secrets {
		resp.Secrets = append(resp.Secrets, secretResponse(s))
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

type artifactListResponse struct {
	Artifacts []artifactSummary `json:"artifacts"`
}

// ListArtifacts handles GET /api/v1/catalog/artifacts, which is complete and
// not paged like the list of deceptions.
func (h *Handler) ListArtifacts(w http.ResponseWriter, r *http.Request) {
	lang, ok := decodeLang(w, r)
	if !ok {
		return
	}
	resp := artifactListResponse{Artifacts: []artifactSummary{}}
	for _, a := range h.catalog.Artifacts() {
		resp.Artifacts = append(resp.Artifacts, toArtifactSummary(a, lang))
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// GetArtifact handles GET /api/v1/catalog/artifacts/{id}.
func (h *Handler) GetArtifact(w http.ResponseWriter, r *http.Request) {
	lang, ok := decodeLang(w, r)
	if !ok {
		return
	}
	a, found := h.catalog.LookupArtifact(r.PathValue("id"))
	if !found {
		httpx.NotFound(w, r)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toArtifactDetail(a, lang))
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
