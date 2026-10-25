// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package artifact keeps the artifacts of scenarios: files that applying a
// deception rendered, such as an SSH configuration that names a DNS
// honeytoken. An artifact raises no event; it makes its scenario believable.
//
// Artifacts are part of the inventory: their content holds the URLs and names
// of honeytokens. Only applying a deception creates them, in its scenario;
// they leave it only when the scenario is deleted and they are kept. HTTP
// lives in artifactapi.
package artifact

import (
	"errors"
	"log/slog"
	"time"

	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/platform/text"
)

// ResourceType names artifacts where other records refer to them, such as
// audit entries.
const ResourceType = "artifact"

// Names of the fields of a change, as recorded in the audit log.
const (
	FieldPlacementNotes = "placement_notes"
	FieldScenarioID     = "scenario_id"
)

// MaxPlacementNotesLength is the length of the placement notes, as the
// database enforces it.
const MaxPlacementNotesLength = 2000

// ErrInvalidPlacementNotes means that placement notes are too long or contain
// control characters other than line breaks and tabs.
var ErrInvalidPlacementNotes = errors.New("invalid placement notes")

// ValidatePlacementNotes accepts notes of up to MaxPlacementNotesLength
// characters, as text.ValidNotes describes.
func ValidatePlacementNotes(s string) error {
	if !text.ValidNotes(s, MaxPlacementNotesLength) {
		return ErrInvalidPlacementNotes
	}
	return nil
}

// MaxContentBytes is the largest content of an artifact, as the template
// engine renders it and the database enforces it.
const MaxContentBytes = catalog.MaxOutputBytes

// Artifact is a stored artifact without its content.
type Artifact struct {
	ID string
	// ScenarioID is the scenario that applying the deception created, or nil
	// once the scenario was deleted and the artifact kept.
	ScenarioID *string
	// DeceptionArtifact is the identifier of the artifact in the catalog.
	DeceptionArtifact string
	// FileName is the name under which the artifact is downloaded.
	FileName string
	Format   catalog.Format
	// Size is the length of the content in bytes.
	Size int
	// PlacementNotes say where the artifact was placed.
	PlacementNotes string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// LogValue names the artifact by its identifier. Its name, notes and content
// are inventory and stay out of logs.
func (a Artifact) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", a.ID))
}

// mediaTypes are the media types of the downloads of each format. Files that
// a tool reads have no media type of their own, such as an SSH configuration,
// and are offered as bytes.
var mediaTypes = map[catalog.Format]string{
	catalog.FormatText:     "text/plain; charset=utf-8",
	catalog.FormatMarkdown: "text/markdown; charset=utf-8",
	catalog.FormatHTML:     "text/html; charset=utf-8",
	catalog.FormatConfig:   "application/octet-stream",
}

// MediaType returns the media type of an artifact of format f, or
// application/octet-stream for an unknown format.
func MediaType(f catalog.Format) string {
	if t, ok := mediaTypes[f]; ok {
		return t
	}
	return "application/octet-stream"
}

// Spec describes an artifact to create, rendered by applying a deception.
type Spec struct {
	ScenarioID        string
	DeceptionArtifact string
	FileName          string
	Format            catalog.Format
	Content           []byte
}
