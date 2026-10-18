// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package artifactapi serves the artifacts of the team.
package artifactapi

import (
	"time"

	"nyktus.org/nyktus/internal/artifact"
	"nyktus.org/nyktus/internal/catalog"
)

// Response is the representation of an artifact without its content, which
// is downloaded on its own.
type Response struct {
	ID                string         `json:"id"`
	ScenarioID        *string        `json:"scenario_id"`
	DeceptionArtifact string         `json:"deception_artifact"`
	FileName          string         `json:"file_name"`
	Format            catalog.Format `json:"format"`
	MediaType         string         `json:"media_type"`
	Size              int            `json:"size"`
	PlacementNotes    string         `json:"placement_notes"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

// NewResponse returns the representation of a.
func NewResponse(a artifact.Artifact) Response {
	return Response{
		ID:                a.ID,
		ScenarioID:        a.ScenarioID,
		DeceptionArtifact: a.DeceptionArtifact,
		FileName:          a.FileName,
		Format:            a.Format,
		MediaType:         artifact.MediaType(a.Format),
		Size:              a.Size,
		PlacementNotes:    a.PlacementNotes,
		CreatedAt:         a.CreatedAt,
		UpdatedAt:         a.UpdatedAt,
	}
}
