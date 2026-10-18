// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package artifact

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/platform/db"
)

// Store persists artifacts in PostgreSQL.
type Store struct {
	db db.Querier
}

// NewStore returns a Store that runs its queries on q, a connection pool or a
// transaction.
func NewStore(q db.Querier) *Store {
	if q == nil {
		panic("artifact: nil querier")
	}
	return &Store{db: q}
}

// columns are the columns of an artifact without its content, which only a
// download reads.
const columns = `id, scenario_id, deception_artifact, file_name, format, octet_length(content), placement_notes,
created_at, updated_at`

func scan(row pgx.Row) (Artifact, error) {
	var a Artifact
	err := row.Scan(&a.ID, &a.ScenarioID, &a.DeceptionArtifact, &a.FileName, &a.Format, &a.Size, &a.PlacementNotes,
		&a.CreatedAt, &a.UpdatedAt)
	return a, err
}

// Create stores the artifact spec in its scenario. The catalog validated the
// file name and the format and bounded the content, and the schema checks
// them again; the caller creates the scenario in the same transaction.
func (s *Store) Create(ctx context.Context, spec Spec) (Artifact, error) {
	a, err := scan(s.db.QueryRow(ctx, `
INSERT INTO artifacts (scenario_id, deception_artifact, file_name, format, content)
VALUES ($1, $2, $3, $4, $5)
RETURNING `+columns, spec.ScenarioID, spec.DeceptionArtifact, spec.FileName, spec.Format, spec.Content))
	if err != nil {
		return Artifact{}, fmt.Errorf("create artifact: %w", err)
	}
	return a, nil
}
