// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package artifact

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/audit"
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

// scan scans the columns of an artifact, followed by more.
func scan(row pgx.Row, more ...any) (Artifact, error) {
	var a Artifact
	err := row.Scan(append([]any{
		&a.ID, &a.ScenarioID, &a.DeceptionArtifact, &a.FileName, &a.Format, &a.Size,
		&a.PlacementNotes, &a.CreatedAt, &a.UpdatedAt,
	}, more...)...)
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

// Errors of the store.
var (
	ErrNotFound = errors.New("artifact not found")
	// ErrInvalidPageSize is returned for a page size outside [1, MaxPageSize].
	ErrInvalidPageSize = errors.New("invalid page size")
)

// MaxPageSize is the largest page that List returns.
const MaxPageSize = 200

// Get returns the artifact id without its content. It returns ErrNotFound if
// there is none.
func (s *Store) Get(ctx context.Context, id string) (Artifact, error) {
	a, err := scan(s.db.QueryRow(ctx, `SELECT `+columns+` FROM artifacts WHERE id = $1`, id))
	if db.NotFound(err) {
		return Artifact{}, ErrNotFound
	}
	if err != nil {
		return Artifact{}, fmt.Errorf("get artifact %s: %w", id, err)
	}
	return a, nil
}

// Content returns the artifact id with its content. It returns ErrNotFound if
// there is none.
func (s *Store) Content(ctx context.Context, id string) (Artifact, []byte, error) {
	var content []byte
	a, err := scan(s.db.QueryRow(ctx, `SELECT `+columns+`, content FROM artifacts WHERE id = $1`, id), &content)
	if db.NotFound(err) {
		return Artifact{}, nil, ErrNotFound
	}
	if err != nil {
		return Artifact{}, nil, fmt.Errorf("get content of artifact %s: %w", id, err)
	}
	return a, content, nil
}

// Cursor marks the position after the last artifact of a page.
type Cursor struct {
	CreatedAt time.Time
	ID        string
}

// Filter narrows a list to the artifacts of a scenario. An empty field does
// not narrow it.
type Filter struct {
	ScenarioID string
}

// The scenario and the cursor, which the indexes serve, are conditions of
// statements of their own, so that a generic plan can seek into the index.
const (
	listOrder = `
ORDER BY created_at DESC, id DESC`
	listNewest = `SELECT ` + columns + ` FROM artifacts` + listOrder + `
LIMIT $1`
	listAfter = `SELECT ` + columns + ` FROM artifacts
WHERE (created_at, id) < ($1, $2::uuid)` + listOrder + `
LIMIT $3`
	listScenarioNewest = `SELECT ` + columns + ` FROM artifacts
WHERE scenario_id = $1` + listOrder + `
LIMIT $2`
	listScenarioAfter = `SELECT ` + columns + ` FROM artifacts
WHERE scenario_id = $1 AND (created_at, id) < ($2, $3::uuid)` + listOrder + `
LIMIT $4`
)

// List returns up to size artifacts that match f, without their content,
// from the newest to the oldest, that come after the cursor after, or from
// the newest if after is nil. next is the cursor of the following page, or nil
// if there are no more artifacts.
func (s *Store) List(ctx context.Context, f Filter, size int, after *Cursor) (list []Artifact, next *Cursor, err error) {
	if size < 1 || size > MaxPageSize {
		return nil, nil, ErrInvalidPageSize
	}
	// One more artifact than requested tells whether another page follows.
	var rows pgx.Rows
	switch {
	case f.ScenarioID == "" && after == nil:
		rows, err = s.db.Query(ctx, listNewest, size+1)
	case f.ScenarioID == "":
		rows, err = s.db.Query(ctx, listAfter, after.CreatedAt, after.ID, size+1)
	case after == nil:
		rows, err = s.db.Query(ctx, listScenarioNewest, f.ScenarioID, size+1)
	default:
		rows, err = s.db.Query(ctx, listScenarioAfter, f.ScenarioID, after.CreatedAt, after.ID, size+1)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("list artifacts: %w", err)
	}
	list, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Artifact, error) { return scan(row) })
	if err != nil {
		return nil, nil, fmt.Errorf("list artifacts: %w", err)
	}
	if len(list) > size {
		list = list[:size]
		last := list[size-1]
		next = &Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	return list, next, nil
}

// SetPlacementNotes validates notes and sets them as the placement notes of
// the artifact id. It returns the artifact after the change and whether the
// notes changed, and ErrNotFound if there is no such artifact.
//
// SetPlacementNotes must run in a transaction: it locks the artifact until
// the end of the transaction, so that the audit log records a change only if
// it changed the notes. An artifact is locked without its scenario, which a
// deletion of the scenario locks first: holding only the artifact, it cannot
// wait for the scenario.
func (s *Store) SetPlacementNotes(ctx context.Context, id, notes string) (Artifact, bool, error) {
	if err := ValidatePlacementNotes(notes); err != nil {
		return Artifact{}, false, err
	}
	current, err := scan(s.db.QueryRow(ctx, `SELECT `+columns+` FROM artifacts WHERE id = $1 FOR NO KEY UPDATE`, id))
	if db.NotFound(err) {
		return Artifact{}, false, ErrNotFound
	}
	if err != nil {
		return Artifact{}, false, fmt.Errorf("lock artifact %s: %w", id, err)
	}
	if current.PlacementNotes == notes {
		return current, false, nil
	}
	a, err := scan(s.db.QueryRow(ctx, `
UPDATE artifacts SET placement_notes = $2, updated_at = clock_timestamp()
WHERE id = $1
RETURNING `+columns, id, notes))
	if err != nil {
		return Artifact{}, false, fmt.Errorf("update artifact %s: %w", id, mapWriteError(err))
	}
	return a, true, nil
}

// Delete deletes the artifact id. It returns ErrNotFound if there is none.
func (s *Store) Delete(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM artifacts WHERE id = $1`, id)
	if db.NotFound(err) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("delete artifact %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// mapWriteError maps the check of the notes to the error of the validation,
// in case the rules of both ever differ.
func mapWriteError(err error) error {
	if db.Violation(err, db.CheckViolation) == "artifacts_placement_notes_check" {
		return ErrInvalidPlacementNotes
	}
	return err
}

// DB runs queries and starts transactions. A connection pool and a transaction
// implement it; in a transaction, Begin starts a savepoint.
type DB interface {
	db.Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

func record(ctx context.Context, q db.Querier, actor audit.Actor, action audit.Action, id string, changed []string) error {
	return audit.NewStore(q).Record(ctx, audit.Entry{
		Action:        action,
		Outcome:       audit.OutcomeSuccess,
		Actor:         actor,
		Resource:      audit.Resource{Type: ResourceType, ID: id},
		ChangedFields: changed,
	}.WithRequest(ctx))
}

// SetPlacementNotes sets the placement notes of the artifact id on behalf of
// actor, as Store.SetPlacementNotes does, and records the change in the audit
// log. A change that changes nothing is not recorded.
func SetPlacementNotes(ctx context.Context, d DB, actor audit.Actor, id, notes string) (Artifact, error) {
	var a Artifact
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		var (
			changed bool
			err     error
		)
		if a, changed, err = NewStore(tx).SetPlacementNotes(ctx, id, notes); err != nil || !changed {
			return err
		}
		return record(ctx, tx, actor, audit.ActionArtifactUpdate, id, []string{FieldPlacementNotes})
	})
	if err != nil {
		return Artifact{}, fmt.Errorf("set placement notes of artifact: %w", err)
	}
	return a, nil
}

// Delete deletes the artifact id on behalf of actor and records it in the
// audit log. It returns ErrNotFound if there is none.
func Delete(ctx context.Context, d DB, actor audit.Actor, id string) error {
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		if err := NewStore(tx).Delete(ctx, id); err != nil {
			return err
		}
		return record(ctx, tx, actor, audit.ActionArtifactDelete, id, nil)
	})
	if err != nil {
		return fmt.Errorf("delete artifact: %w", err)
	}
	return nil
}
