// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenario

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/artifact"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/platform/db"
)

// Errors of the store.
var (
	ErrNotFound = errors.New("scenario not found")
	// ErrNoGuide means that a scenario was put together by hand and has no
	// guide.
	ErrNoGuide = errors.New("scenario has no guide")
	// ErrInvalidPageSize is returned for a page size outside [1, MaxPageSize].
	ErrInvalidPageSize = errors.New("invalid page size")
)

// MaxPageSize is the largest page that List returns.
const MaxPageSize = 200

// constraintErrors maps the checks of the schema to the errors of the
// validation, in case the rules of both ever differ.
var constraintErrors = map[string]error{
	"scenarios_name_check":              ErrInvalidName,
	"scenarios_notes_check":             ErrInvalidNotes,
	"scenarios_engage_activities_check": ErrInvalidEngageActivities,
}

func mapWriteError(err error) error {
	if mapped, ok := constraintErrors[db.Violation(err, db.CheckViolation)]; ok {
		return mapped
	}
	return err
}

// Store persists scenarios in PostgreSQL.
type Store struct {
	db db.Querier
}

// NewStore returns a Store that runs its queries on q, a connection pool or a
// transaction.
func NewStore(q db.Querier) *Store {
	if q == nil {
		panic("scenario: nil querier")
	}
	return &Store{db: q}
}

// columns are the columns of a scenario without its guide, which only a read
// of the guide needs.
const columns = `id, name, notes, engage_activities, deception_id, language, persona, created_at, updated_at`

func scan(row pgx.Row) (Scenario, error) {
	var s Scenario
	err := row.Scan(&s.ID, &s.Name, &s.Notes, &s.EngageActivities, &s.DeceptionID, &s.Language, &s.Persona,
		&s.CreatedAt, &s.UpdatedAt)
	return s, err
}

// Create validates spec and stores a new scenario. The fields are validated
// before the insert, although the schema checks the same rules, so that the
// stored activities exist in the bundled version of Engage and a failing row
// never reaches the log of the database.
func (s *Store) Create(ctx context.Context, spec Spec) (Scenario, error) {
	if err := spec.validate(); err != nil {
		return Scenario{}, err
	}
	activities := spec.EngageActivities
	if activities == nil {
		activities = []string{}
	}
	sc, err := scan(s.db.QueryRow(ctx, `
INSERT INTO scenarios (name, notes, engage_activities) VALUES ($1, $2, $3)
RETURNING `+columns, spec.Name, spec.Notes, activities))
	if err != nil {
		return Scenario{}, fmt.Errorf("create scenario: %w", mapWriteError(err))
	}
	return sc, nil
}

// createFromDeception stores a new scenario that applying the deception
// deceptionID creates, with what the application keeps. The caller validated
// every value.
func (s *Store) createFromDeception(ctx context.Context, spec Spec, deceptionID, lang string,
	persona map[string]string, guide []byte,
) (Scenario, error) {
	sc, err := scan(s.db.QueryRow(ctx, `
INSERT INTO scenarios (name, notes, engage_activities, deception_id, language, persona, guide)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING `+columns, spec.Name, spec.Notes, spec.EngageActivities, deceptionID, lang, persona, string(guide)))
	if err != nil {
		return Scenario{}, fmt.Errorf("create scenario of %s: %w", deceptionID, mapWriteError(err))
	}
	return sc, nil
}

// Guide returns the guide of the scenario id in the language it was applied
// in. It returns ErrNotFound if there is no such scenario and ErrNoGuide if
// the scenario was put together by hand.
func (s *Store) Guide(ctx context.Context, id string) (lang, guide string, err error) {
	var l, g *string
	err = s.db.QueryRow(ctx, `SELECT language, guide FROM scenarios WHERE id = $1`, id).Scan(&l, &g)
	if db.NotFound(err) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("get guide of scenario %s: %w", id, err)
	}
	if l == nil || g == nil {
		return "", "", ErrNoGuide
	}
	return *l, *g, nil
}

// Get returns the scenario id. It returns ErrNotFound if there is none.
func (s *Store) Get(ctx context.Context, id string) (Scenario, error) {
	sc, err := scan(s.db.QueryRow(ctx, `SELECT `+columns+` FROM scenarios WHERE id = $1`, id))
	if db.NotFound(err) {
		return Scenario{}, ErrNotFound
	}
	if err != nil {
		return Scenario{}, fmt.Errorf("get scenario %s: %w", id, err)
	}
	return sc, nil
}

// Cursor marks the position after the last scenario of a page.
type Cursor struct {
	CreatedAt time.Time
	ID        string
}

// The cursor, which the index serves, is a condition of a statement of its
// own, so that a generic plan can seek into the index.
const (
	listNewest = `SELECT ` + columns + ` FROM scenarios
ORDER BY created_at DESC, id DESC
LIMIT $1`
	listAfter = `SELECT ` + columns + ` FROM scenarios
WHERE (created_at, id) < ($1, $2::uuid)
ORDER BY created_at DESC, id DESC
LIMIT $3`
)

// List returns up to size scenarios from the newest to the oldest that come
// after the cursor after, or from the newest if after is nil. next is the
// cursor of the following page, or nil if there are no more scenarios.
func (s *Store) List(ctx context.Context, size int, after *Cursor) (list []Scenario, next *Cursor, err error) {
	if size < 1 || size > MaxPageSize {
		return nil, nil, ErrInvalidPageSize
	}
	// One more scenario than requested tells whether another page follows.
	var rows pgx.Rows
	if after == nil {
		rows, err = s.db.Query(ctx, listNewest, size+1)
	} else {
		rows, err = s.db.Query(ctx, listAfter, after.CreatedAt, after.ID, size+1)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("list scenarios: %w", err)
	}
	list, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Scenario, error) { return scan(row) })
	if err != nil {
		return nil, nil, fmt.Errorf("list scenarios: %w", err)
	}
	if len(list) > size {
		list = list[:size]
		last := list[size-1]
		next = &Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	return list, next, nil
}

// Update validates c and applies it to the scenario id. It returns the
// scenario after the change and the names of the fields whose values changed,
// which is empty if c changes nothing. It returns ErrNotFound if there is no
// such scenario.
//
// Update must run in a transaction: it locks the scenario until the end of the
// transaction, so that concurrent changes cannot interleave between the
// comparison with the current values and the change, which would record wrong
// fields in the audit log.
func (s *Store) Update(ctx context.Context, id string, c Change) (Scenario, []string, error) {
	if err := c.validate(); err != nil {
		return Scenario{}, nil, err
	}
	current, err := scan(s.db.QueryRow(ctx, `SELECT `+columns+` FROM scenarios WHERE id = $1 FOR NO KEY UPDATE`, id))
	if db.NotFound(err) {
		return Scenario{}, nil, ErrNotFound
	}
	if err != nil {
		return Scenario{}, nil, fmt.Errorf("lock scenario %s: %w", id, err)
	}

	updated := current
	var changed []string
	if c.Name != nil && *c.Name != current.Name {
		updated.Name = *c.Name
		changed = append(changed, FieldName)
	}
	if c.Notes != nil && *c.Notes != current.Notes {
		updated.Notes = *c.Notes
		changed = append(changed, FieldNotes)
	}
	if c.SetEngageActivities {
		updated.EngageActivities = slices.Clone(c.EngageActivities)
		if updated.EngageActivities == nil {
			updated.EngageActivities = []string{}
		}
		if !slices.Equal(updated.EngageActivities, current.EngageActivities) {
			changed = append(changed, FieldEngageActivities)
		}
	}
	if len(changed) == 0 {
		return current, nil, nil
	}

	sc, err := scan(s.db.QueryRow(ctx, `
UPDATE scenarios SET name = $2, notes = $3, engage_activities = $4, updated_at = clock_timestamp()
WHERE id = $1
RETURNING `+columns, id, updated.Name, updated.Notes, updated.EngageActivities))
	if err != nil {
		return Scenario{}, nil, fmt.Errorf("update scenario %s: %w", id, mapWriteError(err))
	}
	return sc, changed, nil
}

// Delete deletes the scenario id. Each kind of its resources is deleted with
// it if removals says RemovalDelete, or stays and stands alone with
// RemovalKeep. It returns what happened to the resources, and ErrNotFound if
// there is no such scenario.
//
// Delete must run in a transaction. It locks the scenario before its
// resources, as the assignment of a honeytoken does, so that a honeytoken
// that joins the scenario meanwhile either waits and then finds no scenario,
// or joined before and is removed with the others. Honeytokens are removed
// before artifacts, everywhere.
func (s *Store) Delete(ctx context.Context, id string, removals ResourceRemovals) (Removed, error) {
	if !removals.Honeytokens.Valid() || !removals.Artifacts.Valid() {
		return Removed{}, ErrInvalidRemoval
	}
	var found bool
	err := s.db.QueryRow(ctx, `SELECT true FROM scenarios WHERE id = $1 FOR UPDATE`, id).Scan(&found)
	if db.NotFound(err) {
		return Removed{}, ErrNotFound
	}
	if err != nil {
		return Removed{}, fmt.Errorf("lock scenario %s: %w", id, err)
	}

	var removed Removed
	ids, err := s.remove(ctx, "honeytokens", id, removals.Honeytokens)
	if err != nil {
		return Removed{}, err
	}
	if removals.Honeytokens == RemovalDelete {
		removed.DeletedHoneytokens = ids
	} else {
		removed.DetachedHoneytokens = ids
	}
	if ids, err = s.remove(ctx, "artifacts", id, removals.Artifacts); err != nil {
		return Removed{}, err
	}
	if removals.Artifacts == RemovalDelete {
		removed.DeletedArtifacts = ids
	} else {
		removed.DetachedArtifacts = ids
	}

	if _, err := s.db.Exec(ctx, `DELETE FROM scenarios WHERE id = $1`, id); err != nil {
		return Removed{}, fmt.Errorf("delete scenario %s: %w", id, err)
	}
	return removed, nil
}

// removeStatements delete or detach the resources of a scenario, by table.
var removeStatements = map[string]map[Removal]string{
	"honeytokens": {
		RemovalDelete: `DELETE FROM honeytokens WHERE scenario_id = $1 RETURNING id`,
		RemovalKeep: `UPDATE honeytokens SET scenario_id = NULL, updated_at = clock_timestamp()
WHERE scenario_id = $1
RETURNING id`,
	},
	"artifacts": {
		RemovalDelete: `DELETE FROM artifacts WHERE scenario_id = $1 RETURNING id`,
		RemovalKeep: `UPDATE artifacts SET scenario_id = NULL, updated_at = clock_timestamp()
WHERE scenario_id = $1
RETURNING id`,
	},
}

// remove deletes or detaches the resources in table of the scenario id and
// returns their identifiers.
func (s *Store) remove(ctx context.Context, table, id string, r Removal) ([]string, error) {
	rows, err := s.db.Query(ctx, removeStatements[table][r], id)
	if err != nil {
		return nil, fmt.Errorf("remove %s of scenario %s: %w", table, id, err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("remove %s of scenario %s: %w", table, id, err)
	}
	return ids, nil
}

// DB runs queries and starts transactions. A connection pool and a transaction
// implement it; in a transaction, Begin starts a savepoint.
type DB interface {
	db.Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

func record(ctx context.Context, q db.Querier, actor audit.Actor, action audit.Action, r audit.Resource, changed []string) error {
	return audit.NewStore(q).Record(ctx, audit.Entry{
		Action:        action,
		Outcome:       audit.OutcomeSuccess,
		Actor:         actor,
		Resource:      r,
		ChangedFields: changed,
	}.WithRequest(ctx))
}

func resource(id string) audit.Resource {
	return audit.Resource{Type: ResourceType, ID: id}
}

// Create creates a scenario on behalf of actor and records it in the audit
// log.
func Create(ctx context.Context, d DB, actor audit.Actor, spec Spec) (Scenario, error) {
	var sc Scenario
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		var err error
		if sc, err = NewStore(tx).Create(ctx, spec); err != nil {
			return err
		}
		return record(ctx, tx, actor, audit.ActionScenarioCreate, resource(sc.ID), nil)
	})
	if err != nil {
		return Scenario{}, fmt.Errorf("create scenario: %w", err)
	}
	return sc, nil
}

// Update applies c to the scenario id on behalf of actor, as Store.Update
// does, and records the names of the changed fields in the audit log. A change
// that changes nothing is not recorded.
func Update(ctx context.Context, d DB, actor audit.Actor, id string, c Change) (Scenario, error) {
	var sc Scenario
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		var (
			changed []string
			err     error
		)
		if sc, changed, err = NewStore(tx).Update(ctx, id, c); err != nil || len(changed) == 0 {
			return err
		}
		return record(ctx, tx, actor, audit.ActionScenarioUpdate, resource(id), changed)
	})
	if err != nil {
		return Scenario{}, fmt.Errorf("update scenario: %w", err)
	}
	return sc, nil
}

// Delete deletes the scenario id on behalf of actor, as Store.Delete does, and
// records it in the audit log together with every honeytoken and artifact
// that it deleted or detached, all in one transaction.
func Delete(ctx context.Context, d DB, actor audit.Actor, id string, removals ResourceRemovals) (Removed, error) {
	var removed Removed
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		var err error
		if removed, err = NewStore(tx).Delete(ctx, id, removals); err != nil {
			return err
		}
		for _, e := range []struct {
			ids     []string
			typ     string
			action  audit.Action
			changed []string
		}{
			{removed.DeletedHoneytokens, honeytoken.ResourceType, audit.ActionHoneytokenDelete, nil},
			{removed.DetachedHoneytokens, honeytoken.ResourceType, audit.ActionHoneytokenUpdate, []string{honeytoken.FieldScenarioID}},
			{removed.DeletedArtifacts, artifact.ResourceType, audit.ActionArtifactDelete, nil},
			{removed.DetachedArtifacts, artifact.ResourceType, audit.ActionArtifactUpdate, []string{artifact.FieldScenarioID}},
		} {
			for _, rid := range e.ids {
				if err := record(ctx, tx, actor, e.action, audit.Resource{Type: e.typ, ID: rid}, e.changed); err != nil {
					return err
				}
			}
		}
		return record(ctx, tx, actor, audit.ActionScenarioDelete, resource(id), nil)
	})
	if err != nil {
		return Removed{}, fmt.Errorf("delete scenario: %w", err)
	}
	return removed, nil
}
