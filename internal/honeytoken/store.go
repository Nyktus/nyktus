// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeytoken

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/platform/db"
)

// Errors of the store.
var (
	ErrNotFound = errors.New("honeytoken not found")
	// ErrScenarioNotFound means that the scenario that a honeytoken is to be
	// assigned to does not exist.
	ErrScenarioNotFound = errors.New("scenario not found")
	// ErrInOtherScenario means that a honeytoken belongs to another scenario
	// than the one it is to be assigned to.
	ErrInOtherScenario = errors.New("honeytoken belongs to another scenario")
	// ErrInvalidPageSize is returned for a page size outside [1, MaxPageSize].
	ErrInvalidPageSize = errors.New("invalid page size")
)

// MaxPageSize is the largest page that List returns.
const MaxPageSize = 200

// constraintErrors maps the checks of the schema to the errors of the
// validation, in case the rules of both ever differ.
var constraintErrors = map[string]error{
	"honeytokens_type_check":         ErrInvalidType,
	"honeytokens_name_check":         ErrInvalidName,
	"honeytokens_notes_check":        ErrInvalidNotes,
	"honeytokens_redirect_url_check": ErrInvalidRedirectURL,
	"honeytokens_techniques_check":   ErrInvalidTechniques,
	"honeytokens_severity_check":     ErrInvalidSeverity,
}

func mapWriteError(err error) error {
	if mapped, ok := constraintErrors[db.Violation(err, db.CheckViolation)]; ok {
		return mapped
	}
	return err
}

// Store persists honeytokens in PostgreSQL.
type Store struct {
	db db.Querier
}

// NewStore returns a Store that runs its queries on q, a connection pool or a
// transaction.
func NewStore(q db.Querier) *Store {
	if q == nil {
		panic("honeytoken: nil querier")
	}
	return &Store{db: q}
}

const columns = `id, type, name, notes, enabled, redirect_url, techniques, severity, trigger_value, scenario_id,
created_at, updated_at`

func scan(row pgx.Row) (Honeytoken, error) {
	var h Honeytoken
	err := row.Scan(&h.ID, &h.Type, &h.Name, &h.Notes, &h.Enabled, &h.RedirectURL, &h.Techniques, &h.Severity,
		&h.TriggerValue, &h.ScenarioID, &h.CreatedAt, &h.UpdatedAt)
	return h, err
}

// Create validates spec and stores a new honeytoken with a new trigger value.
// The fields are validated before the insert, although the schema checks the
// same rules, so that the stored techniques exist in the bundled version of
// ATT&CK and a failing row never reaches the log of the database.
func (s *Store) Create(ctx context.Context, spec Spec) (Honeytoken, error) {
	if err := spec.validate(); err != nil {
		return Honeytoken{}, err
	}
	techniques := spec.Techniques
	if techniques == nil {
		techniques = []string{}
	}
	level := spec.Type.DefaultSeverity()
	if spec.Severity != nil {
		level = *spec.Severity
	}
	h, err := scan(s.db.QueryRow(ctx, `
INSERT INTO honeytokens (type, name, notes, enabled, redirect_url, techniques, severity, trigger_value)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING `+columns, spec.Type, spec.Name, spec.Notes, spec.Enabled, spec.RedirectURL, techniques, level,
		newTriggerValue()))
	if err != nil {
		return Honeytoken{}, fmt.Errorf("create honeytoken: %w", mapWriteError(err))
	}
	return h, nil
}

// Get returns the honeytoken id. It returns ErrNotFound if there is none.
func (s *Store) Get(ctx context.Context, id string) (Honeytoken, error) {
	h, err := scan(s.db.QueryRow(ctx, `SELECT `+columns+` FROM honeytokens WHERE id = $1`, id))
	if db.NotFound(err) {
		return Honeytoken{}, ErrNotFound
	}
	if err != nil {
		return Honeytoken{}, fmt.Errorf("get honeytoken %s: %w", id, err)
	}
	return h, nil
}

// Cursor marks the position after the last honeytoken of a page.
type Cursor struct {
	CreatedAt time.Time
	ID        string
}

// Filter narrows a list to honeytokens of a type, state or scenario. A nil
// or empty field does not narrow it.
type Filter struct {
	Type    *Type
	Enabled *bool
	// ScenarioID lists only the honeytokens of one scenario.
	ScenarioID string
}

// The filters of type and state are conditions in every statement and always
// active: without a filter, they list every value. A condition that is active
// only sometimes would keep a generic plan from seeking into the index; the
// scenario and the cursor, which the indexes serve, are therefore conditions
// of statements of their own.
const (
	listOrder = `
ORDER BY created_at DESC, id DESC`
	listNewest = `SELECT ` + columns + ` FROM honeytokens
WHERE type = ANY($1) AND enabled = ANY($2)` + listOrder + `
LIMIT $3`
	listAfter = `SELECT ` + columns + ` FROM honeytokens
WHERE (created_at, id) < ($3, $4::uuid) AND type = ANY($1) AND enabled = ANY($2)` + listOrder + `
LIMIT $5`
	listScenarioNewest = `SELECT ` + columns + ` FROM honeytokens
WHERE scenario_id = $3 AND type = ANY($1) AND enabled = ANY($2)` + listOrder + `
LIMIT $4`
	listScenarioAfter = `SELECT ` + columns + ` FROM honeytokens
WHERE scenario_id = $3 AND (created_at, id) < ($4, $5::uuid) AND type = ANY($1) AND enabled = ANY($2)` +
		listOrder + `
LIMIT $6`
)

// List returns up to size honeytokens that match f, from the newest to the
// oldest, that come after the cursor after, or from the newest if after is nil.
// next is the cursor of the following page, or nil if there are no more
// honeytokens.
func (s *Store) List(ctx context.Context, f Filter, size int, after *Cursor) (list []Honeytoken, next *Cursor, err error) {
	if size < 1 || size > MaxPageSize {
		return nil, nil, ErrInvalidPageSize
	}
	var types []string
	for _, t := range Types {
		if f.Type == nil || *f.Type == t {
			types = append(types, string(t))
		}
	}
	enabled := []bool{true, false}
	if f.Enabled != nil {
		enabled = []bool{*f.Enabled}
	}
	// One more honeytoken than requested tells whether another page follows.
	var rows pgx.Rows
	switch {
	case f.ScenarioID == "" && after == nil:
		rows, err = s.db.Query(ctx, listNewest, types, enabled, size+1)
	case f.ScenarioID == "":
		rows, err = s.db.Query(ctx, listAfter, types, enabled, after.CreatedAt, after.ID, size+1)
	case after == nil:
		rows, err = s.db.Query(ctx, listScenarioNewest, types, enabled, f.ScenarioID, size+1)
	default:
		rows, err = s.db.Query(ctx, listScenarioAfter, types, enabled, f.ScenarioID, after.CreatedAt, after.ID, size+1)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("list honeytokens: %w", err)
	}
	list, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Honeytoken, error) { return scan(row) })
	if err != nil {
		return nil, nil, fmt.Errorf("list honeytokens: %w", err)
	}
	if len(list) > size {
		list = list[:size]
		last := list[size-1]
		next = &Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	return list, next, nil
}

// Update validates c and applies it to the honeytoken id. It returns the
// honeytoken after the change and the names of the fields whose values changed,
// which is empty if c changes nothing. It returns ErrNotFound if there is no
// such honeytoken and ErrRedirectNotAllowed if c sets a redirect for a type that
// is not clicked.
//
// Update must run in a transaction: it locks the honeytoken until the end of
// the transaction, so that concurrent changes cannot interleave between the
// comparison with the current values and the change, which would record wrong
// fields in the audit log.
func (s *Store) Update(ctx context.Context, id string, c Change) (Honeytoken, []string, error) {
	if err := c.validate(); err != nil {
		return Honeytoken{}, nil, err
	}
	current, err := scan(s.db.QueryRow(ctx, `SELECT `+columns+` FROM honeytokens WHERE id = $1 FOR UPDATE`, id))
	if db.NotFound(err) {
		return Honeytoken{}, nil, ErrNotFound
	}
	if err != nil {
		return Honeytoken{}, nil, fmt.Errorf("lock honeytoken %s: %w", id, err)
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
	if c.Enabled != nil && *c.Enabled != current.Enabled {
		updated.Enabled = *c.Enabled
		changed = append(changed, FieldEnabled)
	}
	if c.RedirectURL != nil {
		if *c.RedirectURL != "" && current.Type != TypeWebURL {
			return Honeytoken{}, nil, ErrRedirectNotAllowed
		}
		updated.RedirectURL = nil
		if *c.RedirectURL != "" {
			updated.RedirectURL = c.RedirectURL
		}
		if (updated.RedirectURL == nil) != (current.RedirectURL == nil) ||
			(updated.RedirectURL != nil && *updated.RedirectURL != *current.RedirectURL) {
			changed = append(changed, FieldRedirectURL)
		}
	}
	if c.SetTechniques {
		updated.Techniques = slices.Clone(c.Techniques)
		if updated.Techniques == nil {
			updated.Techniques = []string{}
		}
		if !slices.Equal(updated.Techniques, current.Techniques) {
			changed = append(changed, FieldTechniques)
		}
	}
	if c.Severity != nil && *c.Severity != current.Severity {
		updated.Severity = *c.Severity
		changed = append(changed, FieldSeverity)
	}
	if len(changed) == 0 {
		return current, nil, nil
	}

	h, err := scan(s.db.QueryRow(ctx, `
UPDATE honeytokens SET
	name = $2,
	notes = $3,
	enabled = $4,
	redirect_url = $5,
	techniques = $6,
	severity = $7,
	updated_at = clock_timestamp()
WHERE id = $1
RETURNING `+columns, id, updated.Name, updated.Notes, updated.Enabled, updated.RedirectURL, updated.Techniques,
		updated.Severity))
	if err != nil {
		return Honeytoken{}, nil, fmt.Errorf("update honeytoken %s: %w", id, mapWriteError(err))
	}
	return h, changed, nil
}

// Delete deletes the honeytoken id. It returns ErrNotFound if there is none.
func (s *Store) Delete(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM honeytokens WHERE id = $1`, id)
	if db.NotFound(err) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("delete honeytoken %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetScenario assigns the honeytoken id to the scenario scenarioID, or
// detaches it from its scenario if scenarioID is empty. It returns the
// honeytoken after the change and whether it changed: a honeytoken that is
// already where it is to be stays as it is. It returns ErrNotFound if there is
// no such honeytoken, ErrScenarioNotFound if there is no such scenario, and
// ErrInOtherScenario if the honeytoken belongs to another scenario, which it
// must leave first, so that nothing takes a honeytoken from a scenario by
// mistake.
//
// SetScenario must run in a transaction. It locks the scenario before the
// honeytoken, as the deletion of a scenario does, so that both cannot wait
// for each other: the scenario with a lock that keeps it from being deleted
// meanwhile, the honeytoken until the end of the transaction.
func (s *Store) SetScenario(ctx context.Context, id, scenarioID string) (Honeytoken, bool, error) {
	// A missing honeytoken is reported first, as for any other change of it.
	// Reading it takes no lock, so the order of the locks below holds.
	if _, err := s.Get(ctx, id); err != nil {
		return Honeytoken{}, false, err
	}
	if scenarioID != "" {
		var found bool
		err := s.db.QueryRow(ctx, `SELECT true FROM scenarios WHERE id = $1 FOR KEY SHARE`, scenarioID).Scan(&found)
		if db.NotFound(err) {
			return Honeytoken{}, false, ErrScenarioNotFound
		}
		if err != nil {
			return Honeytoken{}, false, fmt.Errorf("lock scenario %s: %w", scenarioID, err)
		}
	}
	current, err := scan(s.db.QueryRow(ctx, `SELECT `+columns+` FROM honeytokens WHERE id = $1 FOR UPDATE`, id))
	if db.NotFound(err) {
		return Honeytoken{}, false, ErrNotFound
	}
	if err != nil {
		return Honeytoken{}, false, fmt.Errorf("lock honeytoken %s: %w", id, err)
	}
	switch {
	case scenarioID == "" && current.ScenarioID == nil,
		current.ScenarioID != nil && *current.ScenarioID == scenarioID:
		return current, false, nil
	case scenarioID != "" && current.ScenarioID != nil:
		return Honeytoken{}, false, ErrInOtherScenario
	}

	var target *string
	if scenarioID != "" {
		target = &scenarioID
	}
	h, err := scan(s.db.QueryRow(ctx, `
UPDATE honeytokens SET scenario_id = $2, updated_at = clock_timestamp()
WHERE id = $1
RETURNING `+columns, id, target))
	if err != nil {
		return Honeytoken{}, false, fmt.Errorf("set scenario of honeytoken %s: %w", id, err)
	}
	return h, true, nil
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

// Create creates a honeytoken on behalf of actor and records it in the audit
// log.
func Create(ctx context.Context, d DB, actor audit.Actor, spec Spec) (Honeytoken, error) {
	var h Honeytoken
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		var err error
		if h, err = NewStore(tx).Create(ctx, spec); err != nil {
			return err
		}
		return record(ctx, tx, actor, audit.ActionHoneytokenCreate, h.ID, nil)
	})
	if err != nil {
		return Honeytoken{}, fmt.Errorf("create honeytoken: %w", err)
	}
	return h, nil
}

// Update applies c to the honeytoken id on behalf of actor, as Store.Update
// does, and records the names of the changed fields in the audit log. A change
// that changes nothing is not recorded.
func Update(ctx context.Context, d DB, actor audit.Actor, id string, c Change) (Honeytoken, error) {
	var h Honeytoken
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		var (
			changed []string
			err     error
		)
		if h, changed, err = NewStore(tx).Update(ctx, id, c); err != nil || len(changed) == 0 {
			return err
		}
		return record(ctx, tx, actor, audit.ActionHoneytokenUpdate, id, changed)
	})
	if err != nil {
		return Honeytoken{}, fmt.Errorf("update honeytoken: %w", err)
	}
	return h, nil
}

// SetScenario assigns the honeytoken id to the scenario scenarioID, or
// detaches it if scenarioID is empty, on behalf of actor, as Store.SetScenario
// does, and records the change in the audit log. A change that changes
// nothing is not recorded.
func SetScenario(ctx context.Context, d DB, actor audit.Actor, id, scenarioID string) (Honeytoken, error) {
	var h Honeytoken
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		var (
			changed bool
			err     error
		)
		if h, changed, err = NewStore(tx).SetScenario(ctx, id, scenarioID); err != nil || !changed {
			return err
		}
		return record(ctx, tx, actor, audit.ActionHoneytokenUpdate, id, []string{FieldScenarioID})
	})
	if err != nil {
		return Honeytoken{}, fmt.Errorf("set scenario of honeytoken: %w", err)
	}
	return h, nil
}

// Delete deletes the honeytoken id on behalf of actor and records it in the
// audit log. It returns ErrNotFound if there is none.
func Delete(ctx context.Context, d DB, actor audit.Actor, id string) error {
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		if err := NewStore(tx).Delete(ctx, id); err != nil {
			return err
		}
		return record(ctx, tx, actor, audit.ActionHoneytokenDelete, id, nil)
	})
	if err != nil {
		return fmt.Errorf("delete honeytoken: %w", err)
	}
	return nil
}
