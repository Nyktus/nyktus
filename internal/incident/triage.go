// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package incident

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/platform/db"
)

// Errors of the triage and of the lists.
var (
	ErrNotFound = errors.New("incident not found")
	// ErrStatusBackward means that a change would move the status of an
	// incident back, such as opening a closed incident again.
	ErrStatusBackward  = errors.New("the status of an incident only moves forward")
	ErrInvalidStatus   = errors.New("invalid incident status")
	ErrInvalidSeverity = errors.New("invalid severity")
	ErrInvalidNotes    = errors.New("invalid incident notes")
	// ErrInvalidTechniques means that the techniques are not distinct
	// identifiers of the bundled version of ATT&CK, or too many.
	ErrInvalidTechniques = errors.New("invalid techniques")
	// ErrInvalidPageSize is returned for a page size outside [1, MaxPageSize].
	ErrInvalidPageSize = errors.New("invalid page size")
)

// Limits of the fields of an incident, as the database enforces them.
const (
	MaxNotesLength = 10000
	MaxPageSize    = 200
)

// Names of the fields of a triage, as recorded in the audit log.
const (
	FieldStatus             = "status"
	FieldNotes              = "notes"
	FieldSeverityOverride   = "severity_override"
	FieldTechniquesOverride = "techniques_override"
)

// Incident is an incident with its triage.
type Incident struct {
	ID           string
	ResourceType string
	ResourceID   string
	Status       Status
	// EventSeverity and EventTechniques are what the events suggest: the
	// highest severity and every technique of them.
	EventSeverity   Severity
	EventTechniques []string
	// SeverityOverride and TechniquesOverride are the judgment of an analyst,
	// or nil if there is none.
	SeverityOverride   *Severity
	TechniquesOverride []string
	Notes              string
	EventCount         int
	FirstEventAt       time.Time
	LastEventAt        time.Time
	OpenedAt           time.Time
	AcknowledgedAt     *time.Time
	ClosedAt           *time.Time
}

// Severity returns the severity of the incident: the override of an analyst,
// or what the events suggest.
func (i Incident) Severity() Severity {
	if i.SeverityOverride != nil {
		return *i.SeverityOverride
	}
	return i.EventSeverity
}

// Techniques returns the techniques of the incident: the override of an
// analyst, or those of the events.
func (i Incident) Techniques() []string {
	if i.TechniquesOverride != nil {
		return i.TechniquesOverride
	}
	return i.EventTechniques
}

// Change describes the triage of an incident. A nil field stays as it is.
type Change struct {
	Status *Status
	Notes  *string
	// SeverityOverride sets the override of the severity if SetSeverityOverride
	// is true; nil removes it.
	SeverityOverride    *Severity
	SetSeverityOverride bool
	// TechniquesOverride sets the override of the techniques if
	// SetTechniquesOverride is true; nil removes it, and an empty list states
	// that the incident suggests no technique.
	TechniquesOverride    []string
	SetTechniquesOverride bool
}

// IsEmpty reports whether c changes nothing.
func (c Change) IsEmpty() bool {
	return c.Status == nil && c.Notes == nil && !c.SetSeverityOverride && !c.SetTechniquesOverride
}

func (c Change) validate() error {
	if c.Status != nil && !slices.Contains(Statuses, *c.Status) {
		return ErrInvalidStatus
	}
	if c.Notes != nil {
		if err := ValidateNotes(*c.Notes); err != nil {
			return err
		}
	}
	if c.SetSeverityOverride && c.SeverityOverride != nil && !slices.Contains(Severities, *c.SeverityOverride) {
		return ErrInvalidSeverity
	}
	if c.SetTechniquesOverride && c.TechniquesOverride != nil {
		if err := honeytoken.ValidateTechniques(c.TechniquesOverride); err != nil {
			return ErrInvalidTechniques
		}
	}
	return nil
}

// ValidateNotes accepts notes of up to MaxNotesLength characters. They may span
// several lines and contain tabs and every kind of space; other control and
// format characters are rejected, as in the notes of a honeytoken.
func ValidateNotes(s string) error {
	if utf8.RuneCountInString(s) > MaxNotesLength || !utf8.ValidString(s) {
		return ErrInvalidNotes
	}
	for _, r := range s {
		if !unicode.IsGraphic(r) && r != '\n' && r != '\r' && r != '\t' {
			return ErrInvalidNotes
		}
	}
	return nil
}

// uuidPattern matches the text form of a UUID, in which PostgreSQL returns
// identifiers. Other forms that PostgreSQL accepts are rejected, so that an
// identifier names an incident in one form only.
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidID reports whether s is an identifier in the form that the API returns.
func ValidID(s string) bool { return uuidPattern.MatchString(s) }

// SQLSTATE codes mapped by the triage.
const (
	checkViolation            = "23514"
	invalidTextRepresentation = "22P02"
)

// constraintErrors maps the checks of the schema to the errors of the
// validation, in case the rules of both ever differ.
var constraintErrors = map[string]error{
	"incidents_status_forward":            ErrStatusBackward,
	"incidents_status_check":              ErrInvalidStatus,
	"incidents_severity_override_check":   ErrInvalidSeverity,
	"incidents_notes_check":               ErrInvalidNotes,
	"incidents_techniques_override_check": ErrInvalidTechniques,
}

func mapWriteError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == checkViolation {
		if mapped, ok := constraintErrors[pgErr.ConstraintName]; ok {
			return mapped
		}
	}
	return err
}

// notFound reports whether err means that no incident has the identifier. An
// identifier that is not a UUID cannot belong to one.
func notFound(err error) bool {
	var pgErr *pgconn.PgError
	return errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == invalidTextRepresentation)
}

const incidentColumns = `id, resource_type, resource_id, status, severity, techniques, severity_override,
	techniques_override, notes, event_count, first_event_at, last_event_at, opened_at, acknowledged_at, closed_at`

func scanIncident(row pgx.Row) (Incident, error) {
	var i Incident
	err := row.Scan(&i.ID, &i.ResourceType, &i.ResourceID, &i.Status, &i.EventSeverity, &i.EventTechniques,
		&i.SeverityOverride, &i.TechniquesOverride, &i.Notes, &i.EventCount, &i.FirstEventAt, &i.LastEventAt,
		&i.OpenedAt, &i.AcknowledgedAt, &i.ClosedAt)
	return i, err
}

// Cursor marks the position after the last incident or event of a page.
type Cursor struct {
	Time time.Time
	ID   string
}

// Filter narrows a list of incidents. Empty fields do not narrow it.
type Filter struct {
	Statuses []Status
	// ResourceID lists only the incidents of one resource.
	ResourceID string
}

// The filter of the status is a condition in every statement and always
// active: without a filter, it lists every status. The resource and the
// cursor, which the indexes serve, are conditions of statements of their own,
// so that a generic plan can seek into the index.
const (
	incidentsOrder = `
ORDER BY opened_at DESC, id DESC`
	listIncidentsNewest = `SELECT ` + incidentColumns + ` FROM public.incidents
WHERE status = ANY($1)` + incidentsOrder + `
LIMIT $2`
	listIncidentsAfter = `SELECT ` + incidentColumns + ` FROM public.incidents
WHERE (opened_at, id) < ($2, $3::uuid) AND status = ANY($1)` + incidentsOrder + `
LIMIT $4`
	listResourceIncidentsNewest = `SELECT ` + incidentColumns + ` FROM public.incidents
WHERE resource_id = $2 AND status = ANY($1)` + incidentsOrder + `
LIMIT $3`
	listResourceIncidentsAfter = `SELECT ` + incidentColumns + ` FROM public.incidents
WHERE resource_id = $2 AND (opened_at, id) < ($3, $4::uuid) AND status = ANY($1)` + incidentsOrder + `
LIMIT $5`
)

// ListIncidents returns up to size incidents that match f, from the most
// recently opened to the oldest, that come after the cursor after, or from the
// newest if after is nil. next is the cursor of the following page, or nil if
// there are no more incidents.
func ListIncidents(ctx context.Context, q db.Querier, f Filter, size int, after *Cursor) (list []Incident, next *Cursor, err error) {
	if size < 1 || size > MaxPageSize {
		return nil, nil, ErrInvalidPageSize
	}
	statuses := make([]string, 0, len(Statuses))
	for _, s := range Statuses {
		if len(f.Statuses) == 0 || slices.Contains(f.Statuses, s) {
			statuses = append(statuses, string(s))
		}
	}
	// One more incident than requested tells whether another page follows.
	var rows pgx.Rows
	switch {
	case f.ResourceID == "" && after == nil:
		rows, err = q.Query(ctx, listIncidentsNewest, statuses, size+1)
	case f.ResourceID == "":
		rows, err = q.Query(ctx, listIncidentsAfter, statuses, after.Time, after.ID, size+1)
	case after == nil:
		rows, err = q.Query(ctx, listResourceIncidentsNewest, statuses, f.ResourceID, size+1)
	default:
		rows, err = q.Query(ctx, listResourceIncidentsAfter, statuses, f.ResourceID, after.Time, after.ID, size+1)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("list incidents: %w", err)
	}
	list, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Incident, error) { return scanIncident(row) })
	if err != nil {
		return nil, nil, fmt.Errorf("list incidents: %w", err)
	}
	if len(list) > size {
		list = list[:size]
		last := list[size-1]
		next = &Cursor{Time: last.OpenedAt, ID: last.ID}
	}
	return list, next, nil
}

// GetIncident returns the incident id. It returns ErrNotFound if there is
// none.
func GetIncident(ctx context.Context, q db.Querier, id string) (Incident, error) {
	i, err := scanIncident(q.QueryRow(ctx, `SELECT `+incidentColumns+` FROM public.incidents WHERE id = $1`, id))
	if notFound(err) {
		return Incident{}, ErrNotFound
	}
	if err != nil {
		return Incident{}, fmt.Errorf("get incident %s: %w", id, err)
	}
	return i, nil
}

// Triage applies c to the incident id on behalf of actor and records the names
// of the changed fields in the audit log, in one transaction. A change that
// changes nothing is not recorded. It returns the incident after the change,
// ErrNotFound if there is none, and ErrStatusBackward if c would move its
// status back.
//
// The incident is locked until the end of the transaction, so that concurrent
// changes cannot interleave between the comparison with the current values and
// the change, which would record wrong fields in the audit log. The triage
// locks only the incident; the worker locks a job before the incident, so the
// two cannot wait for each other.
func Triage(ctx context.Context, d DB, actor audit.Actor, id string, c Change) (Incident, error) {
	if err := c.validate(); err != nil {
		return Incident{}, err
	}
	var updated Incident
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		current, err := scanIncident(tx.QueryRow(ctx, `SELECT `+incidentColumns+` FROM public.incidents WHERE id = $1 FOR UPDATE`, id))
		if notFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("lock incident %s: %w", id, err)
		}

		updated = current
		changed, err := apply(&updated, c)
		if err != nil || len(changed) == 0 {
			return err
		}
		updated, err = scanIncident(tx.QueryRow(ctx, `
UPDATE public.incidents
SET status = $2, notes = $3, severity_override = $4, techniques_override = $5
WHERE id = $1
RETURNING `+incidentColumns, id, updated.Status, updated.Notes, updated.SeverityOverride, updated.TechniquesOverride))
		if err != nil {
			return fmt.Errorf("triage incident %s: %w", id, mapWriteError(err))
		}
		return audit.NewStore(tx).Record(ctx, audit.Entry{
			Action:        audit.ActionIncidentUpdate,
			Outcome:       audit.OutcomeSuccess,
			Actor:         actor,
			Resource:      audit.Resource{Type: resourceType, ID: id},
			ChangedFields: changed,
		}.WithRequest(ctx))
	})
	if err != nil {
		return Incident{}, err
	}
	return updated, nil
}

// resourceType names incidents in the audit log.
const resourceType = "incident"

// apply applies c to i and returns the names of the fields whose values
// changed.
func apply(i *Incident, c Change) ([]string, error) {
	var changed []string
	if c.Status != nil && *c.Status != i.Status {
		if slices.Index(Statuses, *c.Status) < slices.Index(Statuses, i.Status) {
			return nil, ErrStatusBackward
		}
		i.Status = *c.Status
		changed = append(changed, FieldStatus)
	}
	if c.Notes != nil && *c.Notes != i.Notes {
		i.Notes = *c.Notes
		changed = append(changed, FieldNotes)
	}
	if c.SetSeverityOverride {
		if (c.SeverityOverride == nil) != (i.SeverityOverride == nil) ||
			(c.SeverityOverride != nil && *c.SeverityOverride != *i.SeverityOverride) {
			changed = append(changed, FieldSeverityOverride)
		}
		i.SeverityOverride = c.SeverityOverride
	}
	if c.SetTechniquesOverride {
		if (c.TechniquesOverride == nil) != (i.TechniquesOverride == nil) || !slices.Equal(c.TechniquesOverride, i.TechniquesOverride) {
			changed = append(changed, FieldTechniquesOverride)
		}
		i.TechniquesOverride = slices.Clone(c.TechniquesOverride)
	}
	return changed, nil
}
