// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package scenario manages scenarios: groups of decoys that tell one story,
// so that their events are correlated into one incident.
//
// A scenario holds the deceptions of the catalog that joined it, each with
// its guide, and a persona that belongs to the scenario and only grows: a key
// is added, a value that is there stays, so that the files that were rendered
// with it keep agreeing with those that follow. A deception joins a scenario
// at most once. Applying a deception creates a scenario with it; adding a
// deception or an artifact of the catalog extends an existing one. Every
// operation that extends a scenario locks it first.
//
// A honeytoken joins or leaves a scenario also through its own operation in
// package honeytoken. Name and notes of a scenario are inventory, like those
// of a honeytoken, and stay out of logs and the audit log. HTTP lives in
// scenarioapi.
package scenario

import (
	"errors"
	"log/slog"
	"slices"
	"time"

	"nyktus.org/nyktus/internal/engage"
	"nyktus.org/nyktus/internal/platform/text"
)

// ResourceType names scenarios where other records refer to them, such as
// audit entries and incidents.
const ResourceType = "scenario"

// Limits of the fields of a scenario, as the database enforces them.
const (
	MaxNameLength       = 100
	MaxNotesLength      = 2000
	MaxEngageActivities = 20
)

// MaxDeceptions is the most deceptions a scenario holds, as the database
// enforces it. artifact.MaxPerScenario is the limit of its artifacts.
const MaxDeceptions = 20

// Names of the fields of a change, as recorded in the audit log.
const (
	FieldName             = "name"
	FieldNotes            = "notes"
	FieldEngageActivities = "engage_activities"
	// FieldDeceptions and FieldPersona are the fields that adding a deception
	// or an artifact changes.
	FieldDeceptions = "deceptions"
	FieldPersona    = "persona"
)

// Validation errors.
var (
	ErrInvalidName             = errors.New("invalid scenario name")
	ErrInvalidNotes            = errors.New("invalid scenario notes")
	ErrInvalidEngageActivities = errors.New("invalid Engage activities")
	ErrInvalidRemoval          = errors.New("invalid removal of the resources of a scenario")
	ErrInvalidLanguage         = errors.New("invalid language")
	ErrInvalidSelection        = errors.New("invalid selection of artifacts")
)

// Scenario is a stored scenario.
type Scenario struct {
	ID    string
	Name  string
	Notes string
	// EngageActivities are the identifiers of the activities of MITRE Engage
	// that the scenario carries out.
	EngageActivities []string
	// Deceptions are the deceptions of the catalog that joined the scenario,
	// in the order they joined; none for a scenario put together by hand.
	Deceptions []AppliedDeception
	// Persona holds the values that the deceptions and artifacts of the
	// scenario were rendered with, by key. It is never nil.
	Persona   map[string]string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AppliedDeception is a deception that joined a scenario.
type AppliedDeception struct {
	// DeceptionID is the identifier of the deception in the catalog.
	DeceptionID string
	// Language is the language of its guide and of the names of its
	// honeytokens.
	Language  string
	CreatedAt time.Time
}

// Guide is the guide of a deception of a scenario, as it was rendered.
type Guide struct {
	DeceptionID string
	Language    string
	Content     string
}

// LogValue names the scenario by its identifier. Its name and notes are
// inventory and stay out of logs.
func (s Scenario) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", s.ID))
}

// Spec describes a scenario to create.
type Spec struct {
	Name             string
	Notes            string
	EngageActivities []string
}

func (s Spec) validate() error {
	if err := ValidateName(s.Name); err != nil {
		return err
	}
	if err := ValidateNotes(s.Notes); err != nil {
		return err
	}
	return ValidateEngageActivities(s.EngageActivities)
}

// Change describes changes to a scenario. A nil field stays as it is. Its
// deceptions and persona change only by adding to the scenario.
type Change struct {
	Name  *string
	Notes *string
	// EngageActivities replace the activities of the scenario.
	EngageActivities []string
	// SetEngageActivities reports whether EngageActivities is part of the
	// change, so that an empty list can remove every activity.
	SetEngageActivities bool
}

// IsEmpty reports whether c changes nothing.
func (c Change) IsEmpty() bool {
	return c.Name == nil && c.Notes == nil && !c.SetEngageActivities
}

func (c Change) validate() error {
	if c.Name != nil {
		if err := ValidateName(*c.Name); err != nil {
			return err
		}
	}
	if c.Notes != nil {
		if err := ValidateNotes(*c.Notes); err != nil {
			return err
		}
	}
	if c.SetEngageActivities {
		return ValidateEngageActivities(c.EngageActivities)
	}
	return nil
}

// ValidateName accepts a name of 1 to MaxNameLength characters, as
// text.ValidName describes.
func ValidateName(s string) error {
	if !text.ValidName(s, MaxNameLength) {
		return ErrInvalidName
	}
	return nil
}

// ValidateNotes accepts notes of up to MaxNotesLength characters, as
// text.ValidNotes describes.
func ValidateNotes(s string) error {
	if !text.ValidNotes(s, MaxNotesLength) {
		return ErrInvalidNotes
	}
	return nil
}

// ValidateEngageActivities accepts up to MaxEngageActivities distinct
// engagement activities of the bundled version of MITRE Engage. A scenario
// put together by hand may name none.
func ValidateEngageActivities(ids []string) error {
	if len(ids) > MaxEngageActivities {
		return ErrInvalidEngageActivities
	}
	for i, id := range ids {
		if _, ok := engage.Lookup(id); !ok || slices.Contains(ids[:i], id) {
			return ErrInvalidEngageActivities
		}
	}
	return nil
}

// Removal says what happens to the resources of a scenario that is deleted.
type Removal string

// Removals of the resources of a scenario.
const (
	// RemovalKeep detaches the resources: they stay and stand alone.
	RemovalKeep Removal = "keep"
	// RemovalDelete deletes the resources with the scenario.
	RemovalDelete Removal = "delete"
)

// Removals lists every removal.
var Removals = []Removal{RemovalKeep, RemovalDelete}

// Valid reports whether r is a known removal.
func (r Removal) Valid() bool {
	return slices.Contains(Removals, r)
}

// ResourceRemovals says what happens to each kind of resource of a scenario
// that is deleted.
type ResourceRemovals struct {
	Honeytokens Removal
	Honeypots   Removal
	Artifacts   Removal
}

// Removed lists the resources of a deleted scenario by what happened to them.
type Removed struct {
	// DeletedHoneytokens and DetachedHoneytokens are the identifiers of the
	// honeytokens that were deleted or detached.
	DeletedHoneytokens  []string
	DetachedHoneytokens []string
	// DeletedHoneypots and DetachedHoneypots are those of the honeypots.
	DeletedHoneypots  []string
	DetachedHoneypots []string
	// DeletedArtifacts and DetachedArtifacts are those of the artifacts.
	DeletedArtifacts  []string
	DetachedArtifacts []string
}
