// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package honeypot manages honeypots: network services that a sensor emulates
// in the monitored environment, each with a secret of its own that the sensor
// authenticates with.
//
// Honeypots are part of the inventory, the most sensitive data of Nyktus:
// whoever reads it can avoid every decoy. Only the console manages them. The
// internet-facing trigger role never imports this package.
package honeypot

import (
	"errors"
	"log/slog"
	"slices"
	"time"

	"nyktus.org/nyktus/internal/attack"
	"nyktus.org/nyktus/internal/platform/text"
	"nyktus.org/nyktus/internal/severity"
)

// Service is the network service that a honeypot emulates.
type Service string

// Services of honeypots.
const (
	ServiceSSH      Service = "ssh"
	ServiceTelnet   Service = "telnet"
	ServicePostgres Service = "postgres"
	ServiceLDAP     Service = "ldap"
)

// ResourceType names honeypots where other records refer to them, such as
// audit entries.
const ResourceType = "honeypot"

// Services lists every service, in the order in which documentation names
// them.
var Services = []Service{ServiceSSH, ServiceTelnet, ServicePostgres, ServiceLDAP}

// Valid reports whether s is a known service.
func (s Service) Valid() bool {
	return slices.Contains(Services, s)
}

// defaultSeverity is the severity of a honeypot of each service unless another
// one is chosen. Every honeypot answers whoever connects, including the
// scanners of the own team, so none starts above medium.
var defaultSeverity = map[Service]severity.Level{
	ServiceSSH:      severity.Medium,
	ServiceTelnet:   severity.Medium,
	ServicePostgres: severity.Medium,
	ServiceLDAP:     severity.Medium,
}

// DefaultSeverity returns the severity of a honeypot of service s unless
// another one is chosen, or "" for an unknown service.
func (s Service) DefaultSeverity() severity.Level {
	return defaultSeverity[s]
}

// Status tells whether a sensor reports for a honeypot.
type Status string

// States of a honeypot.
const (
	// StatusNever means that no sensor has reported with the current secret.
	StatusNever Status = "never"
	// StatusOnline means that a sensor reported within OfflineAfter.
	StatusOnline Status = "online"
	// StatusOffline means that the last report is older than OfflineAfter.
	StatusOffline Status = "offline"
)

// Statuses lists every status.
var Statuses = []Status{StatusNever, StatusOnline, StatusOffline}

// OfflineAfter is how long after its last report a honeypot counts as
// offline: three intervals of the heartbeat of a sensor, which reports every
// five minutes, so that a single lost or late heartbeat never makes it
// offline. The store evaluates it in SQL against the clock of the database.
const OfflineAfter = 15 * time.Minute

// Limits of the fields of a honeypot, as the database enforces them.
const (
	MaxNameLength  = 100
	MaxNotesLength = 2000
	MaxTechniques  = 20
)

// Names of the fields of a change, as recorded in the audit log.
const (
	FieldName       = "name"
	FieldNotes      = "notes"
	FieldEnabled    = "enabled"
	FieldTechniques = "techniques"
	FieldSeverity   = "severity"
	FieldScenarioID = "scenario_id"
	// FieldSecret records that the secret was replaced.
	FieldSecret = "secret"
)

// Validation errors.
var (
	ErrInvalidService    = errors.New("invalid honeypot service")
	ErrInvalidName       = errors.New("invalid honeypot name")
	ErrInvalidNotes      = errors.New("invalid honeypot notes")
	ErrInvalidTechniques = errors.New("invalid ATT&CK techniques")
	// ErrInvalidSeverity means that a severity is unknown or info, which only
	// an analyst gives an incident.
	ErrInvalidSeverity = errors.New("invalid honeypot severity")
)

// Honeypot is a stored honeypot. It never holds the secret, which only its
// creation and its replacement return.
type Honeypot struct {
	ID      string
	Service Service
	Name    string
	Notes   string
	Enabled bool
	// Techniques are the identifiers of the ATT&CK techniques that an event
	// suggests, in addition to those of the kind of event.
	Techniques []string
	// Severity is the severity that its events receive.
	Severity severity.Level
	// ScenarioID is the scenario that the honeypot belongs to, or nil if it
	// stands alone.
	ScenarioID *string
	// LastSeenAt is when a sensor last reported for the honeypot with its
	// current secret, or nil if none has.
	LastSeenAt *time.Time
	// SensorVersion is the version that the sensor named, or nil.
	SensorVersion *string
	// Status is derived from LastSeenAt by the database.
	Status    Status
	CreatedAt time.Time
	UpdatedAt time.Time
}

// LogValue names the honeypot by its identifier and service. Its name and
// notes are inventory and stay out of logs.
func (h Honeypot) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", h.ID), slog.String("service", string(h.Service)))
}

// Secret is the secret of a honeypot in clear text, which the sensor presents.
// It is returned when it is created or replaced and to those who may change
// honeypots, and never logged.
type Secret string

// String keeps the value out of formatted output.
func (Secret) String() string { return "[redacted]" }

// GoString keeps the value out of %#v.
func (Secret) GoString() string { return "[redacted]" }

// LogValue keeps the value out of logs.
func (Secret) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// MarshalJSON keeps the value out of JSON, such as a log that encodes a struct
// that holds it. The response that shows the secret converts it explicitly.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

// Created is a honeypot with its secret, as its creation, the replacement of
// its secret and a later read of it return it.
type Created struct {
	Honeypot
	Secret Secret
}

// Spec describes a honeypot to create.
type Spec struct {
	Service    Service
	Name       string
	Notes      string
	Enabled    bool
	Techniques []string
	// Severity is the severity of the honeypot, or nil for the default of its
	// service.
	Severity *severity.Level
	// ScenarioID is the scenario the honeypot joins when it is created, or
	// empty for one that stands alone.
	ScenarioID string
}

func (s Spec) validate() error {
	if !s.Service.Valid() {
		return ErrInvalidService
	}
	if err := ValidateName(s.Name); err != nil {
		return err
	}
	if err := ValidateNotes(s.Notes); err != nil {
		return err
	}
	if s.Severity != nil && !s.Severity.IsSuggested() {
		return ErrInvalidSeverity
	}
	return ValidateTechniques(s.Techniques)
}

// Change describes changes to a honeypot. A nil field stays as it is. The
// service never changes: the sensor is configured for it.
type Change struct {
	Name    *string
	Notes   *string
	Enabled *bool
	// Techniques replace the techniques of the honeypot.
	Techniques []string
	// SetTechniques reports whether Techniques is part of the change, so that
	// an empty list can remove every technique.
	SetTechniques bool
	// Severity replaces the severity, which applies to later events only.
	Severity *severity.Level
}

// IsEmpty reports whether c changes nothing.
func (c Change) IsEmpty() bool {
	return c.Name == nil && c.Notes == nil && c.Enabled == nil && !c.SetTechniques && c.Severity == nil
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
	if c.Severity != nil && !c.Severity.IsSuggested() {
		return ErrInvalidSeverity
	}
	if c.SetTechniques {
		return ValidateTechniques(c.Techniques)
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

// ValidateTechniques accepts up to MaxTechniques distinct identifiers of
// techniques of the bundled version of ATT&CK.
func ValidateTechniques(ids []string) error {
	if len(ids) > MaxTechniques {
		return ErrInvalidTechniques
	}
	for i, id := range ids {
		if _, ok := attack.Lookup(id); !ok || slices.Contains(ids[:i], id) {
			return ErrInvalidTechniques
		}
	}
	return nil
}
