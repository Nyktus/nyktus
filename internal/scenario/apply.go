// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenario

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/honeypot"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/platform/secretbox"
)

// ErrDNSNotConfigured means that a deception asks for a DNS honeytoken and its
// resources are to be created while the console knows no zone of the DNS role,
// so that the honeytoken would have no name to place.
var ErrDNSNotConfigured = errors.New("no zone of the DNS role")

// Join describes a deception that joins a scenario, whether the scenario is
// created for it or exists already.
type Join struct {
	Deception catalog.Deception
	// Language is the language of the names of the resources that are
	// created, one of catalog.Languages.
	Language string
	// CreateResources says that the honeytokens and honeypots that the
	// deception asks for are created and join the scenario. Without it, the
	// deception only joins and the administrator creates them as the guide
	// says.
	CreateResources bool
	// DNSConfigured says that the DNS role has a zone under which DNS
	// honeytokens are named, which creating one needs.
	DNSConfigured bool
	// Keys seal the secrets of the honeypots that are created. They are
	// needed only when the deception asks for honeypots and CreateResources
	// is set.
	Keys *secretbox.Keyring
}

func (j Join) validate() error {
	if !slices.Contains(catalog.Languages, j.Language) {
		return ErrInvalidLanguage
	}
	if j.CreateResources && !j.DNSConfigured && slices.ContainsFunc(j.Deception.Honeytokens, func(h catalog.HoneytokenSlot) bool {
		return h.Type == honeytoken.TypeDNS
	}) {
		return ErrDNSNotConfigured
	}
	return nil
}

// Application describes how a deception is applied: to a scenario of its own.
type Application struct {
	Join
	// Name and Notes are those of the new scenario.
	Name  string
	Notes string
}

// spec returns the scenario that applying the deception creates, with the
// activities of its story.
func (a Application) spec() Spec {
	return Spec{Name: a.Name, Notes: a.Notes, EngageActivities: slices.Clone(a.Deception.EngageActivities)}
}

func (a Application) validate() error {
	if err := a.spec().validate(); err != nil {
		return err
	}
	return a.Join.validate()
}

// Addition describes a deception that joins a scenario that exists.
type Addition struct {
	ScenarioID string
	Join
}

// Applied is what applying a deception or adding one to a scenario changed.
type Applied struct {
	// Scenario is the scenario after the change.
	Scenario Scenario
	// Honeytokens and Honeypots are those that were created; none unless the
	// resources were asked for. The secret of a honeypot is not among them: it
	// is read through its own operation.
	Honeytokens []honeytoken.Honeytoken
	Honeypots   []honeypot.Honeypot
}

// Apply applies a deception of the catalog on behalf of actor: it creates a
// scenario with the deception and, if asked for, the honeytokens and honeypots
// that the deception asks for, and records each in the audit log, all in one
// transaction, so that a failure leaves nothing behind. Nothing of the
// deception is stored but its identifier.
//
// Apply returns ErrInvalidLanguage and ErrDNSNotConfigured for what the
// application asks of the console.
func Apply(ctx context.Context, d DB, actor audit.Actor, a Application) (Applied, error) {
	if err := a.validate(); err != nil {
		return Applied{}, err
	}
	var applied Applied
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		sc, err := NewStore(tx).Create(ctx, a.spec())
		if err != nil {
			return err
		}
		if err := record(ctx, tx, actor, audit.ActionScenarioCreate, resource(sc.ID), nil); err != nil {
			return err
		}
		// The scenario is new and nobody else sees it, so joining is part of
		// its creation and has no audit entry of its own.
		applied, err = a.join(ctx, tx, actor, sc.ID, false)
		return err
	})
	if err != nil {
		return Applied{}, fmt.Errorf("apply deception %s: %w", a.Deception.ID, err)
	}
	return applied, nil
}

// AddDeception adds a deception of the catalog to the scenario on behalf of
// actor, as Apply does for a scenario of its own, and records it with the
// change of the scenario, all in one transaction.
//
// AddDeception returns ErrNotFound if there is no such scenario,
// ErrDeceptionAdded if the deception is part of it already, and the errors of
// Apply.
func AddDeception(ctx context.Context, d DB, actor audit.Actor, add Addition) (Applied, error) {
	if err := add.validate(); err != nil {
		return Applied{}, err
	}
	var applied Applied
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		var err error
		applied, err = add.join(ctx, tx, actor, add.ScenarioID, true)
		return err
	})
	if err != nil {
		return Applied{}, fmt.Errorf("add deception %s: %w", add.Deception.ID, err)
	}
	return applied, nil
}

// RemoveDeception ends the assignment of the deception to the scenario id on
// behalf of actor and records it. The honeytokens and honeypots that were
// created for it stay with the scenario, and so do its Engage activities: a
// slip of the hand costs neither. It returns ErrNotFound if there is no such
// scenario and ErrDeceptionNotAdded if the deception is not part of it.
func RemoveDeception(ctx context.Context, d DB, actor audit.Actor, id, deceptionID string) (Scenario, error) {
	var sc Scenario
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		scenarios := NewStore(tx)
		if _, err := scenarios.Lock(ctx, id); err != nil {
			return err
		}
		if err := scenarios.removeDeception(ctx, id, deceptionID); err != nil {
			return err
		}
		if err := scenarios.touch(ctx, id); err != nil {
			return err
		}
		if err := record(ctx, tx, actor, audit.ActionScenarioUpdate, resource(id), []string{FieldDeceptions}); err != nil {
			return err
		}
		var err error
		sc, err = scenarios.Get(ctx, id)
		return err
	})
	if err != nil {
		return Scenario{}, fmt.Errorf("remove deception: %w", err)
	}
	return sc, nil
}

// join adds the deception to the scenario id in the transaction tx. The
// scenario is locked first, as the deletion of a scenario does, so that
// everything that joins meanwhile waits. The honeytokens follow, then the
// honeypots, which join the scenario as they are created. With auditUpdate,
// the change of the scenario is recorded; the creation of a scenario records
// itself. That a deception joins once is the rule of the schema, which the
// store maps.
func (j Join) join(ctx context.Context, tx pgx.Tx, actor audit.Actor, id string, auditUpdate bool) (Applied, error) {
	scenarios := NewStore(tx)
	sc, err := scenarios.Lock(ctx, id)
	if err != nil {
		return Applied{}, err
	}
	dec := j.Deception
	// The assignment comes first, so that a deception that is part of the
	// scenario already is told before anything is created. The primary key of
	// the schema enforces the rule, and the store maps its error.
	if err := scenarios.addDeception(ctx, id, dec.ID); err != nil {
		return Applied{}, err
	}

	var applied Applied
	if j.CreateResources {
		// Each resource is created in the scenario, through the operation that
		// every creation takes, which locks the scenario first and records the
		// creation with the field scenario_id.
		for _, slot := range dec.Honeytokens {
			h, err := honeytoken.Create(ctx, tx, actor, honeytoken.Spec{
				Type: slot.Type, Name: slot.Label[j.Language], Enabled: true,
				Techniques: slot.Techniques, Severity: &slot.Severity, ScenarioID: id,
			})
			if err != nil {
				return Applied{}, fmt.Errorf("create honeytoken: %w", err)
			}
			applied.Honeytokens = append(applied.Honeytokens, h)
		}
		for _, slot := range dec.Honeypots {
			c, err := honeypot.Create(ctx, tx, j.Keys, actor, honeypot.Spec{
				Service: slot.Service, Name: slot.Label[j.Language], Enabled: true, ScenarioID: id,
			})
			if err != nil {
				return Applied{}, fmt.Errorf("create honeypot: %w", err)
			}
			applied.Honeypots = append(applied.Honeypots, c.Honeypot)
		}
	}
	activities := mergeActivities(sc.EngageActivities, dec.EngageActivities)
	changed := []string{FieldDeceptions}
	if !slices.Equal(activities, sc.EngageActivities) {
		changed = append(changed, FieldEngageActivities)
	}
	if err := scenarios.setActivities(ctx, id, activities); err != nil {
		return Applied{}, err
	}
	if auditUpdate {
		if err := record(ctx, tx, actor, audit.ActionScenarioUpdate, resource(id), changed); err != nil {
			return Applied{}, err
		}
	}
	if applied.Scenario, err = scenarios.Get(ctx, id); err != nil {
		return Applied{}, err
	}
	return applied, nil
}

// mergeActivities returns current followed by the activities of derived that
// it lacks, up to MaxEngageActivities; the list of the scenario can be changed
// freely, so an activity beyond the limit is left out and not an error.
func mergeActivities(current, derived []string) []string {
	out := slices.Clone(current)
	if out == nil {
		out = []string{}
	}
	for _, id := range derived {
		if len(out) < MaxEngageActivities && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}
