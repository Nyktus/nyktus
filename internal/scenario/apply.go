// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenario

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/artifact"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/honeytoken"
)

// ErrDNSNotConfigured means that a deception has a DNS honeytoken while the
// console knows no zone of the DNS role, so that the honeytoken would have no
// name to place.
var ErrDNSNotConfigured = errors.New("no zone of the DNS role")

// Application describes how a deception is applied.
type Application struct {
	Deception catalog.Deception
	// Name and Notes are those of the new scenario.
	Name  string
	Notes string
	// Language is the language of the guide and of the names of the
	// honeytokens, one of catalog.Languages.
	Language string
	// Persona holds the values of the persona of the deception, by key.
	Persona map[string]string
	// TriggerURL is the public address of the trigger, with which the URLs of
	// honeytokens start.
	TriggerURL string
	// DNSZone is the zone under which DNS honeytokens are named in the
	// artifacts, or "" if the DNS role has none.
	DNSZone string
}

// spec returns the scenario that applying the deception creates.
func (a Application) spec() Spec {
	return Spec{Name: a.Name, Notes: a.Notes, EngageActivities: slices.Clone(a.Deception.EngageActivities)}
}

func (a Application) validate() error {
	if err := a.spec().validate(); err != nil {
		return err
	}
	if !slices.Contains(catalog.Languages, a.Language) {
		return ErrInvalidLanguage
	}
	if err := a.Deception.ValidatePersona(a.Persona); err != nil {
		return err
	}
	if a.DNSZone == "" && slices.ContainsFunc(a.Deception.Honeytokens, func(h catalog.Honeytoken) bool {
		return h.Type == honeytoken.TypeDNS
	}) {
		return ErrDNSNotConfigured
	}
	return nil
}

// Applied is what applying a deception created.
type Applied struct {
	Scenario    Scenario
	Honeytokens []honeytoken.Honeytoken
	Artifacts   []artifact.Artifact
}

// Apply applies a deception of the catalog on behalf of actor: it creates a
// scenario with the honeytokens of the deception and the artifacts and the
// guide rendered for them, and records each in the audit log, all in one
// transaction, so that a failure leaves nothing behind.
//
// The trigger values of the honeytokens come from their store, so the
// artifacts are rendered after the honeytokens are created, in the same
// transaction. Every value of the application is validated before. The
// secrets of the deception are generated once and live only in what is
// rendered: the scenario is a snapshot, never rendered again.
//
// Apply returns a catalog.PersonaError for an invalid persona,
// ErrDNSNotConfigured, and a catalog.RevealError if a value makes an artifact
// reveal what it is, such as a zone named "canary".
func Apply(ctx context.Context, d DB, actor audit.Actor, a Application) (Applied, error) {
	if err := a.validate(); err != nil {
		return Applied{}, err
	}
	dec := a.Deception
	secrets := dec.NewSecrets()
	// A deception without a persona still keeps one, empty, so that the
	// scenario shows that it was applied with no values.
	persona := a.Persona
	if persona == nil {
		persona = map[string]string{}
	}

	var applied Applied
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		tokens := honeytoken.NewStore(tx)
		placed := make(map[string]catalog.Placed, len(dec.Honeytokens))
		for _, slot := range dec.Honeytokens {
			h, err := tokens.Create(ctx, honeytoken.Spec{
				Type: slot.Type, Name: slot.Label[a.Language], Enabled: true,
				Techniques: slot.Techniques, Severity: &slot.Severity,
			})
			if err != nil {
				return fmt.Errorf("create honeytoken %s: %w", slot.Key, err)
			}
			if err := record(ctx, tx, actor, audit.ActionHoneytokenCreate,
				audit.Resource{Type: honeytoken.ResourceType, ID: h.ID}, nil); err != nil {
				return err
			}
			p := catalog.Placed{URL: a.TriggerURL + h.TriggerPath()}
			if names := h.TriggerNames([]string{a.DNSZone}); len(names) == 1 {
				p = catalog.Placed{Host: names[0]}
			}
			placed[slot.Key] = p
			applied.Honeytokens = append(applied.Honeytokens, h)
		}

		rendered, err := dec.Render(dec.Values(placed, persona, secrets), a.Language)
		if err != nil {
			return err
		}

		if applied.Scenario, err = NewStore(tx).createFromDeception(ctx, a.spec(), dec.ID, a.Language, persona,
			rendered.Guide); err != nil {
			return err
		}
		sc := applied.Scenario.ID
		if err := record(ctx, tx, actor, audit.ActionScenarioCreate, resource(sc), nil); err != nil {
			return err
		}
		// The honeytokens join the scenario through the operation that every
		// assignment takes, which locks the scenario first. Nobody else sees
		// them yet, so joining is part of their creation and has no audit
		// entry of its own.
		for i, h := range applied.Honeytokens {
			if applied.Honeytokens[i], _, err = tokens.SetScenario(ctx, h.ID, sc); err != nil {
				return fmt.Errorf("assign honeytoken %s: %w", h.ID, err)
			}
		}

		files := artifact.NewStore(tx)
		for _, r := range rendered.Artifacts {
			art, err := files.Create(ctx, artifact.Spec{
				ScenarioID: sc, DeceptionArtifact: r.Key, FileName: r.FileName, Format: r.Format, Content: r.Content,
			})
			if err != nil {
				return fmt.Errorf("create artifact %s: %w", r.Key, err)
			}
			if err := record(ctx, tx, actor, audit.ActionArtifactCreate,
				audit.Resource{Type: artifact.ResourceType, ID: art.ID}, nil); err != nil {
				return err
			}
			applied.Artifacts = append(applied.Artifacts, art)
		}
		return nil
	})
	if err != nil {
		return Applied{}, fmt.Errorf("apply deception %s: %w", dec.ID, err)
	}
	return applied, nil
}
