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

// ErrDNSNotConfigured means that a deception or an artifact has a DNS
// honeytoken while the console knows no zone of the DNS role, so that the
// honeytoken would have no name to place.
var ErrDNSNotConfigured = errors.New("no zone of the DNS role")

// Join describes a deception that joins a scenario, whether the scenario is
// created for it or exists already.
type Join struct {
	Deception catalog.Deception
	// Language is the language of the guide and of the names of the
	// honeytokens, one of catalog.Languages.
	Language string
	// Persona holds the values of the persona of the deception, by key. A
	// scenario that exists keeps the values it has: a key that is left out
	// takes the stored value, and one that differs fails with a
	// catalog.PersonaConflictError.
	Persona map[string]string
	// Artifacts are the identifiers of the artifacts of the deception to
	// create, each once. Nil means every artifact that the deception
	// recommends; an empty list none.
	Artifacts []string
	// TriggerURL is the public address of the trigger, with which the URLs of
	// honeytokens start.
	TriggerURL string
	// DNSZone is the zone under which DNS honeytokens are named in the
	// artifacts, or "" if the DNS role has none.
	DNSZone string
}

// selected returns the artifacts to create, in the order of the deception, or
// ErrInvalidSelection if one is not recommended by the deception or named
// twice.
func (j Join) selected() ([]catalog.Artifact, error) {
	if j.Artifacts == nil {
		return j.Deception.Artifacts, nil
	}
	for i, id := range j.Artifacts {
		if slices.Contains(j.Artifacts[:i], id) ||
			!slices.ContainsFunc(j.Deception.Artifacts, func(a catalog.Artifact) bool { return a.ID == id }) {
			return nil, ErrInvalidSelection
		}
	}
	var out []catalog.Artifact
	for _, a := range j.Deception.Artifacts {
		if slices.Contains(j.Artifacts, a.ID) {
			out = append(out, a)
		}
	}
	return out, nil
}

func (j Join) validate() error {
	if !slices.Contains(catalog.Languages, j.Language) {
		return ErrInvalidLanguage
	}
	if _, err := j.selected(); err != nil {
		return err
	}
	if j.DNSZone == "" && slices.ContainsFunc(j.Deception.Honeytokens, func(h catalog.Honeytoken) bool {
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
// activities of its story; joining adds those that follow from what it holds.
func (a Application) spec() Spec {
	return Spec{Name: a.Name, Notes: a.Notes, EngageActivities: slices.Clone(a.Deception.EngageActivities)}
}

func (a Application) validate() error {
	if err := a.spec().validate(); err != nil {
		return err
	}
	if err := a.Join.validate(); err != nil {
		return err
	}
	return a.Deception.ValidatePersona(a.Persona)
}

// Addition describes a deception that joins a scenario that exists.
type Addition struct {
	ScenarioID string
	Join
}

// Applied is what applying a deception or adding something to a scenario
// created.
type Applied struct {
	// Scenario is the scenario after the change.
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
// secrets of the artifacts are generated once and live only in what is
// rendered: the scenario is a snapshot, never rendered again.
//
// Apply returns a catalog.PersonaError for an invalid persona,
// ErrInvalidSelection, ErrDNSNotConfigured, and a catalog.RevealError if a
// value makes an artifact reveal what it is, such as a zone named "canary".
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
// actor, as Apply does for a scenario of its own: it creates the honeytokens
// and the artifacts and renders the guide, and records each in the audit log
// together with the change of the scenario, all in one transaction.
//
// The persona of the scenario grows by the keys that the deception asks for
// and the scenario lacks, see catalog.Deception.MergePersona. AddDeception
// returns ErrNotFound if there is no such scenario, ErrDeceptionAdded if the
// deception is part of it already, ErrTooManyDeceptions and artifact.ErrLimit
// if the scenario holds the most it may, a catalog.PersonaConflictError for a
// value that differs from the stored one, and the errors of Apply.
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

// join adds the deception to the scenario id in the transaction tx. The
// scenario is locked first, as the deletion of a scenario does, so that the
// persona it is merged into is the one that stays, and everything that joins
// meanwhile waits. The honeytokens follow, then the artifacts. With
// auditUpdate, the change of the scenario is recorded; the creation of a
// scenario records itself. That a deception joins once and that a scenario
// holds no more than it may is the rule of the schema, which counts under the
// lock of the scenario; the store maps its errors.
func (j Join) join(ctx context.Context, tx pgx.Tx, actor audit.Actor, id string, auditUpdate bool) (Applied, error) {
	scenarios := NewStore(tx)
	sc, err := scenarios.Lock(ctx, id)
	if err != nil {
		return Applied{}, err
	}
	dec := j.Deception
	// The lock has loaded the deceptions the scenario holds, so a repeat or a
	// full scenario is told before anything is created or the persona is
	// judged. The schema enforces both rules all the same.
	if slices.ContainsFunc(sc.Deceptions, func(d AppliedDeception) bool { return d.DeceptionID == dec.ID }) {
		return Applied{}, ErrDeceptionAdded
	}
	if len(sc.Deceptions) >= MaxDeceptions {
		return Applied{}, ErrTooManyDeceptions
	}
	chosen, err := j.selected()
	if err != nil {
		return Applied{}, err
	}
	files := artifact.NewStore(tx)
	persona, added, err := dec.MergePersona(sc.Persona, j.Persona)
	if err != nil {
		return Applied{}, err
	}

	var applied Applied
	tokens := honeytoken.NewStore(tx)
	placed := make(map[string]catalog.Placed, len(dec.Honeytokens))
	bound := make(map[string]string, len(dec.Honeytokens))
	for _, slot := range dec.Honeytokens {
		h, err := tokens.Create(ctx, honeytoken.Spec{
			Type: slot.Type, Name: slot.Label[j.Language], Enabled: true,
			Techniques: slot.Techniques, Severity: &slot.Severity,
		})
		if err != nil {
			return Applied{}, fmt.Errorf("create honeytoken %s: %w", slot.Key, err)
		}
		if err := record(ctx, tx, actor, audit.ActionHoneytokenCreate,
			audit.Resource{Type: honeytoken.ResourceType, ID: h.ID}, nil); err != nil {
			return Applied{}, err
		}
		placed[slot.Key] = placedAs(h, j.TriggerURL, j.DNSZone)
		bound[slot.Key] = h.ID
		applied.Honeytokens = append(applied.Honeytokens, h)
	}

	rendered, err := dec.RenderSelected(chosen, placed, persona, dec.NewSecrets(), j.Language)
	if err != nil {
		return Applied{}, err
	}

	// The honeytokens join the scenario through the operation that every
	// assignment takes, which locks the scenario first. Nobody else sees them
	// yet, so joining is part of their creation and has no audit entry of its
	// own.
	for i, h := range applied.Honeytokens {
		if applied.Honeytokens[i], _, err = tokens.SetScenario(ctx, h.ID, id); err != nil {
			return Applied{}, fmt.Errorf("assign honeytoken %s: %w", h.ID, err)
		}
	}
	if err := scenarios.addDeception(ctx, id, dec.ID, j.Language, rendered.Guide); err != nil {
		return Applied{}, err
	}
	for _, r := range rendered.Artifacts {
		art, err := files.Create(ctx, artifact.Spec{
			ScenarioID: id, CatalogArtifact: r.ID, FileName: r.FileName, Format: r.Format, Content: r.Content,
			Placing: r.Placing, Bindings: bindingsOf(r.Artifact, bound),
		})
		if err != nil {
			return Applied{}, fmt.Errorf("create artifact %s: %w", r.ID, err)
		}
		if err := record(ctx, tx, actor, audit.ActionArtifactCreate,
			audit.Resource{Type: artifact.ResourceType, ID: art.ID}, nil); err != nil {
			return Applied{}, err
		}
		applied.Artifacts = append(applied.Artifacts, art)
	}

	activities := mergeActivities(sc.EngageActivities, catalog.Activities(dec.EngageActivities, chosen, placed, persona))
	changed := []string{FieldDeceptions}
	if len(added) > 0 {
		changed = append(changed, FieldPersona)
	}
	if !slices.Equal(activities, sc.EngageActivities) {
		changed = append(changed, FieldEngageActivities)
	}
	if applied.Scenario, err = finishScenario(ctx, tx, actor, scenarios, id, persona, activities, changed,
		true, auditUpdate); err != nil {
		return Applied{}, err
	}
	return applied, nil
}

// finishScenario is the end of everything that extends a scenario. With write
// it stores the persona and the activities, which also moves the time of the
// change; with auditUpdate it records the change. It returns the scenario as it
// is.
func finishScenario(ctx context.Context, tx pgx.Tx, actor audit.Actor, scenarios *Store, id string,
	persona map[string]string, activities, changed []string, write, auditUpdate bool,
) (Scenario, error) {
	if write {
		if err := scenarios.grow(ctx, id, persona, activities); err != nil {
			return Scenario{}, err
		}
	}
	if auditUpdate {
		if err := record(ctx, tx, actor, audit.ActionScenarioUpdate, resource(id), changed); err != nil {
			return Scenario{}, err
		}
	}
	return scenarios.Get(ctx, id)
}

// placedAs returns what the honeytoken h is placed as: the host name under the
// zone for a DNS honeytoken, the URL of the trigger otherwise.
func placedAs(h honeytoken.Honeytoken, triggerURL, zone string) catalog.Placed {
	p := catalog.Placed{URL: triggerURL + h.TriggerPath()}
	if names := h.TriggerNames([]string{zone}); len(names) == 1 {
		p = catalog.Placed{Host: names[0]}
	}
	return p
}

// bindingsOf returns the honeytokens, by identifier, that fill the slots of a,
// from the honeytokens of a deception by key.
func bindingsOf(a catalog.Artifact, honeytokens map[string]string) map[string]string {
	bindings := map[string]string{}
	for _, s := range a.Slots {
		if id, ok := honeytokens[s.Key]; ok {
			bindings[s.Key] = id
		}
	}
	return bindings
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
