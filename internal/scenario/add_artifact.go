// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenario

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/artifact"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/honeytoken"
)

// ErrInvalidBinding means that a honeytoken cannot fill a slot of an artifact.
var ErrInvalidBinding = errors.New("invalid binding")

// BindingError says which slot cannot be filled and why. The reason is one of
// a fixed list, so that it neither reveals whether a honeytoken exists in
// another scenario nor echoes the request.
type BindingError struct {
	Slot   string
	Reason string
}

func (e *BindingError) Error() string {
	return fmt.Sprintf("binding %s: %s", e.Slot, e.Reason)
}

// Is makes the error match ErrInvalidBinding.
func (e *BindingError) Is(target error) bool {
	return target == ErrInvalidBinding
}

// ArtifactAddition describes an artifact of the catalog that is added to a
// scenario.
type ArtifactAddition struct {
	ScenarioID string
	Artifact   catalog.Artifact
	// Language is the language of the text that says where to place the
	// artifact, one of catalog.Languages.
	Language string
	// Persona holds the values of the persona of the artifact, by key. The
	// scenario keeps the values it has, see Join.
	Persona map[string]string
	// Bindings are the honeytokens of the scenario that fill the slots of the
	// artifact, by the key of the slot. A required slot needs one; an
	// optional slot that is left out makes the file pocket litter.
	Bindings map[string]string
	// TriggerURL and DNSZone are those of Join.
	TriggerURL string
	DNSZone    string
}

// validate checks the bindings against the slots, as far as the catalog tells.
// That the honeytokens exist, belong to the scenario and have the right type
// needs the database and is checked under the lock of the scenario.
func (a ArtifactAddition) validate() error {
	if !slices.Contains(catalog.Languages, a.Language) {
		return ErrInvalidLanguage
	}
	for _, key := range slices.Sorted(maps.Keys(a.Bindings)) {
		if !slices.ContainsFunc(a.Artifact.Slots, func(s catalog.Slot) bool { return s.Key == key }) {
			return &BindingError{Slot: bindingName(key), Reason: "is not a slot of the artifact"}
		}
	}
	for _, s := range a.Artifact.Slots {
		if _, ok := a.Bindings[s.Key]; !ok && !s.Optional {
			return &BindingError{Slot: s.Key, Reason: "needs a honeytoken"}
		}
	}
	return nil
}

// bindingName returns key if it has the form of the key of a slot, so that the
// error does not echo any text from the request.
func bindingName(key string) string {
	if !catalog.ValidKey(key) {
		return "with a malformed key"
	}
	return key
}

// AddArtifact adds an artifact of the catalog to the scenario on behalf of
// actor: it renders the artifact with the honeytokens of the bindings, the
// persona of the scenario and secrets of its own, and records the artifact and
// the change of the scenario in the audit log, all in one transaction.
//
// The artifact is rendered once, like one that applying a deception renders,
// and never again. A password that the file names is therefore not the one
// of the older files of the scenario. The persona of the scenario grows by the
// keys that the artifact asks for and the scenario lacks.
//
// AddArtifact returns ErrNotFound if there is no such scenario,
// artifact.ErrLimit if it holds the most artifacts it may, a BindingError for a
// honeytoken that cannot fill its slot, ErrDNSNotConfigured, a
// catalog.PersonaError or catalog.PersonaConflictError for the persona, and a
// catalog.RevealError if the file would contain a marker, among them the
// identifiers of the deceptions of the scenario.
func AddArtifact(ctx context.Context, d DB, actor audit.Actor, add ArtifactAddition) (Applied, error) {
	if err := add.validate(); err != nil {
		return Applied{}, err
	}
	var applied Applied
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		scenarios := NewStore(tx)
		sc, err := scenarios.Lock(ctx, add.ScenarioID)
		if err != nil {
			return err
		}
		files := artifact.NewStore(tx)

		placed, bound, err := add.place(ctx, honeytoken.NewStore(tx), sc.ID)
		if err != nil {
			return err
		}
		persona, added, err := add.Artifact.MergePersona(sc.Persona, add.Persona)
		if err != nil {
			return err
		}
		ids := make([]string, len(sc.Deceptions))
		for i, dec := range sc.Deceptions {
			ids[i] = dec.DeceptionID
		}
		r, err := catalog.RenderArtifact(add.Artifact, placed, persona, add.Artifact.NewSecrets(), add.Language, ids...)
		if err != nil {
			return err
		}
		art, err := files.Create(ctx, artifact.Spec{
			ScenarioID: sc.ID, CatalogArtifact: r.ID, FileName: r.FileName, Format: r.Format, Content: r.Content,
			Placing: r.Placing, Bindings: bound,
		})
		if err != nil {
			return fmt.Errorf("create artifact %s: %w", r.ID, err)
		}
		if err := record(ctx, tx, actor, audit.ActionArtifactCreate,
			audit.Resource{Type: artifact.ResourceType, ID: art.ID}, nil); err != nil {
			return err
		}
		applied.Artifacts = []artifact.Artifact{art}

		activities := mergeActivities(sc.EngageActivities, catalog.Activities(nil, []catalog.Artifact{add.Artifact}, placed, persona))
		var changed []string
		if len(added) > 0 {
			changed = append(changed, FieldPersona)
		}
		if !slices.Equal(activities, sc.EngageActivities) {
			changed = append(changed, FieldEngageActivities)
		}
		// Nothing about the scenario changes if no key of the persona and no
		// activity is new, so it is not written and no entry is recorded.
		applied.Scenario, err = finishScenario(ctx, tx, actor, scenarios, sc.ID, persona, activities, changed,
			len(changed) > 0, len(changed) > 0)
		return err
	})
	if err != nil {
		return Applied{}, fmt.Errorf("add artifact %s: %w", add.Artifact.ID, err)
	}
	return applied, nil
}

// place locks the honeytokens of the bindings and returns what each is placed
// as, by the key of its slot, and their identifiers. A honeytoken must belong
// to the scenario and be of a type that the slot takes. The scenario is
// locked, so it keeps them: a honeytoken cannot leave it or be deleted until
// the transaction ends.
func (a ArtifactAddition) place(ctx context.Context, tokens *honeytoken.Store, scenarioID string) (map[string]catalog.Placed, map[string]string, error) {
	placed := make(map[string]catalog.Placed, len(a.Bindings))
	bound := make(map[string]string, len(a.Bindings))
	for _, s := range a.Artifact.Slots {
		id, ok := a.Bindings[s.Key]
		if !ok {
			continue
		}
		h, err := tokens.GetForShare(ctx, id)
		// A honeytoken that does not exist and one of another scenario are
		// answered alike.
		if errors.Is(err, honeytoken.ErrNotFound) || (err == nil && (h.ScenarioID == nil || *h.ScenarioID != scenarioID)) {
			return nil, nil, &BindingError{Slot: s.Key, Reason: "is not filled by a honeytoken of the scenario"}
		}
		if err != nil {
			return nil, nil, err
		}
		if !slices.Contains(s.Accepts, h.Type) {
			return nil, nil, &BindingError{Slot: s.Key, Reason: "does not take honeytokens of that type"}
		}
		if h.Type == honeytoken.TypeDNS && a.DNSZone == "" {
			return nil, nil, ErrDNSNotConfigured
		}
		placed[s.Key] = placedAs(h, a.TriggerURL, a.DNSZone)
		bound[s.Key] = h.ID
	}
	return placed, bound, nil
}
