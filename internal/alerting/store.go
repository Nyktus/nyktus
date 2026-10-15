// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package alerting

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/secretbox"
)

// Names of the fields of a channel, as the audit log records them.
const (
	FieldName    = "name"
	FieldEnabled = "enabled"
	FieldURL     = "url"
	FieldHeader  = "header"
)

// Purposes of the encrypted secrets. Each binds a value to its use, so that a
// URL copied into the column of a header, or into another channel, fails to
// decrypt.
const (
	purposeURL         = "alert_channel_url"
	purposeHeaderValue = "alert_channel_header_value"
)

// associatedData binds a secret of the channel id to its purpose.
func associatedData(purpose, id string) []byte {
	return []byte(purpose + ":" + id)
}

// constraintErrors maps the checks of the schema to the errors of the
// validation, in case the rules of both ever differ.
var constraintErrors = map[string]error{
	"alert_channels_name_check":        ErrInvalidName,
	"alert_channels_type_check":        ErrInvalidType,
	"alert_channels_target_check":      ErrInvalidURL,
	"alert_channels_header_name_check": ErrInvalidHeaderName,
}

func mapWriteError(err error) error {
	if db.Violation(err, db.UniqueViolation) == "alert_channels_name_key" {
		return ErrNameTaken
	}
	if mapped, ok := constraintErrors[db.Violation(err, db.CheckViolation)]; ok {
		return mapped
	}
	return err
}

// Store manages channels with the privileges of the console, which writes
// their secrets but cannot read them.
type Store struct {
	db   db.Querier
	keys *secretbox.Keyring
}

// NewStore returns a Store that runs its queries on q, a connection pool or a
// transaction, and encrypts secrets with keys. A store that writes no secret,
// such as one that lists or deletes channels, needs no keys.
func NewStore(q db.Querier, keys *secretbox.Keyring) *Store {
	if q == nil {
		panic("alerting: nil querier")
	}
	return &Store{db: q, keys: keys}
}

// errNoKeys means that a store without keys was asked to write a secret.
var errNoKeys = errors.New("alerting: store has no encryption keys")

const columns = `id, name, type, enabled, target, header_name, created_at, updated_at`

func scan(row pgx.Row) (Channel, error) {
	var c Channel
	err := row.Scan(&c.ID, &c.Name, &c.Type, &c.Enabled, &c.Target, &c.HeaderName, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

// List returns every channel, ordered by name. There are at most MaxChannels,
// so the list has no pages.
func (s *Store) List(ctx context.Context) ([]Channel, error) {
	rows, err := s.db.Query(ctx, `SELECT `+columns+` FROM public.alert_channels ORDER BY name, id`)
	if err != nil {
		return nil, fmt.Errorf("list alert channels: %w", err)
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Channel, error) { return scan(row) })
	if err != nil {
		return nil, fmt.Errorf("list alert channels: %w", err)
	}
	return list, nil
}

// Get returns the channel id.
func (s *Store) Get(ctx context.Context, id string) (Channel, error) {
	c, err := scan(s.db.QueryRow(ctx, `SELECT `+columns+` FROM public.alert_channels WHERE id = $1`, id))
	if db.NotFound(err) {
		return Channel{}, ErrNotFound
	}
	if err != nil {
		return Channel{}, fmt.Errorf("get alert channel %s: %w", id, err)
	}
	return c, nil
}

// Create validates spec and stores a new channel with its secrets. The caller
// serializes creations, so that the count of channels holds against
// MaxChannels; it returns ErrTooManyChannels beyond it.
func (s *Store) Create(ctx context.Context, spec Spec) (Channel, error) {
	// The fields are validated before the insert, although the schema checks
	// them as well, so that a failing row never reaches the log of the
	// database next to its secrets.
	if err := spec.Validate(); err != nil {
		return Channel{}, err
	}
	target, err := Target(spec.URL)
	if err != nil {
		return Channel{}, err
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM public.alert_channels`).Scan(&n); err != nil {
		return Channel{}, fmt.Errorf("count alert channels: %w", err)
	}
	if n >= MaxChannels {
		return Channel{}, ErrTooManyChannels
	}
	var headerName *string
	if spec.Header != nil {
		headerName = &spec.Header.Name
	}
	c, err := scan(s.db.QueryRow(ctx, `
INSERT INTO public.alert_channels (name, type, enabled, target, header_name) VALUES ($1, $2, $3, $4, $5)
RETURNING `+columns, spec.Name, spec.Type, spec.Enabled, target, headerName))
	if err != nil {
		return Channel{}, fmt.Errorf("insert alert channel: %w", mapWriteError(err))
	}
	sealedURL, sealedHeader, err := s.seal(c.ID, &spec.URL, spec.Header)
	if err != nil {
		return Channel{}, err
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO public.alert_channel_secrets (channel_id, url, header_value) VALUES ($1, $2, $3)`,
		c.ID, sealedURL, sealedHeader); err != nil {
		return Channel{}, fmt.Errorf("insert secrets of alert channel %s: %w", c.ID, err)
	}
	return c, nil
}

// seal encrypts the URL and the value of the header of the channel id, each if
// given.
func (s *Store) seal(id string, u *Secret, h *Header) (sealedURL, sealedHeader []byte, err error) {
	if s.keys == nil && (u != nil || h != nil) {
		return nil, nil, errNoKeys
	}
	if u != nil {
		if sealedURL, err = s.keys.Seal([]byte(*u), associatedData(purposeURL, id)); err != nil {
			return nil, nil, fmt.Errorf("encrypt URL of alert channel %s: %w", id, err)
		}
	}
	if h != nil {
		if sealedHeader, err = s.keys.Seal([]byte(h.Value), associatedData(purposeHeaderValue, id)); err != nil {
			return nil, nil, fmt.Errorf("encrypt header of alert channel %s: %w", id, err)
		}
	}
	return sealedURL, sealedHeader, nil
}

// Update applies c to the channel id and returns it with the names of the
// changed fields, which is empty if c changes nothing. A new URL or header
// counts as a change, because the stored one cannot be read to compare. It
// returns ErrNotFound if there is no such channel and ErrHeaderNotAllowed if
// c sets a header for a channel other than a webhook.
//
// Update must run in a transaction: it locks the channel until the end of the
// transaction, so that the row and its secrets change together.
func (s *Store) Update(ctx context.Context, id string, c Change) (Channel, []string, error) {
	if err := c.Validate(); err != nil {
		return Channel{}, nil, err
	}
	current, err := scan(s.db.QueryRow(ctx, `SELECT `+columns+` FROM public.alert_channels WHERE id = $1 FOR UPDATE`, id))
	if db.NotFound(err) {
		return Channel{}, nil, ErrNotFound
	}
	if err != nil {
		return Channel{}, nil, fmt.Errorf("lock alert channel %s: %w", id, err)
	}
	if c.Header != nil && current.Type != TypeWebhook {
		return Channel{}, nil, ErrHeaderNotAllowed
	}

	updated := current
	var changed []string
	if c.Name != nil && *c.Name != current.Name {
		updated.Name = *c.Name
		changed = append(changed, FieldName)
	}
	if c.Enabled != nil && *c.Enabled != current.Enabled {
		updated.Enabled = *c.Enabled
		changed = append(changed, FieldEnabled)
	}
	if c.URL != nil {
		if updated.Target, err = Target(*c.URL); err != nil {
			return Channel{}, nil, err
		}
		changed = append(changed, FieldURL)
	}
	switch {
	case c.Header != nil:
		updated.HeaderName = &c.Header.Name
		changed = append(changed, FieldHeader)
	case c.RemoveHeader && current.HeaderName != nil:
		updated.HeaderName = nil
		changed = append(changed, FieldHeader)
	}
	if len(changed) == 0 {
		return current, nil, nil
	}

	ch, err := scan(s.db.QueryRow(ctx, `
UPDATE public.alert_channels SET
	name = $2,
	enabled = $3,
	target = $4,
	header_name = $5,
	updated_at = clock_timestamp()
WHERE id = $1
RETURNING `+columns, id, updated.Name, updated.Enabled, updated.Target, updated.HeaderName))
	if err != nil {
		return Channel{}, nil, fmt.Errorf("update alert channel %s: %w", id, mapWriteError(err))
	}
	if err := s.updateSecrets(ctx, id, c); err != nil {
		return Channel{}, nil, err
	}
	return ch, changed, nil
}

// updateSecrets replaces the secrets of the channel id that c changes.
func (s *Store) updateSecrets(ctx context.Context, id string, c Change) error {
	sealedURL, sealedHeader, err := s.seal(id, c.URL, c.Header)
	if err != nil {
		return err
	}
	if sealedURL != nil {
		if _, err := s.db.Exec(ctx, `UPDATE public.alert_channel_secrets SET url = $2 WHERE channel_id = $1`, id, sealedURL); err != nil {
			return fmt.Errorf("update URL of alert channel %s: %w", id, err)
		}
	}
	if sealedHeader != nil || c.RemoveHeader {
		if _, err := s.db.Exec(ctx, `UPDATE public.alert_channel_secrets SET header_value = $2 WHERE channel_id = $1`,
			id, sealedHeader); err != nil {
			return fmt.Errorf("update header of alert channel %s: %w", id, err)
		}
	}
	return nil
}

// Delete deletes the channel id with its secrets. It returns ErrNotFound if
// there is none and ErrEnabled if it is enabled: a channel stops receiving
// alerts only through a change that is confirmed with a password.
func (s *Store) Delete(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM public.alert_channels WHERE id = $1 AND NOT enabled`, id)
	if db.NotFound(err) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("delete alert channel %s: %w", id, err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	if _, err := s.Get(ctx, id); err != nil {
		return err
	}
	return ErrEnabled
}

// DB runs queries and starts transactions. A connection pool and a transaction
// implement it.
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

// Create creates a channel on behalf of actor in the transaction tx, which
// serializes creations, and records it in the audit log.
func Create(ctx context.Context, tx pgx.Tx, keys *secretbox.Keyring, actor audit.Actor, spec Spec) (Channel, error) {
	c, err := NewStore(tx, keys).Create(ctx, spec)
	if err != nil {
		return Channel{}, err
	}
	return c, record(ctx, tx, actor, audit.ActionAlertChannelCreate, c.ID, nil)
}

// Update applies c to the channel id on behalf of actor in the transaction tx,
// as Store.Update does, and records the names of the changed fields in the
// audit log. A change that changes nothing is not recorded.
func Update(ctx context.Context, tx pgx.Tx, keys *secretbox.Keyring, actor audit.Actor, id string, c Change) (Channel, error) {
	ch, changed, err := NewStore(tx, keys).Update(ctx, id, c)
	if err != nil || len(changed) == 0 {
		return ch, err
	}
	return ch, record(ctx, tx, actor, audit.ActionAlertChannelUpdate, id, changed)
}

// Delete deletes the disabled channel id on behalf of actor and records it in
// the audit log.
func Delete(ctx context.Context, d DB, actor audit.Actor, id string) error {
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		if err := NewStore(tx, nil).Delete(ctx, id); err != nil {
			return err
		}
		return record(ctx, tx, actor, audit.ActionAlertChannelDelete, id, nil)
	})
	if err != nil {
		return fmt.Errorf("delete alert channel: %w", err)
	}
	return nil
}

// CheckKeys returns an error if a secret of a channel is encrypted with a key
// that keys lack, naming the ID of the key. The worker refuses to start then,
// because it could deliver to none of these channels.
func CheckKeys(ctx context.Context, q db.Querier, keys *secretbox.Keyring) error {
	rows, err := q.Query(ctx, `
SELECT DISTINCT get_byte(url, 0) FROM public.alert_channel_secrets
UNION
SELECT DISTINCT get_byte(header_value, 0) FROM public.alert_channel_secrets WHERE header_value IS NOT NULL`)
	if err != nil {
		return fmt.Errorf("list encryption keys in use: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int32])
	if err != nil {
		return fmt.Errorf("list encryption keys in use: %w", err)
	}
	for _, id := range ids {
		if id < 1 || id > 255 || !keys.Has(byte(id)) {
			return fmt.Errorf("stored secrets of alert channels are encrypted with the key ID %d, which is not configured; add the key back to NYKTUS_ENCRYPTION_KEYS", id)
		}
	}
	return nil
}
