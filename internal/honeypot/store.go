// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeypot

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/token"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/secretbox"
)

// Errors of the store.
var (
	ErrNotFound = errors.New("honeypot not found")
	// ErrScenarioNotFound means that the scenario that a honeypot is to be
	// assigned to does not exist.
	ErrScenarioNotFound = errors.New("scenario not found")
	// ErrInOtherScenario means that a honeypot belongs to another scenario than
	// the one it is to be assigned to.
	ErrInOtherScenario = errors.New("honeypot belongs to another scenario")
	// ErrInvalidPageSize is returned for a page size outside [1, MaxPageSize].
	ErrInvalidPageSize = errors.New("invalid page size")
	// ErrSecretUnreadable means that the sealed secret of a honeypot does not
	// open, or does not match the hash that the trigger finds the honeypot by.
	// The stored values are inconsistent, and the secret is replaced.
	ErrSecretUnreadable = errors.New("the secret of the honeypot cannot be read")
	// errNoKeys means that a store without keys was asked to seal or open a
	// secret.
	errNoKeys = errors.New("honeypot: store has no encryption keys")
)

// MaxPageSize is the largest page that List returns.
const MaxPageSize = 200

// constraintErrors maps the checks of the schema to the errors of the
// validation, in case the rules of both ever differ.
var constraintErrors = map[string]error{
	"honeypots_service_check":    ErrInvalidService,
	"honeypots_name_check":       ErrInvalidName,
	"honeypots_notes_check":      ErrInvalidNotes,
	"honeypots_techniques_check": ErrInvalidTechniques,
	"honeypots_severity_check":   ErrInvalidSeverity,
}

func mapWriteError(err error) error {
	if mapped, ok := constraintErrors[db.Violation(err, db.CheckViolation)]; ok {
		return mapped
	}
	// A scenario that is deleted between the lock and the insert, which a
	// store on a connection pool, without the lock, can meet.
	if db.Violation(err, db.ForeignKeyViolation) == "honeypots_scenario_id_fkey" {
		return ErrScenarioNotFound
	}
	return err
}

// Store persists honeypots in PostgreSQL.
type Store struct {
	db   db.Querier
	keys *secretbox.Keyring
}

// NewStore returns a Store that runs its queries on q, a connection pool or a
// transaction, and seals and opens secrets with keys. A store that creates no
// honeypot and reads and replaces no secret, such as one that lists or deletes
// honeypots, needs no keys.
func NewStore(q db.Querier, keys *secretbox.Keyring) *Store {
	if q == nil {
		panic("honeypot: nil querier")
	}
	return &Store{db: q, keys: keys}
}

// columns are the columns of a honeypot without the hash of its secret and the
// sealed secret, which only reading the secret needs, and with its status, which the database derives from its
// last report with its own clock, so that every console process agrees and
// tests move the stored time instead of a clock. The metrics use the same
// function, so that both judge a honeypot alike; it implements OfflineAfter.
const columns = `id, service, name, notes, enabled, techniques, severity, scenario_id, last_seen_at, sensor_version,
public.honeypot_status(last_seen_at), created_at, updated_at`

// scan reads a honeypot, and the values after its columns into more.
func scan(row pgx.Row, more ...any) (Honeypot, error) {
	var h Honeypot
	err := row.Scan(append([]any{
		&h.ID, &h.Service, &h.Name, &h.Notes, &h.Enabled, &h.Techniques, &h.Severity, &h.ScenarioID,
		&h.LastSeenAt, &h.SensorVersion, &h.Status, &h.CreatedAt, &h.UpdatedAt,
	}, more...)...)
	return h, err
}

// newSecret returns a new secret, the hash under which the trigger finds the
// honeypot, and the secret sealed for the console to show it again.
func (s *Store) newSecret() (secret Secret, hash, sealed []byte, err error) {
	if s.keys == nil {
		return "", nil, nil, errNoKeys
	}
	raw, err := token.New()
	if err != nil {
		return "", nil, nil, fmt.Errorf("generate honeypot secret: %w", err)
	}
	hash = token.Hash(raw)
	sealed, err = s.keys.Seal([]byte(raw), secretData(hash))
	if err != nil {
		return "", nil, nil, fmt.Errorf("seal honeypot secret: %w", err)
	}
	return Secret(raw), hash, sealed, nil
}

// secretData is the associated data of a sealed secret: its purpose and the
// hash of the secret. The identifier of the honeypot is not known before the
// row is inserted, but the hash is unique to it, so a sealed secret copied to
// another row does not open.
func secretData(hash []byte) []byte {
	return append([]byte("honeypot secret:"), hash...)
}

// Create validates spec and stores a new honeypot with a new secret, of which
// it stores the hash and the sealed secret. The fields are validated before the insert,
// although the schema checks the same rules, so that the stored techniques
// exist in the bundled version of ATT&CK and a failing row never reaches the
// log of the database.
//
// A honeypot that joins a scenario with spec.ScenarioID is created under the
// same lock as SetScenario takes, so Create must then run in a transaction. It
// returns ErrScenarioNotFound if there is no such scenario.
func (s *Store) Create(ctx context.Context, spec Spec) (Created, error) {
	if err := spec.validate(); err != nil {
		return Created{}, err
	}
	var scenarioID *string
	if spec.ScenarioID != "" {
		if err := s.lockScenario(ctx, spec.ScenarioID); err != nil {
			return Created{}, err
		}
		scenarioID = &spec.ScenarioID
	}
	techniques := spec.Techniques
	if techniques == nil {
		techniques = []string{}
	}
	level := spec.Service.DefaultSeverity()
	if spec.Severity != nil {
		level = *spec.Severity
	}
	secret, hash, sealed, err := s.newSecret()
	if err != nil {
		return Created{}, err
	}
	h, err := scan(s.db.QueryRow(ctx, `
INSERT INTO honeypots (service, name, notes, enabled, techniques, severity, secret_hash, secret_sealed, scenario_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING `+columns, spec.Service, spec.Name, spec.Notes, spec.Enabled, techniques, level, hash, sealed, scenarioID))
	if err != nil {
		return Created{}, fmt.Errorf("create honeypot: %w", mapWriteError(err))
	}
	return Created{Honeypot: h, Secret: secret}, nil
}

// Get returns the honeypot id. It returns ErrNotFound if there is none.
func (s *Store) Get(ctx context.Context, id string) (Honeypot, error) {
	h, err := scan(s.db.QueryRow(ctx, `SELECT `+columns+` FROM honeypots WHERE id = $1`, id))
	if db.NotFound(err) {
		return Honeypot{}, ErrNotFound
	}
	if err != nil {
		return Honeypot{}, fmt.Errorf("get honeypot %s: %w", id, err)
	}
	return h, nil
}

// Cursor marks the position after the last honeypot of a page.
type Cursor struct {
	CreatedAt time.Time
	ID        string
}

// Filter narrows a list to honeypots of a service, state or scenario. A nil or
// empty field does not narrow it.
type Filter struct {
	Service *Service
	Enabled *bool
	// ScenarioID lists only the honeypots of one scenario.
	ScenarioID string
}

// The filters of service and state are conditions in every statement and
// always active: without a filter, they list every value. A condition that is
// active only sometimes would keep a generic plan from seeking into the index;
// the scenario and the cursor, which the indexes serve, are therefore
// conditions of statements of their own.
var (
	listOrder = `
ORDER BY created_at DESC, id DESC`
	listNewest = `SELECT ` + columns + ` FROM honeypots
WHERE service = ANY($1) AND enabled = ANY($2)` + listOrder + `
LIMIT $3`
	listAfter = `SELECT ` + columns + ` FROM honeypots
WHERE (created_at, id) < ($3, $4::uuid) AND service = ANY($1) AND enabled = ANY($2)` + listOrder + `
LIMIT $5`
	listScenarioNewest = `SELECT ` + columns + ` FROM honeypots
WHERE scenario_id = $3 AND service = ANY($1) AND enabled = ANY($2)` + listOrder + `
LIMIT $4`
	listScenarioAfter = `SELECT ` + columns + ` FROM honeypots
WHERE scenario_id = $3 AND (created_at, id) < ($4, $5::uuid) AND service = ANY($1) AND enabled = ANY($2)` +
		listOrder + `
LIMIT $6`
)

// List returns up to size honeypots that match f, from the newest to the
// oldest, that come after the cursor after, or from the newest if after is nil.
// next is the cursor of the following page, or nil if there are no more
// honeypots.
func (s *Store) List(ctx context.Context, f Filter, size int, after *Cursor) (list []Honeypot, next *Cursor, err error) {
	if size < 1 || size > MaxPageSize {
		return nil, nil, ErrInvalidPageSize
	}
	var services []string
	for _, sv := range Services {
		if f.Service == nil || *f.Service == sv {
			services = append(services, string(sv))
		}
	}
	enabled := []bool{true, false}
	if f.Enabled != nil {
		enabled = []bool{*f.Enabled}
	}
	// One more honeypot than requested tells whether another page follows.
	var rows pgx.Rows
	switch {
	case f.ScenarioID == "" && after == nil:
		rows, err = s.db.Query(ctx, listNewest, services, enabled, size+1)
	case f.ScenarioID == "":
		rows, err = s.db.Query(ctx, listAfter, services, enabled, after.CreatedAt, after.ID, size+1)
	case after == nil:
		rows, err = s.db.Query(ctx, listScenarioNewest, services, enabled, f.ScenarioID, size+1)
	default:
		rows, err = s.db.Query(ctx, listScenarioAfter, services, enabled, f.ScenarioID, after.CreatedAt, after.ID, size+1)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("list honeypots: %w", err)
	}
	list, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Honeypot, error) { return scan(row) })
	if err != nil {
		return nil, nil, fmt.Errorf("list honeypots: %w", err)
	}
	if len(list) > size {
		list = list[:size]
		last := list[size-1]
		next = &Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	return list, next, nil
}

// Update validates c and applies it to the honeypot id. It returns the
// honeypot after the change and the names of the fields whose values changed,
// which is empty if c changes nothing. It returns ErrNotFound if there is no
// such honeypot.
//
// Update must run in a transaction: it locks the honeypot until the end of the
// transaction, so that concurrent changes cannot interleave between the
// comparison with the current values and the change, which would record wrong
// fields in the audit log.
func (s *Store) Update(ctx context.Context, id string, c Change) (Honeypot, []string, error) {
	if err := c.validate(); err != nil {
		return Honeypot{}, nil, err
	}
	current, err := scan(s.db.QueryRow(ctx, `SELECT `+columns+` FROM honeypots WHERE id = $1 FOR UPDATE`, id))
	if db.NotFound(err) {
		return Honeypot{}, nil, ErrNotFound
	}
	if err != nil {
		return Honeypot{}, nil, fmt.Errorf("lock honeypot %s: %w", id, err)
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
UPDATE honeypots SET
	name = $2,
	notes = $3,
	enabled = $4,
	techniques = $5,
	severity = $6,
	updated_at = clock_timestamp()
WHERE id = $1
RETURNING `+columns, id, updated.Name, updated.Notes, updated.Enabled, updated.Techniques, updated.Severity))
	if err != nil {
		return Honeypot{}, nil, fmt.Errorf("update honeypot %s: %w", id, mapWriteError(err))
	}
	return h, changed, nil
}

// ReplaceSecret gives the honeypot id a new secret and returns it with the
// honeypot. The old secret stops working at once, because the trigger finds the
// honeypot by the hash of the new one. The database clears what the last sensor
// reported, so that the honeypot shows whether a sensor with the new secret has
// reported yet. It returns ErrNotFound if there is no such honeypot.
func (s *Store) ReplaceSecret(ctx context.Context, id string) (Created, error) {
	secret, hash, sealed, err := s.newSecret()
	if err != nil {
		return Created{}, err
	}
	h, err := scan(s.db.QueryRow(ctx, `
UPDATE honeypots SET secret_hash = $2, secret_sealed = $3, updated_at = clock_timestamp()
WHERE id = $1
RETURNING `+columns, id, hash, sealed))
	if db.NotFound(err) {
		return Created{}, ErrNotFound
	}
	if err != nil {
		return Created{}, fmt.Errorf("replace secret of honeypot %s: %w", id, err)
	}
	return Created{Honeypot: h, Secret: secret}, nil
}

// Secret returns the honeypot id with its secret. It returns ErrNotFound if
// there is no such honeypot and ErrSecretUnreadable if the sealed secret does
// not open with the keys, or opens to a value that is not the one the trigger
// finds the honeypot by: a sealed value that was moved or altered is refused,
// never handed to a sensor.
func (s *Store) Secret(ctx context.Context, id string) (Created, error) {
	if s.keys == nil {
		return Created{}, errNoKeys
	}
	var hash, sealed []byte
	h, err := scan(s.db.QueryRow(ctx, `SELECT `+columns+`, secret_hash, secret_sealed FROM honeypots WHERE id = $1`, id), &hash, &sealed)
	if db.NotFound(err) {
		return Created{}, ErrNotFound
	}
	if err != nil {
		return Created{}, fmt.Errorf("get secret of honeypot %s: %w", id, err)
	}
	plain, err := s.keys.Open(sealed, secretData(hash))
	if err != nil {
		return Created{}, fmt.Errorf("open secret of honeypot %s: %w: %w", id, ErrSecretUnreadable, err)
	}
	if !hmac.Equal(token.Hash(string(plain)), hash) {
		return Created{}, fmt.Errorf("open secret of honeypot %s: %w: the hash differs", id, ErrSecretUnreadable)
	}
	return Created{Honeypot: h, Secret: Secret(plain)}, nil
}

// CheckKeys returns an error if the secret of a honeypot is sealed with a key
// that keys lack, naming the ID of the key. The console refuses to start then,
// because it could show the secret of none of these honeypots.
func CheckKeys(ctx context.Context, q db.Querier, keys *secretbox.Keyring) error {
	rows, err := q.Query(ctx, `SELECT DISTINCT get_byte(secret_sealed, 0) FROM public.honeypots`)
	if err != nil {
		return fmt.Errorf("list encryption keys in use: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int32])
	if err != nil {
		return fmt.Errorf("list encryption keys in use: %w", err)
	}
	for _, id := range ids {
		if id < 1 || id > 255 || !keys.Has(byte(id)) {
			return fmt.Errorf("stored secrets of honeypots are sealed with the key ID %d, which is not configured; add the key back to NYKTUS_ENCRYPTION_KEYS", id)
		}
	}
	return nil
}

// Resealed counts what Reseal did.
type Resealed struct {
	// Done is the number of secrets that it sealed again with the current key.
	Done int
	// Unreadable is the number of secrets sealed with another key that did not
	// open. They stay as they are: the read of such a secret fails, and
	// replacing it repairs it.
	Unreadable int
}

// Reseal seals the secrets again that another key than the current one of keys
// sealed, so that the first key of a rotation takes over and the old one can be
// retired. The console runs it when it starts, after CheckKeys, and it does
// nothing where every secret is sealed with the current key.
//
// It locks the honeypots it changes, so that the replacement of a secret that
// runs at the same time is not overwritten with the old secret, and it leaves
// their other columns alone.
func Reseal(ctx context.Context, d DB, keys *secretbox.Keyring) (Resealed, error) {
	var done Resealed
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		done = Resealed{}
		rows, err := tx.Query(ctx, `
SELECT id, secret_hash, secret_sealed FROM honeypots
WHERE get_byte(secret_sealed, 0) <> $1 ORDER BY id FOR UPDATE`, int(keys.CurrentKeyID()))
		if err != nil {
			return fmt.Errorf("list secrets to seal again: %w", err)
		}
		type old struct {
			id           string
			hash, sealed []byte
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (old, error) {
			var o old
			err := row.Scan(&o.id, &o.hash, &o.sealed)
			return o, err
		})
		if err != nil {
			return fmt.Errorf("list secrets to seal again: %w", err)
		}
		for _, o := range list {
			plain, err := keys.Open(o.sealed, secretData(o.hash))
			if err != nil {
				done.Unreadable++
				continue
			}
			fresh, err := keys.Seal(plain, secretData(o.hash))
			if err != nil {
				return fmt.Errorf("seal secret of honeypot %s again: %w", o.id, err)
			}
			if _, err := tx.Exec(ctx, `UPDATE honeypots SET secret_sealed = $2 WHERE id = $1`, o.id, fresh); err != nil {
				return fmt.Errorf("store secret of honeypot %s sealed again: %w", o.id, err)
			}
			done.Done++
		}
		return nil
	})
	if err != nil {
		return Resealed{}, err
	}
	return done, nil
}

// Delete deletes the honeypot id. It returns ErrNotFound if there is none.
func (s *Store) Delete(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM honeypots WHERE id = $1`, id)
	if db.NotFound(err) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("delete honeypot %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// lockScenario keeps the scenario id from being deleted until the end of the
// transaction, before the honeypot that refers to it is written. It returns
// ErrScenarioNotFound if there is none.
func (s *Store) lockScenario(ctx context.Context, id string) error {
	var found bool
	err := s.db.QueryRow(ctx, `SELECT true FROM scenarios WHERE id = $1 FOR KEY SHARE`, id).Scan(&found)
	if db.NotFound(err) {
		return ErrScenarioNotFound
	}
	if err != nil {
		return fmt.Errorf("lock scenario %s: %w", id, err)
	}
	return nil
}

// SetScenario assigns the honeypot id to the scenario scenarioID, or detaches
// it from its scenario if scenarioID is empty. It returns the honeypot after
// the change and whether it changed: a honeypot that is already where it is to
// be stays as it is. It returns ErrNotFound if there is no such honeypot,
// ErrScenarioNotFound if there is no such scenario, and ErrInOtherScenario if
// the honeypot belongs to another scenario, which it must leave first, so that
// nothing takes a honeypot from a scenario by mistake.
//
// SetScenario must run in a transaction. It locks the scenario before the
// honeypot, as the deletion of a scenario does, so that both cannot wait for
// each other: the scenario with a lock that keeps it from being deleted
// meanwhile, the honeypot until the end of the transaction.
func (s *Store) SetScenario(ctx context.Context, id, scenarioID string) (Honeypot, bool, error) {
	// A missing honeypot is reported first, as for any other change of it.
	// Reading it takes no lock, so the order of the locks below holds.
	if _, err := s.Get(ctx, id); err != nil {
		return Honeypot{}, false, err
	}
	if scenarioID != "" {
		if err := s.lockScenario(ctx, scenarioID); err != nil {
			return Honeypot{}, false, err
		}
	}
	current, err := scan(s.db.QueryRow(ctx, `SELECT `+columns+` FROM honeypots WHERE id = $1 FOR UPDATE`, id))
	if db.NotFound(err) {
		return Honeypot{}, false, ErrNotFound
	}
	if err != nil {
		return Honeypot{}, false, fmt.Errorf("lock honeypot %s: %w", id, err)
	}
	switch {
	case scenarioID == "" && current.ScenarioID == nil,
		current.ScenarioID != nil && *current.ScenarioID == scenarioID:
		return current, false, nil
	case scenarioID != "" && current.ScenarioID != nil:
		return Honeypot{}, false, ErrInOtherScenario
	}

	var target *string
	if scenarioID != "" {
		target = &scenarioID
	}
	h, err := scan(s.db.QueryRow(ctx, `
UPDATE honeypots SET scenario_id = $2, updated_at = clock_timestamp()
WHERE id = $1
RETURNING `+columns, id, target))
	if err != nil {
		return Honeypot{}, false, fmt.Errorf("set scenario of honeypot %s: %w", id, err)
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

// Create creates a honeypot on behalf of actor and records it in the audit
// log, with the field scenario_id if it joins a scenario.
func Create(ctx context.Context, d DB, keys *secretbox.Keyring, actor audit.Actor, spec Spec) (Created, error) {
	var c Created
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		var err error
		if c, err = NewStore(tx, keys).Create(ctx, spec); err != nil {
			return err
		}
		var changed []string
		if spec.ScenarioID != "" {
			changed = []string{FieldScenarioID}
		}
		return record(ctx, tx, actor, audit.ActionHoneypotCreate, c.ID, changed)
	})
	if err != nil {
		return Created{}, fmt.Errorf("create honeypot: %w", err)
	}
	return c, nil
}

// Update applies c to the honeypot id on behalf of actor, as Store.Update
// does, and records the names of the changed fields in the audit log. A change
// that changes nothing is not recorded.
func Update(ctx context.Context, d DB, actor audit.Actor, id string, c Change) (Honeypot, error) {
	var h Honeypot
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		var (
			changed []string
			err     error
		)
		if h, changed, err = NewStore(tx, nil).Update(ctx, id, c); err != nil || len(changed) == 0 {
			return err
		}
		return record(ctx, tx, actor, audit.ActionHoneypotUpdate, id, changed)
	})
	if err != nil {
		return Honeypot{}, fmt.Errorf("update honeypot: %w", err)
	}
	return h, nil
}

// ReplaceSecret gives the honeypot id a new secret on behalf of actor, as
// Store.ReplaceSecret does, and records the change of the field secret in the
// audit log. Clearing what the last sensor reported follows from it and is not
// recorded as a field of its own.
func ReplaceSecret(ctx context.Context, d DB, keys *secretbox.Keyring, actor audit.Actor, id string) (Created, error) {
	var c Created
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		var err error
		if c, err = NewStore(tx, keys).ReplaceSecret(ctx, id); err != nil {
			return err
		}
		return record(ctx, tx, actor, audit.ActionHoneypotUpdate, id, []string{FieldSecret})
	})
	if err != nil {
		return Created{}, fmt.Errorf("replace secret of honeypot: %w", err)
	}
	return c, nil
}

// ReadSecret returns the honeypot id with its secret on behalf of actor, as
// Store.Secret does, and records the read in the audit log in the same
// transaction, so that the secret never leaves without an entry. Every read is
// recorded, unlike other reads that a caller can repeat at will: it is rare,
// and an entry that a throttle left out would be the one that mattered. The
// entry holds the honeypot, never the secret.
func ReadSecret(ctx context.Context, d DB, keys *secretbox.Keyring, actor audit.Actor, id string) (Created, error) {
	var c Created
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		var err error
		if c, err = NewStore(tx, keys).Secret(ctx, id); err != nil {
			return err
		}
		return audit.NewStore(tx).Record(ctx, audit.Entry{
			Action:   audit.ActionHoneypotSecretRead,
			Outcome:  audit.OutcomeSuccess,
			Actor:    actor,
			Resource: audit.Resource{Type: ResourceType, ID: id},
		}.WithRequest(ctx))
	})
	if err != nil {
		return Created{}, fmt.Errorf("read secret of honeypot: %w", err)
	}
	return c, nil
}

// SetScenario assigns the honeypot id to the scenario scenarioID, or detaches
// it if scenarioID is empty, on behalf of actor, as Store.SetScenario does,
// and records the change in the audit log. A change that changes nothing is
// not recorded.
func SetScenario(ctx context.Context, d DB, actor audit.Actor, id, scenarioID string) (Honeypot, error) {
	var h Honeypot
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		var (
			changed bool
			err     error
		)
		if h, changed, err = NewStore(tx, nil).SetScenario(ctx, id, scenarioID); err != nil || !changed {
			return err
		}
		return record(ctx, tx, actor, audit.ActionHoneypotUpdate, id, []string{FieldScenarioID})
	})
	if err != nil {
		return Honeypot{}, fmt.Errorf("set scenario of honeypot: %w", err)
	}
	return h, nil
}

// Delete deletes the honeypot id on behalf of actor and records it in the
// audit log. It returns ErrNotFound if there is none.
func Delete(ctx context.Context, d DB, actor audit.Actor, id string) error {
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		if err := NewStore(tx, nil).Delete(ctx, id); err != nil {
			return err
		}
		return record(ctx, tx, actor, audit.ActionHoneypotDelete, id, nil)
	})
	if err != nil {
		return fmt.Errorf("delete honeypot: %w", err)
	}
	return nil
}
