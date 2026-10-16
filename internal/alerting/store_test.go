// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package alerting

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/platform/secretbox"
	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
)

type storeFixture struct {
	owner   *pgxpool.Pool
	console *pgxpool.Pool
	keys    *secretbox.Keyring
}

func newStoreFixture(t *testing.T) storeFixture {
	t.Helper()
	ownerURL, consoleURL := schematest.Console(t)
	return storeFixture{
		owner:   schematest.Open(t, ownerURL),
		console: schematest.Open(t, consoleURL),
		keys:    secretboxtest.Keyring(t),
	}
}

// create creates a channel with the console's role in a transaction.
func (f storeFixture) create(t *testing.T, spec Spec) (Channel, error) {
	t.Helper()
	var c Channel
	err := pgx.BeginFunc(t.Context(), f.console, func(tx pgx.Tx) error {
		var err error
		c, err = NewStore(tx, f.keys).Create(t.Context(), spec)
		return err
	})
	return c, err
}

func (f storeFixture) mustCreate(t *testing.T, spec Spec) Channel {
	t.Helper()
	c, err := f.create(t, spec)
	if err != nil {
		t.Fatalf("Create(%s): %v", spec.Name, err)
	}
	return c
}

func (f storeFixture) update(t *testing.T, id string, c Change) (Channel, []string, error) {
	t.Helper()
	var (
		ch      Channel
		changed []string
	)
	err := pgx.BeginFunc(t.Context(), f.console, func(tx pgx.Tx) error {
		var err error
		ch, changed, err = NewStore(tx, f.keys).Update(t.Context(), id, c)
		return err
	})
	return ch, changed, err
}

// secrets reads the sealed secrets of the channel id as the owner.
func (f storeFixture) secrets(t *testing.T, id string) (sealedURL, sealedHeader []byte) {
	t.Helper()
	err := f.owner.QueryRow(t.Context(), `SELECT url, header_value FROM alert_channel_secrets WHERE channel_id = $1`, id).
		Scan(&sealedURL, &sealedHeader)
	if err != nil {
		t.Fatalf("read secrets: %v", err)
	}
	return sealedURL, sealedHeader
}

func webhookSpec(name string) Spec {
	return Spec{
		Name: name, Type: TypeWebhook, Enabled: true, URL: hookURL,
		Header: &Header{Name: "Authorization", Value: "Bearer s3cr3t"},
	}
}

func TestCreate_StoresTheSecretsEncryptedAndBoundToTheChannel(t *testing.T) {
	t.Parallel()
	f := newStoreFixture(t)

	c := f.mustCreate(t, webhookSpec("SOAR"))
	if c.Target != "https://hooks.example.com" || c.HeaderName == nil || *c.HeaderName != "Authorization" ||
		!c.Enabled || c.Type != TypeWebhook || !c.CreatedAt.Equal(c.UpdatedAt) {
		t.Errorf("channel = %+v", c)
	}
	sealedURL, sealedHeader := f.secrets(t, c.ID)
	for _, sealed := range [][]byte{sealedURL, sealedHeader} {
		if bytes.Contains(sealed, []byte("s3cr3t")) || bytes.Contains(sealed, []byte("hooks.example.com")) {
			t.Error("a secret is stored in plain text")
		}
	}
	plainURL, err := f.keys.Open(sealedURL, associatedData(purposeURL, c.ID))
	if err != nil || string(plainURL) != hookURL {
		t.Errorf("open URL = %q, %v", plainURL, err)
	}
	plainHeader, err := f.keys.Open(sealedHeader, associatedData(purposeHeaderValue, c.ID))
	if err != nil || string(plainHeader) != "Bearer s3cr3t" {
		t.Errorf("open header value = %q, %v", plainHeader, err)
	}

	// A value copied into another column or channel does not decrypt.
	other := f.mustCreate(t, webhookSpec("Other"))
	if _, err := f.keys.Open(sealedURL, associatedData(purposeHeaderValue, c.ID)); err == nil {
		t.Error("the URL decrypts as the value of a header")
	}
	if _, err := f.keys.Open(sealedURL, associatedData(purposeURL, other.ID)); err == nil {
		t.Error("the URL decrypts as the URL of another channel")
	}
}

// The console writes secrets but can never read them back, so that whoever
// takes over its database role does not obtain the channels.
func TestConsole_CannotReadSecrets(t *testing.T) {
	t.Parallel()
	f := newStoreFixture(t)
	c := f.mustCreate(t, webhookSpec("SOAR"))

	for _, query := range []string{
		`SELECT url FROM alert_channel_secrets`,
		`SELECT header_value FROM alert_channel_secrets`,
		`SELECT * FROM alert_channel_secrets`,
		`SELECT count(*) FROM alert_channel_secrets WHERE url IS NOT NULL`,
	} {
		var pgErr *pgconn.PgError
		_, err := f.console.Exec(t.Context(), query)
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s: error = %v, want permission denied", query, err)
		}
	}
	// Returning the secret from a write is reading it as well.
	var pgErr *pgconn.PgError
	_, err := f.console.Exec(t.Context(), `UPDATE alert_channel_secrets SET url = url WHERE channel_id = $1 RETURNING url`, c.ID)
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Errorf("UPDATE ... RETURNING url: error = %v, want permission denied", err)
	}
}

func TestCreate_Rejections(t *testing.T) {
	t.Parallel()
	f := newStoreFixture(t)
	f.mustCreate(t, webhookSpec("SOAR"))

	if _, err := f.create(t, webhookSpec("SOAR")); !errors.Is(err, ErrNameTaken) {
		t.Errorf("same name: error = %v, want ErrNameTaken", err)
	}
	if _, err := f.create(t, Spec{Name: "Slack", Type: TypeSlack, URL: hookURL, Header: &Header{Name: "X", Value: "y"}}); !errors.Is(err, ErrHeaderNotAllowed) {
		t.Errorf("header for slack: error = %v, want ErrHeaderNotAllowed", err)
	}
	for i := 1; i < MaxChannels; i++ {
		f.mustCreate(t, Spec{Name: fmt.Sprintf("Channel %d", i), Type: TypeSlack, URL: hookURL})
	}
	if _, err := f.create(t, Spec{Name: "One too many", Type: TypeSlack, URL: hookURL}); !errors.Is(err, ErrTooManyChannels) {
		t.Errorf("channel %d: error = %v, want ErrTooManyChannels", MaxChannels+1, err)
	}
}

func TestList_OrdersByName(t *testing.T) {
	t.Parallel()
	f := newStoreFixture(t)
	for _, name := range []string{"b", "c", "a"} {
		f.mustCreate(t, Spec{Name: name, Type: TypeSlack, URL: hookURL})
	}
	list, err := NewStore(f.console, nil).List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range list {
		names = append(names, c.Name)
	}
	if !slices.Equal(names, []string{"a", "b", "c"}) {
		t.Errorf("names = %v", names)
	}
}

func TestGet_UnknownOrMalformedIdentifier_IsNotFound(t *testing.T) {
	t.Parallel()
	f := newStoreFixture(t)
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if _, err := NewStore(f.console, nil).Get(t.Context(), id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%s) = %v, want ErrNotFound", id, err)
		}
	}
}

func TestUpdate(t *testing.T) {
	t.Parallel()
	f := newStoreFixture(t)
	c := f.mustCreate(t, webhookSpec("SOAR"))
	oldURL, oldHeader := f.secrets(t, c.ID)

	name, off := "Renamed", false
	got, changed, err := f.update(t, c.ID, Change{Name: &name, Enabled: &off})
	if err != nil || got.Name != name || got.Enabled || !slices.Equal(changed, []string{FieldName, FieldEnabled}) {
		t.Fatalf("rename and disable: %+v, %v, %v", got, changed, err)
	}
	if u, h := f.secrets(t, c.ID); !bytes.Equal(u, oldURL) || !bytes.Equal(h, oldHeader) {
		t.Error("a change of name and status replaced the secrets")
	}

	newURL := Secret("https://other.example.org:8443/hook?token=abc")
	got, changed, err = f.update(t, c.ID, Change{URL: &newURL})
	if err != nil || got.Target != "https://other.example.org:8443" || !slices.Equal(changed, []string{FieldURL}) {
		t.Fatalf("new URL: %+v, %v, %v", got, changed, err)
	}
	u, h := f.secrets(t, c.ID)
	if plain, err := f.keys.Open(u, associatedData(purposeURL, c.ID)); err != nil || string(plain) != string(newURL) {
		t.Errorf("stored URL = %q, %v", plain, err)
	}
	if !bytes.Equal(h, oldHeader) {
		t.Error("a new URL replaced the header")
	}

	got, changed, err = f.update(t, c.ID, Change{Header: &Header{Name: "X-API-Key", Value: "k2"}})
	if err != nil || got.HeaderName == nil || *got.HeaderName != "X-API-Key" || !slices.Equal(changed, []string{FieldHeader}) {
		t.Fatalf("new header: %+v, %v, %v", got, changed, err)
	}
	_, h = f.secrets(t, c.ID)
	if plain, err := f.keys.Open(h, associatedData(purposeHeaderValue, c.ID)); err != nil || string(plain) != "k2" {
		t.Errorf("stored header value = %q, %v", plain, err)
	}

	got, changed, err = f.update(t, c.ID, Change{RemoveHeader: true})
	if err != nil || got.HeaderName != nil || !slices.Equal(changed, []string{FieldHeader}) {
		t.Fatalf("remove header: %+v, %v, %v", got, changed, err)
	}
	if _, h := f.secrets(t, c.ID); h != nil {
		t.Error("the value of a removed header stays stored")
	}
	if _, changed, err := f.update(t, c.ID, Change{RemoveHeader: true}); err != nil || len(changed) != 0 {
		t.Errorf("remove a missing header: %v, %v; want no change", changed, err)
	}

	slack := f.mustCreate(t, Spec{Name: "Slack", Type: TypeSlack, URL: hookURL})
	if _, _, err := f.update(t, slack.ID, Change{Header: &Header{Name: "X", Value: "y"}}); !errors.Is(err, ErrHeaderNotAllowed) {
		t.Errorf("header for slack: error = %v, want ErrHeaderNotAllowed", err)
	}
	if _, _, err := f.update(t, "00000000-0000-4000-8000-000000000000", Change{Name: &name}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown channel: error = %v, want ErrNotFound", err)
	}
	if _, _, err := f.update(t, slack.ID, Change{Name: &name}); !errors.Is(err, ErrNameTaken) {
		t.Errorf("taken name: error = %v, want ErrNameTaken", err)
	}
}

func TestDelete_OnlyDisabledChannels(t *testing.T) {
	t.Parallel()
	f := newStoreFixture(t)
	c := f.mustCreate(t, webhookSpec("SOAR"))
	s := NewStore(f.console, nil)

	if err := s.Delete(t.Context(), c.ID); !errors.Is(err, ErrEnabled) {
		t.Fatalf("delete an enabled channel: error = %v, want ErrEnabled", err)
	}
	off := false
	if _, _, err := f.update(t, c.ID, Change{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(t.Context(), c.ID); err != nil {
		t.Fatalf("delete a disabled channel: %v", err)
	}
	var n int
	if err := f.owner.QueryRow(t.Context(), `SELECT count(*) FROM alert_channel_secrets`).Scan(&n); err != nil || n != 0 {
		t.Errorf("secrets left after deletion: %d, %v", n, err)
	}
	for _, id := range []string{c.ID, "not-a-uuid"} {
		if err := s.Delete(t.Context(), id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Delete(%s) = %v, want ErrNotFound", id, err)
		}
	}
}

func TestChanges_AreAudited(t *testing.T) {
	t.Parallel()
	f := newStoreFixture(t)
	var userID string
	err := f.owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, password_hash)
VALUES ('admin@example.com', 'Admin', 'admin', 'active', '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA')
RETURNING id`).Scan(&userID)
	if err != nil {
		t.Fatal(err)
	}
	actor := audit.Actor{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: userID}

	var c Channel
	if err := pgx.BeginFunc(t.Context(), f.console, func(tx pgx.Tx) error {
		c, err = Create(t.Context(), tx, f.keys, actor, webhookSpec("SOAR"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	off := false
	u := Secret(hookURL + "2")
	if err := pgx.BeginFunc(t.Context(), f.console, func(tx pgx.Tx) error {
		_, err := Update(t.Context(), tx, f.keys, actor, c.ID, Change{Enabled: &off, URL: &u})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := Delete(t.Context(), f.console, actor, c.ID); err != nil {
		t.Fatal(err)
	}

	rows, err := f.owner.Query(t.Context(), `
SELECT action, resource_type, resource_id, changed_fields FROM audit_entries ORDER BY occurred_at, id`)
	if err != nil {
		t.Fatal(err)
	}
	type entry struct {
		Action, Type, ID string
		Changed          []string
	}
	entries, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (entry, error) {
		var e entry
		return e, row.Scan(&e.Action, &e.Type, &e.ID, &e.Changed)
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []entry{
		{string(audit.ActionAlertChannelCreate), ResourceType, c.ID, nil},
		{string(audit.ActionAlertChannelUpdate), ResourceType, c.ID, []string{FieldEnabled, FieldURL}},
		{string(audit.ActionAlertChannelDelete), ResourceType, c.ID, nil},
	}
	if len(entries) != len(want) {
		t.Fatalf("entries = %+v", entries)
	}
	for i := range want {
		if entries[i].Action != want[i].Action || entries[i].Type != want[i].Type || entries[i].ID != want[i].ID ||
			!slices.Equal(entries[i].Changed, want[i].Changed) {
			t.Errorf("entry %d = %+v, want %+v", i, entries[i], want[i])
		}
	}
}

// Every type that the code knows is accepted by the schema, and every header
// that the code rejects is rejected by the schema as well.
func TestSchema_AgreesWithTheCode(t *testing.T) {
	t.Parallel()
	f := newStoreFixture(t)

	for _, typ := range Types {
		if _, err := f.create(t, Spec{Name: string(typ), Type: typ, URL: hookURL}); err != nil {
			t.Errorf("type %s: %v", typ, err)
		}
	}
	insert := func(name, header string) error {
		_, err := f.console.Exec(t.Context(), `
INSERT INTO alert_channels (name, type, target, header_name) VALUES ($1, 'webhook', 'https://h.example.com', $2)`, name, header)
		return err
	}
	for i, h := range append(slices.Clone(reservedHeaders), "Proxy-Authorization", "X Token") {
		if err := insert(fmt.Sprintf("reserved %d", i), h); db.Violation(err, db.CheckViolation) != "alert_channels_header_name_check" {
			t.Errorf("header %q: error = %v, want alert_channels_header_name_check", h, err)
		}
	}
	if err := insert("allowed", "X-API-Key"); err != nil {
		t.Errorf("header X-API-Key: %v", err)
	}
	_, err := f.console.Exec(t.Context(), `
INSERT INTO alert_channels (name, type, target, header_name) VALUES ('slack header', 'slack', 'https://h.example.com', 'X-Token')`)
	if db.Violation(err, db.CheckViolation) != "alert_channels_header_name_check" {
		t.Errorf("header for slack: error = %v, want alert_channels_header_name_check", err)
	}
	for _, target := range []string{"https://h.example.com/path", "https://u@h.example.com", "ftp://h.example.com", "https://h.example.com?q"} {
		_, err := f.console.Exec(t.Context(), `
INSERT INTO alert_channels (name, type, target) VALUES ($1, 'slack', $1)`, target)
		if db.Violation(err, db.CheckViolation) != "alert_channels_target_check" {
			t.Errorf("target %q: error = %v, want alert_channels_target_check", target, err)
		}
	}
}

// The checks of the schema only fire if its rules and those of the code ever
// differ. The mapping still turns them into the errors of the validation.
func TestMapWriteError_MapsTheConstraintsOfTheSchema(t *testing.T) {
	t.Parallel()

	for constraint, want := range constraintErrors {
		err := fmt.Errorf("insert: %w", &pgconn.PgError{Code: db.CheckViolation, ConstraintName: constraint})
		if got := mapWriteError(err); !errors.Is(got, want) {
			t.Errorf("mapWriteError(%s) = %v, want %v", constraint, got, want)
		}
	}
	taken := &pgconn.PgError{Code: db.UniqueViolation, ConstraintName: "alert_channels_name_key"}
	if got := mapWriteError(taken); !errors.Is(got, ErrNameTaken) {
		t.Errorf("mapWriteError(name key) = %v, want ErrNameTaken", got)
	}
	other := &pgconn.PgError{Code: db.CheckViolation, ConstraintName: "alert_channels_updated_at_check"}
	if got := mapWriteError(other); !errors.Is(got, other) {
		t.Errorf("mapWriteError(other check) = %v, want it unchanged", got)
	}
}
