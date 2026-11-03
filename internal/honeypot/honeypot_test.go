// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeypot

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
	"nyktus.org/nyktus/internal/severity"
)

func TestValidateName(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"a", "db01 replica", "Pr\u00fcfserver", strings.Repeat("x", MaxNameLength), strings.Repeat("\u00fc", MaxNameLength)} {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{"", " a", "a ", strings.Repeat("x", MaxNameLength+1), "a\nb", "a\x00b", "a\u202eb", "\xff"} {
		if err := ValidateName(name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("ValidateName(%q) = %v, want ErrInvalidName", name, err)
		}
	}
}

func TestValidateNotes(t *testing.T) {
	t.Parallel()

	for _, notes := range []string{"", "VLAN 20, rack 4.\r\nOwner:\tIT", strings.Repeat("\u00e4", MaxNotesLength)} {
		if err := ValidateNotes(notes); err != nil {
			t.Errorf("ValidateNotes(%q) = %v, want nil", notes, err)
		}
	}
	for _, notes := range []string{strings.Repeat("x", MaxNotesLength+1), "a\x00b", "a\x1bb", "a\u200bb", "\xff"} {
		if err := ValidateNotes(notes); !errors.Is(err, ErrInvalidNotes) {
			t.Errorf("ValidateNotes(%q) = %v, want ErrInvalidNotes", notes, err)
		}
	}
}

func TestValidateTechniques(t *testing.T) {
	t.Parallel()

	valid := []string{
		"T1001", "T1003", "T1003.001", "T1005", "T1007", "T1010", "T1012", "T1014", "T1016", "T1018",
		"T1020", "T1021", "T1025", "T1027", "T1029", "T1030", "T1033", "T1036", "T1037", "T1039",
	}
	for _, ids := range [][]string{nil, {}, {"T1021.004"}, valid} {
		if err := ValidateTechniques(ids); err != nil {
			t.Errorf("ValidateTechniques(%q) = %v, want nil", ids, err)
		}
	}
	for _, ids := range [][]string{append(valid, "T1040"), {"T1110", "T1110"}, {"T9999"}, {"t1110"}, {""}} {
		if err := ValidateTechniques(ids); !errors.Is(err, ErrInvalidTechniques) {
			t.Errorf("ValidateTechniques(%q) = %v, want ErrInvalidTechniques", ids, err)
		}
	}
}

func TestSpec_ValidatesTheService(t *testing.T) {
	t.Parallel()

	for _, s := range Services {
		if err := (Spec{Service: s, Name: "a"}).validate(); err != nil {
			t.Errorf("service %q: %v", s, err)
		}
	}
	for _, s := range []Service{"", "smtp", "http", "SSH", "ssh "} {
		if err := (Spec{Service: s, Name: "a"}).validate(); !errors.Is(err, ErrInvalidService) {
			t.Errorf("service %q: %v, want ErrInvalidService", s, err)
		}
	}
}

// Every service starts at medium: whatever it emulates, it answers every
// scanner of the own team as well.
func TestService_DefaultSeverity(t *testing.T) {
	t.Parallel()

	for _, s := range Services {
		if l := s.DefaultSeverity(); l != severity.Medium {
			t.Errorf("%s.DefaultSeverity() = %q, want medium", s, l)
		}
	}
	if l := Service("smtp").DefaultSeverity(); l != "" {
		t.Errorf("DefaultSeverity of an unknown service = %q, want none", l)
	}
}

// A honeypot takes every level that a decoy can suggest, but not info. The
// validation runs without a database, because the store maps the check of the
// schema to the same error.
func TestSpecAndChange_ValidateTheSeverity(t *testing.T) {
	t.Parallel()

	for _, l := range severity.Suggested {
		if err := (Spec{Service: ServiceSSH, Name: "a", Severity: &l}).validate(); err != nil {
			t.Errorf("Spec with severity %q: %v", l, err)
		}
		if err := (Change{Severity: &l}).validate(); err != nil {
			t.Errorf("Change to severity %q: %v", l, err)
		}
	}
	for _, l := range []severity.Level{"", severity.Info, "urgent", "LOW"} {
		if err := (Spec{Service: ServiceSSH, Name: "a", Severity: &l}).validate(); !errors.Is(err, ErrInvalidSeverity) {
			t.Errorf("Spec with severity %q: %v, want ErrInvalidSeverity", l, err)
		}
		if err := (Change{Severity: &l}).validate(); !errors.Is(err, ErrInvalidSeverity) {
			t.Errorf("Change to severity %q: %v, want ErrInvalidSeverity", l, err)
		}
	}
}

func TestChange_ValidatesEachField(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", MaxNameLength+1)
	notes := strings.Repeat("x", MaxNotesLength+1)
	for _, tt := range []struct {
		c    Change
		want error
	}{
		{Change{Name: &long}, ErrInvalidName},
		{Change{Notes: &notes}, ErrInvalidNotes},
		{Change{Techniques: []string{"T9999"}, SetTechniques: true}, ErrInvalidTechniques},
		{Change{Techniques: []string{"T9999"}}, nil},
	} {
		if err := tt.c.validate(); !errors.Is(err, tt.want) {
			t.Errorf("validate(%+v) = %v, want %v", tt.c, err, tt.want)
		}
	}
	if !(Change{}).IsEmpty() || (Change{SetTechniques: true}).IsEmpty() || (Change{Enabled: new(bool)}).IsEmpty() {
		t.Error("IsEmpty does not match the fields of the change")
	}
}

// A secret carries 256 bits from crypto/rand in 43 characters of base64url
// without a prefix, which would mark the host of the sensor, and is stored as
// its SHA-256 hash and sealed for the console to show again, bound to the hash.
func TestNewSecret(t *testing.T) {
	t.Parallel()

	keys := secretboxtest.Keyring(t)
	store := &Store{keys: keys}
	format := regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	seen := map[Secret]bool{}
	for range 1000 {
		s, hash, sealed, err := store.newSecret()
		if err != nil {
			t.Fatal(err)
		}
		if !format.MatchString(string(s)) || seen[s] {
			t.Fatalf("newSecret() = %q, want 43 characters of base64url, unique", string(s))
		}
		if sum := sha256.Sum256([]byte(s)); !bytes.Equal(hash, sum[:]) {
			t.Fatalf("hash of %q = %x, want its SHA-256", string(s), hash)
		}
		if opened, err := keys.Open(sealed, secretData(hash)); err != nil || string(opened) != string(s) {
			t.Fatalf("Open(sealed) = %q, %v; want the secret", opened, err)
		}
		if _, err := keys.Open(sealed, secretData(make([]byte, len(hash)))); err == nil {
			t.Fatal("a sealed secret opens with the hash of another secret")
		}
		if n := len(sealed); n < 30 || n > 200 {
			t.Fatalf("len(sealed) = %d, want what the schema accepts", n)
		}
		seen[s] = true
	}
}

// A store without keys creates no secret, instead of storing one that cannot
// be shown again.
func TestNewSecret_NeedsKeys(t *testing.T) {
	t.Parallel()

	if _, _, _, err := (&Store{}).newSecret(); !errors.Is(err, errNoKeys) {
		t.Errorf("newSecret() without keys error = %v, want errNoKeys", err)
	}
}

// The secret never reaches a log, an error or JSON, also not as part of the
// honeypot that it was created with, and the name and the notes, which are
// inventory, never reach a log.
func TestCreated_KeepsTheSecretAndTheInventoryOutOfLogs(t *testing.T) {
	t.Parallel()

	// A recognizable value of the length of a secret.
	secret := strings.Repeat("leak-", 8) + "end"
	c := Created{
		Honeypot: Honeypot{ID: "00000000-0000-4000-8000-000000000000", Service: ServiceSSH, Name: "secret-name", Notes: "secret-notes"},
		Secret:   Secret(secret),
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("test", slog.Any("honeypot", c.Honeypot), slog.Any("secret", c.Secret))
	logger.Info("test", slog.Any("created", c))
	encoded, err := json.Marshal(c) //nolint:gosec // The test proves that the secret is redacted in JSON.
	if err != nil {
		t.Fatal(err)
	}
	outputs := map[string]string{
		"log":   buf.String(),
		"json":  string(encoded),
		"error": fmt.Errorf("create: %v %+v %#v %s", c, c, c, c.Secret).Error(),
	}
	for name, out := range outputs {
		if strings.Contains(out, secret) {
			t.Errorf("%s %s contains the secret", name, out)
		}
	}
	for _, leak := range []string{"secret-name", "secret-notes"} {
		if strings.Contains(buf.String(), leak) {
			t.Errorf("log %s contains %q", buf.String(), leak)
		}
	}
	if !strings.Contains(buf.String(), c.ID) {
		t.Errorf("log %s does not name the honeypot", buf.String())
	}
}
