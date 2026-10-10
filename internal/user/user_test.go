// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestParseEmail(t *testing.T) {
	t.Parallel()

	// 64 + 1 + 189 = 254 bytes.
	longest := strings.Repeat("a", 64) + "@" + strings.Repeat("b", 185) + ".org"
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "jane@example.com", want: "jane@example.com"},
		{in: "Jane.Doe+nyktus@Example.COM", want: "jane.doe+nyktus@example.com"},
		{in: "jürgen@bücher.example", want: "jürgen@bücher.example"},
		// Upper case beyond ASCII and decomposed umlauts map to the same stored
		// address.
		{in: "J\u00dcRGEN@B\u00dcCHER.EXAMPLE", want: "j\u00fcrgen@b\u00fccher.example"},
		{in: "Ju\u0308rgen@Bu\u0308cher.example", want: "j\u00fcrgen@b\u00fccher.example"},
		{in: "admin@localhost", want: "admin@localhost"},
		{in: longest, want: longest},
		{in: longest + "x", wantErr: true},
		// U+023A is two bytes long, its lower case U+2C65 three.
		{in: strings.Repeat("Ⱥ", 84) + "@b.org", wantErr: true},
		{in: "", wantErr: true},
		{in: "jane", wantErr: true},
		{in: "jane@", wantErr: true},
		{in: "@example.com", wantErr: true},
		{in: "Jane <jane@example.com>", wantErr: true},
		{in: "<jane@example.com>", wantErr: true},
		{in: "jane@example.com (Jane)", wantErr: true},
		{in: " jane@example.com", wantErr: true},
		{in: "jane@example.com\n", wantErr: true},
		{in: `"jane doe"@example.com`, wantErr: true},
		{in: `"jane@home"@example.com`, wantErr: true},
		{in: "jane,joe@example.com", wantErr: true},
		{in: "jane@example.com\u202e", wantErr: true},
		{in: "jane\xff@example.com", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseEmail(tt.in)
		switch {
		case tt.wantErr && !errors.Is(err, ErrInvalidEmail):
			t.Errorf("ParseEmail(%q) = %q, %v, want ErrInvalidEmail", tt.in, got, err)
		case !tt.wantErr && (err != nil || got != tt.want):
			t.Errorf("ParseEmail(%q) = %q, %v, want %q", tt.in, got, err, tt.want)
		}
	}
}

func TestParseDisplayName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in    string
		valid bool
	}{
		{in: "Jane Doe", valid: true},
		{in: "J", valid: true},
		{in: "Jürgen Ölmann-Straße", valid: true},
		{in: strings.Repeat("ä", MaxDisplayNameLength), valid: true},
		{in: strings.Repeat("ä", MaxDisplayNameLength+1)},
		{in: ""},
		{in: " Jane"},
		{in: "Jane "},
		{in: "Jane\tDoe"},
		{in: "Jane\nDoe"},
		{in: "Jane\u00a0Doe"},
		// A right-to-left override would display this name as "Jane Admin".
		{in: "Jane \u202enimdA"},
		{in: "Jane\xff"},
	}
	for _, tt := range tests {
		got, err := ParseDisplayName(tt.in)
		switch {
		case tt.valid && (err != nil || got != tt.in):
			t.Errorf("ParseDisplayName(%q) = %q, %v, want it unchanged", tt.in, got, err)
		case !tt.valid && !errors.Is(err, ErrInvalidDisplayName):
			t.Errorf("ParseDisplayName(%q) = %q, %v, want ErrInvalidDisplayName", tt.in, got, err)
		}
	}
}

func TestUser_LogValueOmitsHashAndAddress(t *testing.T) {
	t.Parallel()

	u := User{
		ID:           "7a1e0e4c-2f8b-4f7e-9a51-1f0a3c4d5e6f",
		Email:        "jane@example.com",
		Role:         RoleAdmin,
		Status:       StatusActive,
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("test", slog.Any("user", u))

	out := buf.String()
	if strings.Contains(out, "argon2id") || strings.Contains(out, u.Email) {
		t.Errorf("log record contains the hash or the address: %s", out)
	}
	if !strings.Contains(out, u.ID) || !strings.Contains(out, `"role":"admin"`) {
		t.Errorf("log record lacks the ID or the role: %s", out)
	}
}

func TestRole_Valid(t *testing.T) {
	t.Parallel()

	for _, r := range []Role{RoleAdmin, RoleEditor, RoleViewer} {
		if !r.Valid() {
			t.Errorf("Role(%q).Valid() = false, want true", r)
		}
	}
	for _, r := range []Role{"", "Admin", "root", "owner"} {
		if r.Valid() {
			t.Errorf("Role(%q).Valid() = true, want false", r)
		}
	}
}
