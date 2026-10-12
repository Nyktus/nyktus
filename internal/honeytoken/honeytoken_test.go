// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeytoken

import (
	"bytes"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"a", "Quarterly report 2026", "Pr\u00fcfbericht", strings.Repeat("x", MaxNameLength), strings.Repeat("\u00fc", MaxNameLength)} {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{
		"", " a", "a ", strings.Repeat("x", MaxNameLength+1), "a\nb", "a\tb", "a\x00b", "a\x7fb",
		"a\u202eb", // right-to-left override
		"a\u200bb", // zero width space
		"\xff",
	} {
		if err := ValidateName(name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("ValidateName(%q) = %v, want ErrInvalidName", name, err)
		}
	}
}

func TestValidateNotes(t *testing.T) {
	t.Parallel()

	for _, notes := range []string{
		"", "Share \\\\fs01\\finance, folder Q3.\r\nOwner:\tIT", " leading and trailing ", strings.Repeat("\u00e4", MaxNotesLength),
		"Q3\u00a0forecast", // a non-breaking space, as in text copied from a document
	} {
		if err := ValidateNotes(notes); err != nil {
			t.Errorf("ValidateNotes(%q) = %v, want nil", notes, err)
		}
	}
	for _, notes := range []string{strings.Repeat("x", MaxNotesLength+1), "a\x00b", "a\x1bb", "a\u202eb", "a\u200bb", "\xff"} {
		if err := ValidateNotes(notes); !errors.Is(err, ErrInvalidNotes) {
			t.Errorf("ValidateNotes(%q) = %v, want ErrInvalidNotes", notes, err)
		}
	}
}

func TestValidateRedirectURL(t *testing.T) {
	t.Parallel()

	for _, u := range []string{
		"https://www.example.com",
		"http://intranet.example.com/wiki/Finance?page=2#top",
		"https://example.com:8443/",
		"https://xn--bcher-kva.example/",
		"https://1.example.com/",
		"https://example.123abc/",
		"https://" + strings.Repeat("a", MaxRedirectURLLength-len("https://")),
	} {
		if err := ValidateRedirectURL(u); err != nil {
			t.Errorf("ValidateRedirectURL(%q) = %v, want nil", u, err)
		}
	}
	for _, u := range []string{
		"",
		"www.example.com",
		"//www.example.com",
		"ftp://example.com",
		"javascript:alert(1)",
		"data:text/html,x",
		"HTTPS://example.com",
		"https:example.com",
		"https://",
		"https:///path",
		"https://user:pass@example.com",
		"https://user@example.com",
		"https://127.0.0.1/",
		"https://10.0.0.1:8080/",
		"https://[::1]/",
		"https://[fe80::1%25en0]/",
		"https://2130706433/",
		"https://0x7f.1/",
		"https://0X7F000001/",
		"https://example.0x1f/",
		"https://example.42/",
		"https://example.42./",
		"https://exa mple.com/",
		"https://example.com/a b",
		"https://example.com/\n",
		"https://b\u00fccher.example/",
		"https://example.com/%zz",
		"https://" + strings.Repeat("a", MaxRedirectURLLength-len("https://")+1),
	} {
		if err := ValidateRedirectURL(u); !errors.Is(err, ErrInvalidRedirectURL) {
			t.Errorf("ValidateRedirectURL(%q) = %v, want ErrInvalidRedirectURL", u, err)
		}
	}
}

func TestValidateTechniques(t *testing.T) {
	t.Parallel()

	valid := []string{
		"T1001", "T1003", "T1003.001", "T1005", "T1007", "T1010", "T1012", "T1014", "T1016", "T1018",
		"T1020", "T1021", "T1025", "T1027", "T1029", "T1030", "T1033", "T1036", "T1037", "T1039",
	}
	for _, ids := range [][]string{nil, {}, {"T1078"}, valid} {
		if err := ValidateTechniques(ids); err != nil {
			t.Errorf("ValidateTechniques(%q) = %v, want nil", ids, err)
		}
	}
	for _, ids := range [][]string{
		append(valid, "T1040"),
		{"T1078", "T1078"},
		{"T9999"},
		{"T1086"}, // revoked
		{"t1078"},
		{"T1078 "},
		{""},
	} {
		if err := ValidateTechniques(ids); !errors.Is(err, ErrInvalidTechniques) {
			t.Errorf("ValidateTechniques(%q) = %v, want ErrInvalidTechniques", ids, err)
		}
	}
}

func TestSpec_RedirectOnlyForURLs(t *testing.T) {
	t.Parallel()

	target := "https://www.example.com"
	if err := (Spec{Type: TypeWebURL, Name: "a", RedirectURL: &target}).validate(); err != nil {
		t.Errorf("web_url with redirect: %v", err)
	}
	if err := (Spec{Type: TypeWebImage, Name: "a", RedirectURL: &target}).validate(); !errors.Is(err, ErrRedirectNotAllowed) {
		t.Errorf("web_image with redirect: %v, want ErrRedirectNotAllowed", err)
	}
	for _, typ := range []Type{"", "dns", "qr_code", "WEB_URL"} {
		if err := (Spec{Type: typ, Name: "a"}).validate(); !errors.Is(err, ErrInvalidType) {
			t.Errorf("type %q: %v, want ErrInvalidType", typ, err)
		}
	}
}

// A trigger value carries 128 bits from crypto/rand in 26 characters of
// lowercase base32, which is a valid DNS label.
func TestNewTriggerValue(t *testing.T) {
	t.Parallel()

	format := regexp.MustCompile(`^[a-z2-7]{26}$`)
	seen := map[string]bool{}
	for range 1000 {
		v := newTriggerValue()
		if !format.MatchString(v) || seen[v] {
			t.Fatalf("newTriggerValue() = %q, want 26 characters of lowercase base32, unique", v)
		}
		seen[v] = true
	}
}

// The name, the notes and the trigger value are inventory and never reach a
// log.
func TestHoneytoken_LogValueOmitsTheInventory(t *testing.T) {
	t.Parallel()

	target := "https://redirect.example.com"
	h := Honeytoken{
		ID: "00000000-0000-4000-8000-000000000000", Type: TypeWebURL, Name: "secret-name", Notes: "secret-notes",
		RedirectURL: &target, TriggerValue: "abcdefghijklmnopqrstuvwxyz",
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("test", slog.Any("honeytoken", h))
	for _, leak := range []string{"secret-name", "secret-notes", "redirect.example.com", "abcdefghijklmnopqrstuvwxyz"} {
		if strings.Contains(buf.String(), leak) {
			t.Errorf("log %s contains %q", buf.String(), leak)
		}
	}
	if !strings.Contains(buf.String(), h.ID) {
		t.Errorf("log %s does not name the honeytoken", buf.String())
	}
}
