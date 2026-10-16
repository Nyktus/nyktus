// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package smtp

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const goldenMessage = "testdata/message.golden"

func TestBuild_MatchesTheGoldenFile(t *testing.T) {
	t.Parallel()

	got, err := testMessage().build("nyktus@example.com", time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build = %v", err)
	}
	if *update {
		if err := os.WriteFile(goldenMessage, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenMessage)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("message =\n%s\nwant\n%s", got, want)
	}
}

func TestBuild_RejectsHeaderInjectionInEveryField(t *testing.T) {
	t.Parallel()

	for name, change := range map[string]func(*Message){
		"subject with CRLF":    func(m *Message) { m.Subject = "Nyktus\r\nBcc: attacker@example.net" },
		"subject with LF":      func(m *Message) { m.Subject = "Nyktus\nBcc: attacker@example.net" },
		"subject with CR":      func(m *Message) { m.Subject = "Nyktus\rBcc: attacker@example.net" },
		"subject with NUL":     func(m *Message) { m.Subject = "Nyktus\x00" },
		"subject not ASCII":    func(m *Message) { m.Subject = "Nyktus: Vorfall er\xc3\xb6ffnet" },
		"empty subject":        func(m *Message) { m.Subject = "" },
		"long subject":         func(m *Message) { m.Subject = strings.Repeat("x", maxSubjectLength+1) },
		"recipient with CRLF":  func(m *Message) { m.To = []string{"soc@example.com\r\nBcc: attacker@example.net"} },
		"recipient with name":  func(m *Message) { m.To = []string{"SOC <soc@example.com>"} },
		"no recipient":         func(m *Message) { m.To = nil },
		"too many recipients":  func(m *Message) { m.To = make([]string, MaxRecipients+1) },
		"ID with CRLF":         func(m *Message) { m.ID = "id\r\nBcc: attacker@example.net" },
		"ID with angle":        func(m *Message) { m.ID = "id>" },
		"ID with at":           func(m *Message) { m.ID = "id@example.net" },
		"empty ID":             func(m *Message) { m.ID = "" },
		"body with CR":         func(m *Message) { m.Body = "line\r\nBcc: attacker@example.net" },
		"body with NUL":        func(m *Message) { m.Body = "line\x00" },
		"body not ASCII":       func(m *Message) { m.Body = "Vorfall er\xc3\xb6ffnet" },
		"body with long line":  func(m *Message) { m.Body = strings.Repeat("x", maxLineLength+1) },
		"body too long":        func(m *Message) { m.Body = strings.Repeat("x\n", maxBodyLength) },
		"body with escape seq": func(m *Message) { m.Body = "\x1b[31mred" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := testMessage()
			change(&m)
			if _, err := m.build("nyktus@example.com", time.Now()); err == nil {
				t.Error("build = nil, want an error")
			}
		})
	}
}

func TestBuild_EscapesNothingButKeepsDots(t *testing.T) {
	t.Parallel()

	// A line of a single dot would end the data; net/smtp escapes it when it
	// sends, so the message keeps it as it is.
	m := testMessage()
	m.Body = "first\n.\nlast"
	got, err := m.build("nyktus@example.com", time.Now())
	if err != nil {
		t.Fatalf("build = %v", err)
	}
	if !strings.HasSuffix(string(got), "\r\n\r\nfirst\r\n.\r\nlast\r\n") {
		t.Errorf("message = %q", got)
	}
}

func TestBuild_EveryLineFitsSMTP(t *testing.T) {
	t.Parallel()

	m := testMessage()
	m.To = nil
	for i := range MaxRecipients {
		m.To = append(m.To, strings.Repeat("a", maxLocalPart)+"@"+strings.Repeat(string(rune('a'+i)), 63)+"."+
			strings.Repeat("b", 63)+"."+strings.Repeat("c", 53)+".example")
	}
	if len(m.To[0]) != MaxAddressLength {
		t.Fatalf("address of %d characters, want the longest", len(m.To[0]))
	}
	got, err := m.build("nyktus@example.com", time.Now())
	if err != nil {
		t.Fatalf("build = %v", err)
	}
	for line := range strings.SplitSeq(strings.TrimSuffix(string(got), "\r\n"), "\r\n") {
		if len(line) > maxLineLength {
			t.Errorf("line of %d characters", len(line))
		}
	}
}

func TestValidateAddress(t *testing.T) {
	t.Parallel()

	valid := []string{
		"soc@example.com", "first.last+alerts@mail.example.org", "o'neil@example.com", "a@b.co",
		"soc@xn--bcher-kva.example", strings.Repeat("a", 64) + "@example.com",
	}
	for _, s := range valid {
		if err := ValidateAddress(s); err != nil {
			t.Errorf("ValidateAddress(%q) = %v", s, err)
		}
	}
	invalid := []string{
		"", "soc", "@example.com", "soc@", "soc@@example.com", "soc@localhost", "soc@example..com", "soc@-example.com",
		"soc@example-.com", "soc@192.0.2.1", "soc@[192.0.2.1]", ".soc@example.com", "soc.@example.com",
		"so..c@example.com", `"soc"@example.com`, "SOC <soc@example.com>", "soc@example.com (SOC)", "s oc@example.com",
		"soc@exa mple.com", "soc@example.com\r\nBcc: x@example.net", "soc\n@example.com", "s\xc3\xb6c@example.com",
		"soc@b\xc3\xbccher.example", strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." +
			strings.Repeat("d", 54) + ".example", "a@b@example.com", strings.Repeat("a", 65) + "@example.com",
		"soc@" + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." +
			strings.Repeat("d", 61) + ".com",
	}
	for _, s := range invalid {
		if err := ValidateAddress(s); !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("ValidateAddress(%q) = %v, want ErrInvalidAddress", s, err)
		}
	}
}
