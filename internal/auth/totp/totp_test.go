// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package totp

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// rfcSeed is the seed of the SHA-1 test vectors in RFC 4226 and RFC 6238.
var rfcSeed = []byte("12345678901234567890")

// RFC 6238, Appendix B, mode SHA1. The test vectors use eight digits.
func TestHOTP_RFC6238Vectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, tt := range tests {
		step := StepAt(time.Unix(tt.unix, 0))
		if got := hotp(rfcSeed, uint64(step), 8); got != tt.want { //nolint:gosec // The steps are positive.
			t.Errorf("TOTP at %d = %s, want %s", tt.unix, got, tt.want)
		}
	}
}

// RFC 4226, Appendix D: six digits, as Code computes them.
func TestCode_RFC4226Vectors(t *testing.T) {
	t.Parallel()

	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for counter, w := range want {
		if got := Code(rfcSeed, int64(counter)); got != w {
			t.Errorf("Code(counter %d) = %s, want %s", counter, got, w)
		}
	}
}

func TestMatch_AcceptsOneStepOfSkew(t *testing.T) {
	t.Parallel()

	const current = 1000
	for _, step := range []int64{current - 1, current, current + 1} {
		got, ok := Match(rfcSeed, Code(rfcSeed, step), current, 0)
		if !ok || got != step {
			t.Errorf("Match(code of step %d) = %d, %v; want %d, true", step, got, ok, step)
		}
	}
	for _, step := range []int64{current - 2, current + 2} {
		if _, ok := Match(rfcSeed, Code(rfcSeed, step), current, 0); ok {
			t.Errorf("Match(code of step %d) accepted a code outside the skew", step)
		}
	}
}

func TestMatch_RejectsUsedAndOlderSteps(t *testing.T) {
	t.Parallel()

	const current = 1000
	// The code of the current step was used: it and the previous one are spent.
	for _, step := range []int64{current - 1, current} {
		if _, ok := Match(rfcSeed, Code(rfcSeed, step), current, current); ok {
			t.Errorf("Match(code of step %d) accepted a step up to the last used one", step)
		}
	}
	if got, ok := Match(rfcSeed, Code(rfcSeed, current+1), current, current); !ok || got != current+1 {
		t.Errorf("Match(code of the next step) = %d, %v; want %d, true", got, ok, current+1)
	}
}

func TestMatch_RejectsMalformedCodes(t *testing.T) {
	t.Parallel()

	valid := Code(rfcSeed, 1000)
	for _, code := range []string{"", valid[:5], valid + "0", " " + valid[1:], "12345a", "\uff11\uff12\uff13\uff14\uff15\uff16", valid[:3] + "-" + valid[3:5]} {
		if _, ok := Match(rfcSeed, code, 1000, 0); ok {
			t.Errorf("Match(%q) = true", code)
		}
	}
}

func TestURI(t *testing.T) {
	t.Parallel()

	got := URI("Nyktus", "ada@example.com", rfcSeed)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse %q: %v", got, err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/Nyktus:ada@example.com" {
		t.Errorf("URI() = %q, want otpauth://totp/Nyktus:ada@example.com", got)
	}
	want := url.Values{
		"secret":    {"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"},
		"issuer":    {"Nyktus"},
		"algorithm": {"SHA1"},
		"digits":    {"6"},
		"period":    {"30"},
	}
	if q := u.Query(); q.Encode() != want.Encode() {
		t.Errorf("query = %s, want %s", q.Encode(), want.Encode())
	}
}

func TestNewSecret(t *testing.T) {
	t.Parallel()

	a, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != SecretSize || string(a) == string(b) {
		t.Errorf("NewSecret() = %d bytes, equal twice: %v", len(a), string(a) == string(b))
	}
}

func TestNewRecoveryCodes(t *testing.T) {
	t.Parallel()

	codes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("got %d codes, want %d", len(codes), RecoveryCodeCount)
	}
	format := regexp.MustCompile(`^[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$`)
	seen := map[string]bool{}
	for _, c := range codes {
		if !format.MatchString(c) {
			t.Errorf("code %q does not have the form xxxx-xxxx-xxxx-xxxx", c)
		}
		if seen[c] {
			t.Errorf("code %q issued twice", c)
		}
		seen[c] = true
		if n, ok := NormalizeRecoveryCode(c); !ok || n != strings.ReplaceAll(c, "-", "") {
			t.Errorf("NormalizeRecoveryCode(%q) = %q, %v", c, n, ok)
		}
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	t.Parallel()

	const want = "abcdefghijklmnop"
	for _, in := range []string{"abcd-efgh-ijkl-mnop", "ABCD-EFGH-IJKL-MNOP", "abcdefghijklmnop", " abcd efgh ijkl mnop "} {
		if got, ok := NormalizeRecoveryCode(in); !ok || got != want {
			t.Errorf("NormalizeRecoveryCode(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "abcd-efgh-ijkl-mno", "abcd-efgh-ijkl-mnopq", "abcd-efgh-ijkl-mno1", "abcd_efgh_ijkl_mnop", strings.Repeat("-", 100) + want} {
		if got, ok := NormalizeRecoveryCode(in); ok {
			t.Errorf("NormalizeRecoveryCode(%q) = %q, true; want false", in, got)
		}
	}
}
