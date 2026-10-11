// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package totp computes and checks time-based one-time passwords (RFC 6238)
// and generates recovery codes. It does not touch the database.
//
// Codes use the parameters that every authenticator app understands: HMAC-SHA-1,
// six digits and a period of 30 seconds. A secret has 160 bits, the size that
// RFC 4226 recommends for HMAC-SHA-1.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 with HMAC-SHA-1 is what authenticator apps implement; HMAC-SHA-1 is not affected by SHA-1 collisions.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Parameters of the codes.
const (
	// Digits is the length of a code.
	Digits = 6
	// Period is the time for which a code is valid.
	Period = 30 * time.Second
	// SecretSize is the length of a secret in bytes.
	SecretSize = 20
	// Skew is the number of periods before and after the current one whose codes
	// are accepted, so that a clock that is slightly off still works.
	Skew = 1
)

// encoding is the base32 of authenticator apps: standard alphabet, no padding.
var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a new random secret.
func NewSecret() ([]byte, error) {
	secret := make([]byte, SecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate TOTP secret: %w", err)
	}
	return secret, nil
}

// EncodeSecret returns secret in the base32 form that users type into an
// authenticator app.
func EncodeSecret(secret []byte) string {
	return encoding.EncodeToString(secret)
}

// StepAt returns the time step of t: the number of periods since the Unix epoch.
func StepAt(t time.Time) int64 {
	return t.Unix() / int64(Period/time.Second)
}

// Code returns the code of secret for the time step step.
func Code(secret []byte, step int64) string {
	return hotp(secret, uint64(step), Digits) //nolint:gosec // Time steps are never negative.
}

// hotp computes the HOTP value of RFC 4226 with dynamic truncation.
func hotp(secret []byte, counter uint64, digits int) string {
	mac := hmac.New(sha1.New, secret)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	s := strconv.FormatUint(uint64(value%mod), 10)
	return strings.Repeat("0", digits-len(s)) + s
}

// Match checks code against the steps from current-Skew to current+Skew that
// come after the step after, and returns the step that it matches. Steps up to
// after are skipped, so that a code that was already used, or an older one, is
// never accepted again. A code that does not consist of exactly Digits ASCII
// digits never matches.
func Match(secret []byte, code string, current, after int64) (int64, bool) {
	if !wellFormed(code) {
		return 0, false
	}
	for step := current - Skew; step <= current+Skew; step++ {
		if step <= after || step < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(Code(secret, step)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

func wellFormed(code string) bool {
	if len(code) != Digits {
		return false
	}
	for i := range len(code) {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

// URI returns the otpauth URI that authenticator apps read, usually from a QR
// code, for the account named account at issuer.
func URI(issuer, account string, secret []byte) string {
	q := url.Values{}
	q.Set("secret", EncodeSecret(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(Digits))
	q.Set("period", strconv.Itoa(int(Period/time.Second)))
	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + issuer + ":" + account,
		RawQuery: q.Encode(),
	}
	return u.String()
}
