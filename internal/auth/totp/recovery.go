// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package totp

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

// Recovery codes let a user sign in without their authenticator, once each.
const (
	// RecoveryCodeCount is the number of recovery codes issued at a time.
	RecoveryCodeCount = 10
	// recoveryCodeBytes gives a code 80 bits, enough that a code stored only as
	// a SHA-256 hash cannot be found by trying every value.
	recoveryCodeBytes = 10
	// recoveryCodeLength is the number of base32 characters of a code.
	recoveryCodeLength = recoveryCodeBytes * 8 / 5
	// recoveryGroup is the length of the groups in which a code is shown.
	recoveryGroup = 4
)

var recoveryEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NewRecoveryCodes returns RecoveryCodeCount new recovery codes, each written
// in groups of four, such as "abcd-efgh-ijkl-mnop".
func NewRecoveryCodes() ([]string, error) {
	codes := make([]string, RecoveryCodeCount)
	raw := make([]byte, recoveryCodeBytes)
	for i := range codes {
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		encoded := recoveryEncoding.EncodeToString(raw)
		var b strings.Builder
		for j := 0; j < len(encoded); j += recoveryGroup {
			if j > 0 {
				b.WriteByte('-')
			}
			b.WriteString(encoded[j : j+recoveryGroup])
		}
		codes[i] = b.String()
	}
	return codes, nil
}

// NormalizeRecoveryCode returns the form of a recovery code that is hashed:
// lower case, without hyphens and spaces, so that a code typed with other
// grouping or capitals still matches. It reports false if code cannot be a
// recovery code.
func NormalizeRecoveryCode(code string) (string, bool) {
	if len(code) > 4*recoveryCodeLength {
		return "", false
	}
	var b strings.Builder
	for _, c := range strings.ToLower(code) {
		switch {
		case c == '-' || c == ' ':
		case (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7'):
			b.WriteRune(c)
		default:
			return "", false
		}
	}
	if b.Len() != recoveryCodeLength {
		return "", false
	}
	return b.String(), true
}
