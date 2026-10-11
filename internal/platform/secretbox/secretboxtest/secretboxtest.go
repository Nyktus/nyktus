// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package secretboxtest provides encryption keys for tests. Keys are generated
// for each test, so that no key material is written into the source.
package secretboxtest

import (
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"testing"

	"nyktus.org/nyktus/internal/platform/secretbox"
)

// Entry returns a keyring entry with the ID id and a new random key, as an
// operator writes it into NYKTUS_ENCRYPTION_KEYS.
func Entry(tb testing.TB, id int) string {
	tb.Helper()
	raw := make([]byte, secretbox.KeySize)
	if _, err := rand.Read(raw); err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	return strconv.Itoa(id) + ":" + base64.StdEncoding.EncodeToString(raw)
}

// Keyring returns a keyring with one new random key.
func Keyring(tb testing.TB) *secretbox.Keyring {
	tb.Helper()
	k, err := secretbox.ParseKeyring(Entry(tb, 1))
	if err != nil {
		tb.Fatalf("ParseKeyring() error = %v", err)
	}
	return k
}
