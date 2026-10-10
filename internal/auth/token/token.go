// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package token generates the opaque secrets that authenticate a holder, such as
// setup tokens and session tokens, and derives the hash under which they are
// stored.
//
// A token carries 256 bits from crypto/rand. The database stores only its SHA-256
// hash, so reading the database does not reveal a usable token. A fast hash is
// enough, because a random value of that size cannot be guessed.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// size is the amount of randomness in a token, in bytes.
const size = 32

// New returns a new token, encoded in unpadded base64url so that it fits into
// URLs and cookies unchanged.
func New() (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Hash returns the SHA-256 hash under which t is stored.
func Hash(t string) []byte {
	sum := sha256.Sum256([]byte(t))
	return sum[:]
}
