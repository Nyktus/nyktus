// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package secretbox encrypts secrets that the server stores and must read back,
// such as the secrets of second factors, with AES-256-GCM.
//
// A sealed value starts with the identifier of the key that sealed it, followed
// by a random nonce and the ciphertext with its authentication tag:
//
//	key ID (1 byte) | nonce (12 bytes) | ciphertext | tag (16 bytes)
//
// A Keyring holds every key that may still be in use. It seals with its first
// key and opens with whichever key a value names, so that a new key can be
// introduced while values sealed with the old one remain readable.
//
// The caller passes associated data that names the purpose and the owner of a
// value, such as "totp:" and the ID of the account. A value copied into the
// record of another owner then fails to open.
package secretbox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
)

// KeySize is the length of a key in bytes, which selects AES-256.
const KeySize = 32

// Errors of opening a sealed value.
var (
	// ErrUnknownKey means that a value was sealed with a key that the keyring
	// does not hold.
	ErrUnknownKey = errors.New("secretbox: value was sealed with an unknown key")
	// ErrInvalid means that a value is malformed, was altered, or belongs to
	// other associated data.
	ErrInvalid = errors.New("secretbox: value cannot be opened")
	// ErrNoAssociatedData means that a caller passed no associated data.
	ErrNoAssociatedData = errors.New("secretbox: associated data is required")
)

// Keyring seals and opens values. It is safe for concurrent use.
type Keyring struct {
	// ids lists the key IDs in configured order; the first one seals.
	ids   []byte
	aeads map[byte]cipher.AEAD
}

// ParseKeyring parses a comma-separated list of keys, each written as
// "<id>:<key>", where id is a number from 1 to 255 and key is the standard
// base64 encoding of KeySize random bytes. The first key seals new values.
//
// IDs must be unique. Keys whose bytes are all equal, such as a key of zeros,
// are rejected, because they are placeholders rather than random keys.
func ParseKeyring(s string) (*Keyring, error) {
	k := &Keyring{aeads: make(map[byte]cipher.AEAD)}
	for i, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		idText, encoded, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("key %d: must be written as <id>:<base64 key>", i+1)
		}
		n, err := strconv.ParseUint(strings.TrimSpace(idText), 10, 8)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("key %d: the ID must be a number from 1 to 255", i+1)
		}
		id := byte(n)
		if _, dup := k.aeads[id]; dup {
			return nil, fmt.Errorf("key %d: the ID %d is used twice", i+1, id)
		}
		// The key itself never appears in an error message.
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		if err != nil {
			return nil, fmt.Errorf("key %d: not valid base64", i+1)
		}
		if len(raw) != KeySize {
			return nil, fmt.Errorf("key %d: must be %d bytes, got %d", i+1, KeySize, len(raw))
		}
		if bytes.Count(raw, raw[:1]) == len(raw) {
			return nil, fmt.Errorf("key %d: all bytes are equal; generate a random key", i+1)
		}
		aead, err := newAEAD(raw)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i+1, err)
		}
		k.ids = append(k.ids, id)
		k.aeads[id] = aead
	}
	return k, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// CurrentKeyID returns the ID of the key that seals new values.
func (k *Keyring) CurrentKeyID() byte { return k.ids[0] }

// Seal encrypts plaintext with the current key, bound to aad, which must not be
// empty: without it, a value copied into the record of another owner would
// still open.
func (k *Keyring) Seal(plaintext, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, ErrNoAssociatedData
	}
	id := k.CurrentKeyID()
	aead := k.aeads[id]
	// A random nonce is safe for far more values than a server ever seals
	// under one key.
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("secretbox: generate nonce: %w", err)
	}
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+aead.Overhead())
	out = append(append(out, id), nonce...)
	return aead.Seal(out, nonce, plaintext, aad), nil
}

// Open decrypts a value sealed by Seal with the same aad. It returns
// ErrUnknownKey if the keyring does not hold the key that sealed it and
// ErrInvalid if the value is malformed, altered or bound to other associated
// data.
func (k *Keyring) Open(sealed, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, ErrNoAssociatedData
	}
	if len(sealed) == 0 {
		return nil, ErrInvalid
	}
	aead, ok := k.aeads[sealed[0]]
	if !ok {
		return nil, ErrUnknownKey
	}
	if len(sealed) < 1+aead.NonceSize()+aead.Overhead() {
		return nil, ErrInvalid
	}
	nonce, ciphertext := sealed[1:1+aead.NonceSize()], sealed[1+aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrInvalid
	}
	return plaintext, nil
}

// NeedsReseal reports whether sealed was sealed with a key other than the
// current one, so that a caller that writes the value anyway can seal it again
// and the old key can eventually be removed.
func (k *Keyring) NeedsReseal(sealed []byte) bool {
	return len(sealed) > 0 && sealed[0] != k.CurrentKeyID()
}

const redacted = "[redacted]"

// String keeps the keys out of formatted output.
func (k *Keyring) String() string { return redacted }

// GoString keeps the keys out of %#v.
func (k *Keyring) GoString() string { return redacted }

// LogValue names the keys by ID only.
func (k *Keyring) LogValue() slog.Value {
	ids := make([]int, len(k.ids))
	for i, id := range k.ids {
		ids[i] = int(id)
	}
	return slog.GroupValue(slog.Any("key_ids", ids))
}
