// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"strings"
)

// Prefix starts every key, so that secret scanners recognize a leaked one.
const Prefix = "nyk_"

const (
	idSize     = 16
	secretSize = 32
	sumSize    = 4
	// keyLength is the length of a key: the prefix and the identifier, the
	// secret and the checksum in unpadded base32.
	keyLength = len(Prefix) + ((idSize+secretSize+sumSize)*8+4)/5
)

// encoding is base32 in lowercase without padding. Its alphabet has no
// characters that end a word, so a key is selected whole by a double click,
// and no characters that are easily confused.
var encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// newSecret returns the random secret of a new key.
func newSecret() ([]byte, error) {
	secret := make([]byte, secretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate API key secret: %w", err)
	}
	return secret, nil
}

// hashSecret returns the SHA-256 hash under which secret is stored. A fast hash
// is enough, because a random value of 256 bits cannot be guessed.
func hashSecret(secret []byte) []byte {
	sum := sha256.Sum256(secret)
	return sum[:]
}

// format returns the key of the key id with secret. The checksum lets the server
// and secret scanners reject a mistyped or random string without a lookup; it
// is public and adds nothing to the secret.
func format(id string, secret []byte) (string, error) {
	raw, err := uuidBytes(id)
	if err != nil {
		return "", err
	}
	payload := make([]byte, 0, idSize+secretSize+sumSize)
	payload = append(payload, raw...)
	payload = append(payload, secret...)
	payload = binary.BigEndian.AppendUint32(payload, crc32.ChecksumIEEE(payload))
	return Prefix + encoding.EncodeToString(payload), nil
}

// parse returns the key ID and the secret of key. ok is false if key is not of
// the form that format produces, including a wrong checksum.
func parse(key string) (id string, secret []byte, ok bool) {
	if len(key) != keyLength || !strings.HasPrefix(key, Prefix) {
		return "", nil, false
	}
	encoded := key[len(Prefix):]
	payload, err := encoding.DecodeString(encoded)
	// The last character carries bits beyond the payload, which the decoder
	// ignores. Only the canonical form is a key, so that a key has one spelling.
	if err != nil || len(payload) != idSize+secretSize+sumSize || encoding.EncodeToString(payload) != encoded {
		return "", nil, false
	}
	data, sum := payload[:idSize+secretSize], payload[idSize+secretSize:]
	if crc32.ChecksumIEEE(data) != binary.BigEndian.Uint32(sum) {
		return "", nil, false
	}
	return uuidString(data[:idSize]), data[idSize:], true
}

func uuidBytes(id string) ([]byte, error) {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return nil, fmt.Errorf("invalid key ID %q", id)
	}
	raw, err := hex.DecodeString(id[:8] + id[9:13] + id[14:18] + id[19:23] + id[24:])
	if err != nil || strings.ToLower(id) != id {
		return nil, fmt.Errorf("invalid key ID %q", id)
	}
	return raw, nil
}

func uuidString(raw []byte) string {
	h := hex.EncodeToString(raw)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
