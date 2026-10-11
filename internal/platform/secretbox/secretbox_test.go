// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package secretbox_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/platform/secretbox"
)

// randomEntry returns a keyring entry with a fresh random key, so that no key
// material is written into the source.
func randomEntry(t *testing.T, id int) string {
	t.Helper()
	raw := make([]byte, secretbox.KeySize)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%d:%s", id, base64.StdEncoding.EncodeToString(raw))
}

func parse(t *testing.T, s string) *secretbox.Keyring {
	t.Helper()
	k, err := secretbox.ParseKeyring(s)
	if err != nil {
		t.Fatalf("ParseKeyring() error = %v", err)
	}
	return k
}

func TestSealOpen_RoundTrip(t *testing.T) {
	t.Parallel()

	k := parse(t, randomEntry(t, 7))
	plaintext := []byte("twenty byte secret!!")
	aad := []byte("totp:0b6f2e6c-1f2a-4c55-9d32-6f0f7e0d6a11")

	sealed, err := k.Seal(plaintext, aad)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if sealed[0] != 7 {
		t.Errorf("key ID byte = %d, want 7", sealed[0])
	}
	if bytes.Contains(sealed, plaintext) {
		t.Error("sealed value contains the plaintext")
	}
	got, err := k.Open(sealed, aad)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Open() = %q, want %q", got, plaintext)
	}

	again, err := k.Seal(plaintext, aad)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if bytes.Equal(again, sealed) {
		t.Error("two seals of the same value are equal; the nonce is not random")
	}
}

func TestOpen_RejectsOtherAssociatedData(t *testing.T) {
	t.Parallel()

	k := parse(t, randomEntry(t, 1))
	sealed, err := k.Seal([]byte("secret"), []byte("totp:alice"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Open(sealed, []byte("totp:bob")); !errors.Is(err, secretbox.ErrInvalid) {
		t.Errorf("Open() with other associated data error = %v, want ErrInvalid", err)
	}
}

func TestOpen_RejectsAlteredValues(t *testing.T) {
	t.Parallel()

	k := parse(t, randomEntry(t, 1))
	aad := []byte("totp:alice")
	sealed, err := k.Seal([]byte("secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(sealed); i++ {
		altered := bytes.Clone(sealed)
		altered[i] ^= 0x01
		if _, err := k.Open(altered, aad); !errors.Is(err, secretbox.ErrInvalid) {
			t.Fatalf("Open() with byte %d altered error = %v, want ErrInvalid", i, err)
		}
	}
	for _, short := range [][]byte{nil, {}, sealed[:1], sealed[:len(sealed)-1], sealed[:29]} {
		if _, err := k.Open(short, aad); !errors.Is(err, secretbox.ErrInvalid) {
			t.Errorf("Open(%d bytes) error = %v, want ErrInvalid", len(short), err)
		}
	}
}

func TestKeyring_Rotation(t *testing.T) {
	t.Parallel()

	oldEntry, newEntry := randomEntry(t, 1), randomEntry(t, 2)
	aad := []byte("totp:alice")
	old := parse(t, oldEntry)
	sealedOld, err := old.Seal([]byte("secret"), aad)
	if err != nil {
		t.Fatal(err)
	}

	rotated := parse(t, newEntry+", "+oldEntry)
	if got := rotated.CurrentKeyID(); got != 2 {
		t.Errorf("CurrentKeyID() = %d, want the first key 2", got)
	}
	if got, err := rotated.Open(sealedOld, aad); err != nil || string(got) != "secret" {
		t.Errorf("Open() of a value of the old key = %q, %v; want it readable", got, err)
	}
	if !rotated.NeedsReseal(sealedOld) {
		t.Error("NeedsReseal() = false for a value of the old key")
	}
	sealedNew, err := rotated.Seal([]byte("secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if sealedNew[0] != 2 || rotated.NeedsReseal(sealedNew) {
		t.Errorf("new value sealed with key %d, NeedsReseal() = %v; want key 2 and false", sealedNew[0], rotated.NeedsReseal(sealedNew))
	}

	// Once the old key is removed, its values name a key the keyring lacks.
	if _, err := parse(t, newEntry).Open(sealedOld, aad); !errors.Is(err, secretbox.ErrUnknownKey) {
		t.Errorf("Open() without the old key error = %v, want ErrUnknownKey", err)
	}
}

func TestParseKeyring_RejectsInvalidKeys(t *testing.T) {
	t.Parallel()

	valid := randomEntry(t, 1)
	_, validKey, _ := strings.Cut(valid, ":")
	zeros := base64.StdEncoding.EncodeToString(make([]byte, secretbox.KeySize))
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	tests := map[string]struct {
		in, want string
	}{
		"empty":           {"", "key 1: must be written as <id>:<base64 key>"},
		"no ID":           {validKey, "key 1: must be written as <id>:<base64 key>"},
		"ID zero":         {"0:" + validKey, "key 1: the ID must be a number from 1 to 255"},
		"ID too large":    {"256:" + validKey, "key 1: the ID must be a number from 1 to 255"},
		"ID not a number": {"a:" + validKey, "key 1: the ID must be a number from 1 to 255"},
		"duplicate ID":    {valid + "," + randomEntry(t, 1), "key 2: the ID 1 is used twice"},
		"not base64":      {"1:" + validKey[:10] + "!" + validKey[11:], "key 1: not valid base64"},
		"too short":       {"1:" + short, "key 1: must be 32 bytes, got 16"},
		"all zero":        {"1:" + zeros, "key 1: all bytes are equal; generate a random key"},
		"trailing comma":  {valid + ",", "key 2: must be written as <id>:<base64 key>"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := secretbox.ParseKeyring(tt.in)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("ParseKeyring() error = %v, want %q", err, tt.want)
			}
			if strings.Contains(err.Error(), validKey) {
				t.Error("error message contains the key")
			}
		})
	}
}

func TestKeyring_FormattingIsRedacted(t *testing.T) {
	t.Parallel()

	entry := randomEntry(t, 3)
	_, key, _ := strings.Cut(entry, ":")
	k := parse(t, entry)
	for _, verb := range []string{"%v", "%+v", "%s", "%#v"} {
		if out := fmt.Sprintf(verb, k); strings.Contains(out, key) || out != "[redacted]" {
			t.Errorf("Sprintf(%q) = %q, want [redacted]", verb, out)
		}
	}
	if got := k.LogValue().String(); got != "[key_ids=[3]]" {
		t.Errorf("LogValue() = %q, want only the key IDs", got)
	}
}
