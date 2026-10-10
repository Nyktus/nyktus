// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package token

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestNew_Encodes32RandomBytes(t *testing.T) {
	t.Parallel()

	a, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	b, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(a)
	if err != nil || len(raw) != 32 {
		t.Errorf("New() = %q, want 32 bytes in unpadded base64url", a)
	}
	if a == b {
		t.Error("two tokens are equal")
	}
}

func TestHash_IsSHA256(t *testing.T) {
	t.Parallel()

	want := sha256.Sum256([]byte("value"))
	if got := Hash("value"); !bytes.Equal(got, want[:]) {
		t.Errorf("Hash() = %x, want %x", got, want)
	}
}
