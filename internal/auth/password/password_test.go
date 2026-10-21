// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package password

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// cheapParams keep tests fast where the cost parameters do not matter.
func cheapParams() params {
	return params{memory: 64, iterations: 1, parallelism: 1, saltLength: 16, keyLength: 32}
}

func cheapHasher() *Hasher { return newHasher(cheapParams(), 4) }

const validPassword = "correct horse battery staple"

// The reference tag (RFC 9106) of validPassword with the default parameters
// was computed independently with OpenSSL 3.6:
//
//	openssl kdf -keylen 32 -kdfopt pass:"correct horse battery staple" \
//	  -kdfopt hexsalt:000102030405060708090a0b0c0d0e0f -kdfopt iter:3 \
//	  -kdfopt memcost:65536 -kdfopt lanes:4 ARGON2ID
const (
	referenceSalt = "000102030405060708090a0b0c0d0e0f"
	referenceTag  = "853b272a44db1421c02962669a55eb0994f3cab385ed1c4c79253eee19bab49e"
)

// reference returns the salt and tag of the reference vector in the base64
// encoding of the PHC string format.
func reference(t *testing.T) (salt, key string) {
	t.Helper()
	rawSalt, err := hex.DecodeString(referenceSalt)
	if err != nil {
		t.Fatalf("decode reference salt: %v", err)
	}
	rawTag, err := hex.DecodeString(referenceTag)
	if err != nil {
		t.Fatalf("decode reference tag: %v", err)
	}
	return base64.RawStdEncoding.EncodeToString(rawSalt), base64.RawStdEncoding.EncodeToString(rawTag)
}

func TestHasher_DefaultParametersMatchReferenceImplementation(t *testing.T) {
	t.Parallel()

	salt, key := reference(t)
	h := NewHasher()
	encoded := "$argon2id$v=19$m=65536,t=3,p=4$" + salt + "$" + key
	if want := encode(h.params, nil, nil); !strings.HasPrefix(want, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("encode() = %q, want the default parameters m=65536,t=3,p=4", want)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("encoded = %q, want the default parameters m=65536,t=3,p=4", encoded)
	}
	ok, err := h.Verify(t.Context(), validPassword, encoded)
	if err != nil || !ok {
		t.Errorf("Verify() = %v, %v, want true for the reference key", ok, err)
	}
}

func TestHash_ProducesPHCStringWithRandomSalt(t *testing.T) {
	t.Parallel()

	h := NewHasher()
	format := regexp.MustCompile(`^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)
	first, err := h.Hash(t.Context(), validPassword)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	second, err := h.Hash(t.Context(), validPassword)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	for _, encoded := range []string{first, second} {
		if !format.MatchString(encoded) {
			t.Errorf("Hash() = %q, want a PHC string with a 16-byte salt and a 32-byte key", encoded)
		}
	}
	if first == second {
		t.Error("Hash() returned the same hash twice; the salt is not random")
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	h := cheapHasher()
	encoded, err := h.Hash(t.Context(), validPassword)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{name: "same password", password: validPassword, want: true},
		{name: "different password", password: "correct horse battery stapler", want: false},
		{name: "different case", password: "Correct horse battery staple", want: false},
		{name: "empty", password: "", want: false},
		{name: "invalid UTF-8", password: validPassword + "\xff", want: false},
		{name: "too long", password: strings.Repeat("a", MaxLength+1), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := h.Verify(t.Context(), tt.password, encoded)
			if err != nil || got != tt.want {
				t.Errorf("Verify(%q) = %v, %v, want %v, nil", tt.password, got, err, tt.want)
			}
		})
	}
}

// Validate applies the same rules as Hash, without hashing.
func TestHashAndValidate_LengthIsCountedInCodePointsAfterNFC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		password string
		want     error
	}{
		{name: "one below minimum", password: strings.Repeat("a", MinLength-1), want: ErrTooShort},
		{name: "minimum", password: strings.Repeat("a", MinLength)},
		{name: "maximum", password: strings.Repeat("a", MaxLength)},
		{name: "one above maximum", password: strings.Repeat("a", MaxLength+1), want: ErrTooLong},
		{name: "two-byte characters at minimum", password: strings.Repeat("ä", MinLength)},
		{name: "four-byte characters at maximum", password: strings.Repeat("🦉", MaxLength)},
		{name: "four-byte characters above maximum", password: strings.Repeat("🦉", MaxLength+1), want: ErrTooLong},
		// Twelve code points before normalization, six after it.
		{name: "decomposed characters", password: strings.Repeat("a\u0308", MinLength/2), want: ErrTooShort},
		{name: "oversized input", password: strings.Repeat("a", 1<<20), want: ErrTooLong},
		{name: "invalid UTF-8", password: strings.Repeat("a", MinLength) + "\xff", want: ErrInvalidUTF8},
	}
	h := cheapHasher()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := h.Hash(t.Context(), tt.password)
			if !errors.Is(err, tt.want) {
				t.Errorf("Hash() error = %v, want %v", err, tt.want)
			}
			if err := Validate(tt.password); !errors.Is(err, tt.want) {
				t.Errorf("Validate() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVerify_NormalizesUnicode(t *testing.T) {
	t.Parallel()

	h := cheapHasher()
	// The same text, typed with a decomposed and a precomposed umlaut.
	decomposed := "Kennwort mit Umlaut a\u0308"
	precomposed := "Kennwort mit Umlaut \u00e4"
	encoded, err := h.Hash(t.Context(), decomposed)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	ok, err := h.Verify(t.Context(), precomposed, encoded)
	if err != nil || !ok {
		t.Errorf("Verify() = %v, %v, want true for the precomposed form", ok, err)
	}
}

func TestVerify_UsesParametersFromHash(t *testing.T) {
	t.Parallel()

	encoded, err := cheapHasher().Hash(t.Context(), validPassword)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if !strings.Contains(encoded, "$m=64,t=1,p=1$") {
		t.Fatalf("Hash() = %q, want the cheap parameters", encoded)
	}
	// A hasher with the default parameters still verifies hashes created with
	// other parameters, so the parameters can be raised later.
	ok, err := NewHasher().Verify(t.Context(), validPassword, encoded)
	if err != nil || !ok {
		t.Errorf("Verify() = %v, %v, want true", ok, err)
	}
}

func TestVerify_RejectsMalformedHashes(t *testing.T) {
	t.Parallel()

	salt, key := reference(t)
	tests := map[string]string{
		"empty":                "",
		"plain text":           validPassword,
		"argon2i":              "$argon2i$v=19$m=65536,t=3,p=4$" + salt + "$" + key,
		"version 16":           "$argon2id$v=16$m=65536,t=3,p=4$" + salt + "$" + key,
		"missing field":        "$argon2id$v=19$m=65536,t=3,p=4$" + salt,
		"extra field":          "$argon2id$v=19$m=65536,t=3,p=4$" + salt + "$" + key + "$x",
		"parameter order":      "$argon2id$v=19$t=3,m=65536,p=4$" + salt + "$" + key,
		"duplicate parameter":  "$argon2id$v=19$m=65536,m=65536,t=3,p=4$" + salt + "$" + key,
		"negative parameter":   "$argon2id$v=19$m=-1,t=3,p=4$" + salt + "$" + key,
		"zero iterations":      "$argon2id$v=19$m=65536,t=0,p=4$" + salt + "$" + key,
		"zero parallelism":     "$argon2id$v=19$m=65536,t=3,p=0$" + salt + "$" + key,
		"memory below 8p KiB":  "$argon2id$v=19$m=31,t=3,p=4$" + salt + "$" + key,
		"excessive memory":     "$argon2id$v=19$m=4194304,t=3,p=4$" + salt + "$" + key,
		"excessive iterations": "$argon2id$v=19$m=65536,t=1000,p=4$" + salt + "$" + key,
		"padded salt":          "$argon2id$v=19$m=65536,t=3,p=4$" + salt + "==$" + key,
		"short salt":           "$argon2id$v=19$m=65536,t=3,p=4$AAECAw$" + key,
		"short key":            "$argon2id$v=19$m=65536,t=3,p=4$" + salt + "$AAECAw",
		"invalid base64":       "$argon2id$v=19$m=65536,t=3,p=4$" + salt + "$" + key[:42] + "*",
	}
	h := cheapHasher()
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ok, err := h.Verify(t.Context(), validPassword, encoded)
			if ok || !errors.Is(err, ErrMalformedHash) {
				t.Errorf("Verify(%q) = %v, %v, want false, ErrMalformedHash", encoded, ok, err)
			}
		})
	}
}

func TestHasher_LimitsConcurrentHashing(t *testing.T) {
	t.Parallel()

	h := newHasher(cheapParams(), 1)
	encoded, err := h.Hash(t.Context(), validPassword)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	// Occupy the only slot, as a running hash would.
	h.slots <- struct{}{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := h.Hash(ctx, validPassword); !errors.Is(err, context.Canceled) {
		t.Errorf("Hash() with all slots taken error = %v, want context.Canceled", err)
	}
	if _, err := h.Verify(ctx, validPassword, encoded); !errors.Is(err, context.Canceled) {
		t.Errorf("Verify() with all slots taken error = %v, want context.Canceled", err)
	}

	<-h.slots
	if _, err := h.Hash(t.Context(), validPassword); err != nil {
		t.Errorf("Hash() after the slot was freed error = %v", err)
	}
}

func TestNewHasher_RejectsInvalidConcurrency(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("newHasher(0) did not panic")
		}
	}()
	newHasher(cheapParams(), 0)
}

func TestNewHasherWithCost_RejectsParametersThatVerifyRefuses(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name               string
		memory, iterations uint32
		parallelism        uint8
	}{
		{"memory below eight KiB per lane", 15, 1, 2},
		{"no iterations", 64, 0, 1},
		{"too many iterations", 64, maxIterations + 1, 1},
		{"no lanes", 64, 1, 0},
		{"too much memory", maxMemory + 1, 1, 1},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: NewHasherWithCost(%d, %d, %d) did not panic", tt.name, tt.memory, tt.iterations, tt.parallelism)
				}
			}()
			NewHasherWithCost(tt.memory, tt.iterations, tt.parallelism)
		}()
	}
}

func TestNewHasherWithCost_HashesVerifiablyAtOtherParametersThanTheDefault(t *testing.T) {
	t.Parallel()

	h := NewHasherWithCost(256, 1, 1)
	encoded, err := h.Hash(t.Context(), validPassword)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=256,t=1,p=1$") {
		t.Errorf("Hash() = %q, want the given parameters", encoded)
	}
	if ok, err := NewHasher().Verify(t.Context(), validPassword, encoded); err != nil || !ok {
		t.Errorf("default hasher Verify() = %v, %v, want true: parameters come from the hash", ok, err)
	}
	if h.NeedsRehash(encoded) {
		t.Error("NeedsRehash() = true for a hash of the same hasher")
	}
	if !NewHasher().NeedsRehash(encoded) {
		t.Error("NeedsRehash() = false for the default hasher, want true for cheaper parameters")
	}
}

func TestNeedsRehash(t *testing.T) {
	t.Parallel()

	h := cheapHasher()
	current, err := h.Hash(t.Context(), validPassword)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	older := params{memory: 32, iterations: 1, parallelism: 1, saltLength: 16, keyLength: 32}
	stale, err := newHasher(older, 1).Hash(t.Context(), validPassword)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	longerKey, err := newHasher(params{memory: 64, iterations: 1, parallelism: 1, saltLength: 16, keyLength: 64}, 1).Hash(t.Context(), validPassword)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	for name, tt := range map[string]struct {
		encoded string
		want    bool
	}{
		"current parameters": {current, false},
		"other memory":       {stale, true},
		"other key length":   {longerKey, true},
		"malformed hash":     {"$argon2id$v=19$m=64", true},
		"default parameters": {strings.Replace(current, "m=64,t=1,p=1", "m=65536,t=3,p=4", 1), true},
	} {
		if got := h.NeedsRehash(tt.encoded); got != tt.want {
			t.Errorf("NeedsRehash(%s) = %v, want %v", name, got, tt.want)
		}
	}
}
