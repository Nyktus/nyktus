// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package password hashes and verifies passwords with Argon2id.
//
// Hashes are encoded in the PHC string format, for example
//
//	$argon2id$v=19$m=65536,t=3,p=4$<salt>$<key>
//
// with salt and key in unpadded standard base64. Verification reads the
// parameters from the encoded hash, so raising them later keeps existing hashes
// valid.
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// Length limits in Unicode code points after NFC normalization. The upper bound
// keeps the input to the hash function small.
const (
	MinLength = 12
	MaxLength = 128
)

// Sentinel errors for passwords that cannot be set.
var (
	ErrTooShort    = fmt.Errorf("password must have at least %d characters", MinLength)
	ErrTooLong     = fmt.Errorf("password must have at most %d characters", MaxLength)
	ErrInvalidUTF8 = errors.New("password is not valid UTF-8")
)

// ErrMalformedHash is returned when an encoded hash cannot be parsed or carries
// parameters outside the accepted bounds.
var ErrMalformedHash = errors.New("malformed password hash")

// params are the Argon2id cost parameters. Memory is in KiB.
type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

// defaultParams follow the secure coding guidelines.
func defaultParams() params {
	return params{memory: 64 * 1024, iterations: 3, parallelism: 4, saltLength: 16, keyLength: 32}
}

// inBounds reports whether the cost parameters are ones that Verify accepts.
// Argon2 requires at least eight KiB of memory per lane.
func inBounds(memory, iterations, parallelism uint64) bool {
	return parallelism >= 1 && iterations >= 1 && iterations <= maxIterations &&
		memory >= 8*parallelism && memory <= maxMemory
}

// Upper bounds for parameters read from an encoded hash. They are far above the
// defaults and only stop a corrupted hash from exhausting memory or CPU.
const (
	maxMemory     = 1024 * 1024
	maxIterations = 64
	minKeyLength  = 16
	maxKeyLength  = 64
	minSaltLength = 8
	maxSaltLength = 64
)

// Hasher hashes and verifies passwords. It is safe for concurrent use.
//
// Each hash allocates the full Argon2id memory, so the number of concurrent hash
// operations is limited. Without a limit, parallel login attempts could exhaust
// the memory of the server.
type Hasher struct {
	params params
	slots  chan struct{}
}

// NewHasher returns a Hasher with the default parameters that runs at most
// GOMAXPROCS hash operations at a time. The limit applies per Hasher, so a process
// creates one and shares it among all code that hashes or verifies passwords.
func NewHasher() *Hasher {
	return newHasher(defaultParams(), runtime.GOMAXPROCS(0))
}

// NewHasherWithCost returns a Hasher with the given Argon2id parameters that runs
// at most GOMAXPROCS hash operations at a time. It exists so that tests can hash
// at a fraction of the cost of NewHasher, which the race detector multiplies by
// nine; the linter rejects it outside package passwordtest. It panics if the
// parameters lie outside the bounds that Verify accepts.
func NewHasherWithCost(memory, iterations uint32, parallelism uint8) *Hasher {
	p := defaultParams()
	p.memory, p.iterations, p.parallelism = memory, iterations, parallelism
	return newHasher(p, runtime.GOMAXPROCS(0))
}

func newHasher(p params, concurrency int) *Hasher {
	if concurrency < 1 {
		panic("password: concurrency must be at least 1")
	}
	if !inBounds(uint64(p.memory), uint64(p.iterations), uint64(p.parallelism)) {
		panic("password: parameters out of bounds")
	}
	return &Hasher{params: p, slots: make(chan struct{}, concurrency)}
}

// Validate reports whether password may be set: ErrInvalidUTF8, ErrTooLong or
// ErrTooShort if not. It costs no hash, so a caller can reject a password before
// other expensive work.
func Validate(password string) error {
	_, err := validate(password)
	return err
}

func validate(password string) (string, error) {
	if !utf8.ValidString(password) {
		return "", ErrInvalidUTF8
	}
	normalized, ok := normalize(password)
	switch {
	case !ok:
		return "", ErrTooLong
	case utf8.RuneCountInString(normalized) < MinLength:
		return "", ErrTooShort
	}
	return normalized, nil
}

// Hash validates password and returns its encoded hash. It waits for a free slot
// and returns the context's error if the context ends first.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	normalized, err := validate(password)
	if err != nil {
		return "", err
	}

	salt := make([]byte, h.params.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key, err := h.derive(ctx, normalized, salt, h.params)
	if err != nil {
		return "", err
	}
	return encode(h.params, salt, key), nil
}

// Verify reports whether password matches the encoded hash. The minimum length
// is not checked, so that raising it does not lock out existing accounts.
func (h *Hasher) Verify(ctx context.Context, password, encoded string) (bool, error) {
	p, salt, key, err := decode(encoded)
	if err != nil {
		return false, err
	}
	normalized, ok := normalize(password)
	if !ok {
		// Such a password can never have been set.
		return false, nil
	}
	got, err := h.derive(ctx, normalized, salt, p)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, key) == 1, nil
}

// NeedsRehash reports whether encoded was created with other parameters than h
// uses, or cannot be read. A caller that has just verified the password with the
// stored hash then hashes it again, so that raised parameters reach every account
// that signs in.
func (h *Hasher) NeedsRehash(encoded string) bool {
	p, _, _, err := decode(encoded)
	return err != nil || p != h.params
}

// normalize applies NFC, so that the same password typed on systems that compose
// characters differently yields the same hash. It reports false for input that
// can never be a valid password: invalid UTF-8 or more than MaxLength code points.
func normalize(password string) (string, bool) {
	if !utf8.ValidString(password) {
		return "", false
	}
	normalized := norm.NFC.String(password)
	return normalized, utf8.RuneCountInString(normalized) <= MaxLength
}

func (h *Hasher) derive(ctx context.Context, password string, salt []byte, p params) ([]byte, error) {
	select {
	case h.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for password hashing: %w", ctx.Err())
	}
	defer func() { <-h.slots }()
	return argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength), nil
}

func encode(p params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.memory, p.iterations, p.parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

func decode(encoded string) (params, []byte, []byte, error) {
	var p params
	fields := strings.Split(encoded, "$")
	if len(fields) != 6 || fields[0] != "" || fields[1] != "argon2id" {
		return p, nil, nil, fmt.Errorf("%w: expected $argon2id$v=..$m=..,t=..,p=..$salt$key", ErrMalformedHash)
	}
	if fields[2] != "v="+strconv.Itoa(argon2.Version) {
		return p, nil, nil, fmt.Errorf("%w: unsupported version %q", ErrMalformedHash, fields[2])
	}

	var m, t, par uint64
	for i, part := range strings.Split(fields[3], ",") {
		name, value, ok := strings.Cut(part, "=")
		// The order is fixed by the format; a strict parse rejects duplicates.
		if !ok || i > 2 || name != [...]string{"m", "t", "p"}[i] {
			return p, nil, nil, fmt.Errorf("%w: invalid parameters %q", ErrMalformedHash, fields[3])
		}
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return p, nil, nil, fmt.Errorf("%w: invalid parameter %s: %w", ErrMalformedHash, name, err)
		}
		switch name {
		case "m":
			m = n
		case "t":
			t = n
		default:
			par = n
		}
	}
	if par > math.MaxUint8 || !inBounds(m, t, par) {
		return p, nil, nil, fmt.Errorf("%w: parameters out of bounds %q", ErrMalformedHash, fields[3])
	}

	enc := base64.RawStdEncoding.Strict()
	salt, err := enc.DecodeString(fields[4])
	if err != nil {
		return p, nil, nil, fmt.Errorf("%w: invalid salt: %w", ErrMalformedHash, err)
	}
	saltLength := len(salt)
	if saltLength < minSaltLength || saltLength > maxSaltLength {
		return p, nil, nil, fmt.Errorf("%w: salt of %d bytes", ErrMalformedHash, saltLength)
	}
	key, err := enc.DecodeString(fields[5])
	if err != nil {
		return p, nil, nil, fmt.Errorf("%w: invalid key: %w", ErrMalformedHash, err)
	}
	keyLength := len(key)
	if keyLength < minKeyLength || keyLength > maxKeyLength {
		return p, nil, nil, fmt.Errorf("%w: key of %d bytes", ErrMalformedHash, keyLength)
	}

	p = params{
		memory:      uint32(m),
		iterations:  uint32(t),
		parallelism: uint8(par),
		saltLength:  uint32(saltLength),
		keyLength:   uint32(keyLength),
	}
	return p, salt, key, nil
}
