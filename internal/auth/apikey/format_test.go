// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package apikey

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

const testID = "0b6f0c7e-3a5d-4f1e-9c2b-8d7a6e5f4c3b"

func testKey(t *testing.T) (string, []byte) {
	t.Helper()
	secret := bytes.Repeat([]byte{0xa5}, secretSize)
	key, err := format(testID, secret)
	if err != nil {
		t.Fatalf("format() error = %v", err)
	}
	return key, secret
}

func TestFormat_RoundTrip(t *testing.T) {
	t.Parallel()

	key, secret := testKey(t)
	if len(key) != keyLength || !strings.HasPrefix(key, Prefix) {
		t.Errorf("key %q has length %d, want %d with prefix %s", key, len(key), keyLength, Prefix)
	}
	if strings.Trim(key[len(Prefix):], "abcdefghijklmnopqrstuvwxyz234567") != "" {
		t.Errorf("key %q has characters outside lowercase base32", key)
	}
	id, got, ok := parse(key)
	if !ok || id != testID || !bytes.Equal(got, secret) {
		t.Errorf("parse() = %q, %x, %v; want %q, %x, true", id, got, ok, testID, secret)
	}
}

// The checksum rejects a mistyped key without a lookup, and only the form that
// format produces is a key.
func TestParse_RejectsMalformedKeys(t *testing.T) {
	t.Parallel()

	key, _ := testKey(t)
	typo := []byte(key)
	typo[len(Prefix)+40] = map[bool]byte{true: 'b', false: 'a'}[typo[len(Prefix)+40] == 'a']
	// The last character carries four bits beyond the payload, which are zero
	// in the canonical form. Setting the lowest one keeps the payload.
	last := []byte(key)
	last[len(last)-1]++
	for name, k := range map[string]string{
		"empty":          "",
		"prefix only":    Prefix,
		"other prefix":   "nyx_" + key[len(Prefix):],
		"uppercase":      Prefix + strings.ToUpper(key[len(Prefix):]),
		"truncated":      key[:len(key)-1],
		"extended":       key + "a",
		"typo":           string(typo),
		"surrounding":    " " + key[:len(key)-1],
		"non canonical":  string(last),
		"invalid base32": key[:len(key)-1] + "1",
		"session-like":   Prefix + strings.Repeat("A", keyLength-len(Prefix)),
	} {
		if _, _, ok := parse(k); ok {
			t.Errorf("%s: parse(%q) accepted the key", name, k)
		}
	}
}

func TestFormat_RejectsMalformedIDs(t *testing.T) {
	t.Parallel()

	for _, id := range []string{"", "not-a-uuid", strings.ToUpper(testID), testID + "0", strings.ReplaceAll(testID, "-", "")} {
		if _, err := format(id, make([]byte, secretSize)); err == nil {
			t.Errorf("format(%q) accepted the ID", id)
		}
		if validID(id) {
			t.Errorf("validID(%q) = true", id)
		}
	}
}

// The secret is compared in constant time, so that the time of a rejection does
// not reveal how much of a guessed secret was right. Timing cannot be measured
// reliably in a test, so the source is checked: the package compares with
// crypto/subtle and with nothing that returns early.
func TestAuthenticate_ComparesSecretsInConstantTime(t *testing.T) {
	t.Parallel()

	file, err := parser.ParseFile(token.NewFileSet(), "apikey.go", nil, 0)
	if err != nil {
		t.Fatalf("parse apikey.go: %v", err)
	}
	var constant, early []string
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			pkg, ok := n.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch name := pkg.Name + "." + n.Sel.Name; name {
			case "subtle.ConstantTimeCompare":
				constant = append(constant, name)
			case "bytes.Equal", "bytes.Compare", "slices.Equal", "reflect.DeepEqual":
				early = append(early, name)
			}
		case *ast.BasicLit:
			// A comparison in SQL would let the database compare the hash.
			if n.Kind == token.STRING && strings.Contains(n.Value, "secret_hash =") {
				early = append(early, n.Value)
			}
		}
		return true
	})
	if len(constant) != 1 || len(early) != 0 {
		t.Errorf("constant-time comparisons %v, other comparisons %v; want one with crypto/subtle and no other", constant, early)
	}
}
