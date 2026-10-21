// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package secret holds the type of the secret of a honeypot, which a sensor
// authenticates with. It writes nothing but a placeholder, whatever formats
// or logs a value ends up in.
package secret

import "log/slog"

// Length is the length of a secret: 256 random bits in unpadded base64url.
const Length = 43

const redacted = "[redacted]"

// Secret is the secret of a honeypot. Convert it with string() only where it
// is sent.
type Secret string

// Valid reports whether s has the form of a secret. The server accepts
// nothing else, so a sensor with another value would report in vain.
func Valid(s string) bool {
	if len(s) != Length {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// String implements fmt.Stringer.
func (Secret) String() string { return redacted }

// GoString implements fmt.GoStringer, which %#v and %+v of a struct use.
func (Secret) GoString() string { return redacted }

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText implements encoding.TextMarshaler, which JSON and YAML encoders
// use, so that a value that is written out by mistake holds no secret.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
