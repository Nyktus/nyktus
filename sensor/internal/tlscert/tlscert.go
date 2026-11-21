// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tlscert holds the certificate that an operator gives a honeypot for
// TLS, and the settings of TLS that every honeypot shares.
//
// The sensor never makes a certificate of its own: one that it made would be
// the same kind in every installation and identify it.
package tlscert

import (
	"crypto/tls"
	"log/slog"
)

// Certificate is a certificate with its private key. It writes nothing but a
// placeholder, whatever formats or logs a value that holds it ends up in.
type Certificate struct {
	tls.Certificate
}

const redacted = "[redacted]"

// String implements fmt.Stringer.
func (Certificate) String() string { return redacted }

// GoString implements fmt.GoStringer, which %#v and %+v of a struct use.
func (Certificate) GoString() string { return redacted }

// LogValue implements slog.LogValuer.
func (Certificate) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText implements encoding.TextMarshaler, which JSON and YAML encoders
// use.
func (Certificate) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// ServerConfig returns the settings of TLS for a honeypot that presents c:
// TLS 1.2 or later, as the servers it emulates offer. The protocols, if any,
// are those it names in ALPN.
func (c *Certificate) ServerConfig(protocols ...string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{c.Certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   protocols,
	}
}
