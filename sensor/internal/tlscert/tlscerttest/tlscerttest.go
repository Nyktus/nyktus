// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tlscerttest makes certificates for tests. The sensor itself never
// makes one.
package tlscerttest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"nyktus.org/nyktus/sensor/internal/tlscert"
)

// New returns a self-signed certificate for the name, valid for an hour.
func New(tb testing.TB, name string) *tlscert.Certificate {
	tb.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		tb.Fatal(err)
	}
	return &tlscert.Certificate{Certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}}
}
