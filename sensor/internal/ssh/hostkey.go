// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ssh

import (
	"errors"
	"fmt"
	"log/slog"

	cryptossh "golang.org/x/crypto/ssh"
)

const redacted = "[redacted]"

// HostKey is the private key of an SSH honeypot. It writes nothing but a
// placeholder, whatever formats or logs a value that holds it ends up in, like
// the secret of a honeypot.
type HostKey struct {
	cryptossh.Signer
}

// ParseHostKey reads the private key of an SSH honeypot: an Ed25519 key without
// a passphrase, as ssh-keygen writes it. The error never holds a byte of data.
func ParseHostKey(data []byte) (HostKey, error) {
	key, err := cryptossh.ParsePrivateKey(data)
	var missing *cryptossh.PassphraseMissingError
	switch {
	case errors.As(err, &missing):
		return HostKey{}, errors.New("the host key is protected by a passphrase: the sensor starts unattended, use a key without one")
	case err != nil:
		return HostKey{}, errors.New("the host key file does not hold a private key in OpenSSH or PEM format")
	case key.PublicKey().Type() != cryptossh.KeyAlgoED25519:
		return HostKey{}, fmt.Errorf("the host key is of type %s, want %s", key.PublicKey().Type(), cryptossh.KeyAlgoED25519)
	}
	return HostKey{Signer: key}, nil
}

// String implements fmt.Stringer.
func (HostKey) String() string { return redacted }

// GoString implements fmt.GoStringer, which %#v and %+v of a struct use.
func (HostKey) GoString() string { return redacted }

// LogValue implements slog.LogValuer.
func (HostKey) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText implements encoding.TextMarshaler, which JSON and YAML encoders
// use.
func (HostKey) MarshalText() ([]byte, error) { return []byte(redacted), nil }
