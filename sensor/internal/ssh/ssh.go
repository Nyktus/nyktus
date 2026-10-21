// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ssh emulates the login of an SSH server: it speaks the protocol with
// the library of the Go project, announces the version of a common OpenSSH, and
// refuses every login.
//
// It offers nothing behind the login. No login succeeds, so there is never a
// channel, a shell, a command, a forwarded port or a subsystem: the library
// ends the connection when the authentication fails, and no callback returns
// anything but a refusal. What the client sent is read, counted and recorded in
// the session. A password is not kept: only its length. A key is not kept
// either: only its fingerprint.
package ssh

import (
	"context"
	"errors"
	"net"
	"strings"
	"unicode/utf8"

	cryptossh "golang.org/x/crypto/ssh"

	"nyktus.org/nyktus/sensor/internal/clock"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/session"
)

// DefaultVersion is the identification string of the honeypot: the OpenSSH of
// Ubuntu 22.04, where the Telnet honeypot says Ubuntu 22.04 as well. Operators
// change it, because a string that every installation shares is one that a
// scanner can look for.
const DefaultVersion = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"

// errRefused is what every authentication callback returns.
var errRefused = errors.New("ssh: login refused")

// Config holds the identity of a honeypot.
type Config struct {
	// Version is the identification string that the server sends first, without
	// the line ending.
	Version string
	// HostKey is the key of the server. It stays the same from one start to the
	// next: a key that changes would identify the honeypot.
	HostKey HostKey
}

// Service is the SSH honeypot.
type Service struct {
	// base holds what the connections share: the identification string, the
	// limit of failures and the host key. A connection copies it and adds the
	// callbacks of its session.
	base  cryptossh.ServerConfig
	clock clock.Clock
}

// New returns an SSH honeypot. It panics if a dependency is missing.
func New(cfg Config, clk clock.Clock) *Service {
	if clk == nil || cfg.HostKey.Signer == nil || cfg.Version == "" {
		panic("ssh: missing clock, host key or version")
	}
	// The library signs with the default algorithm of a key that does not say
	// which it supports; for Ed25519 that is the only one.
	if t := cfg.HostKey.PublicKey().Type(); t != cryptossh.KeyAlgoED25519 {
		panic("ssh: the host key is of type " + t + ", want an Ed25519 key")
	}
	s := &Service{clock: clk}
	s.base.ServerVersion = cfg.Version
	// As many failures as a session keeps logins. The library counts every
	// refused password and every refused key, and the first "none" of a client,
	// which asks for the methods, is free.
	s.base.MaxAuthTries = session.MaxAttempts
	s.base.AddHostKey(cfg.HostKey)
	return s
}

// Serve plays the login on conn and records the logins in sess. It returns when
// the library has ended the connection: after the sixth refused login, when the
// client has gone, was silent for too long or sent too much. It leaves closing
// the connection to its caller.
func (s *Service) Serve(ctx context.Context, conn net.Conn, sess *session.Session) {
	if ctx.Err() != nil {
		return
	}
	gc := newGuardedConn(conn, s.clock)
	// The version is read where the connection ends, because the library
	// shows it only after the key exchange. A client that fails the exchange
	// is the one that is most worth naming.
	defer func() { sess.SetClientVersion(clean(gc.clientVersion(), report.MaxClientVersion)) }()

	r := &recorder{sess: sess}
	cfg := s.base
	cfg.PasswordCallback = r.password
	cfg.PublicKeyCallback = r.publicKey
	cfg.AuthLogCallback = r.other

	// The login fails, so the library returns an error and closes the
	// connection. Nothing else is possible: no callback grants access.
	if sc, _, _, err := cryptossh.NewServerConn(gc, &cfg); err == nil {
		_ = sc.Close()
	}
}

// recorder records the logins of a session. Each of its methods refuses.
type recorder struct {
	sess *session.Session
	// nones counts the requests for the methods, the first of which costs a
	// client nothing.
	nones int
}

func (r *recorder) password(m cryptossh.ConnMetadata, password []byte) (*cryptossh.Permissions, error) {
	n := len(password)
	r.sess.AddAttempt(report.Attempt{Username: clean(m.User(), report.MaxUsername), PasswordLength: &n})
	return nil, errRefused
}

// publicKey records a key that is offered and refuses it. The library then sends
// no request for a signature, so a client that asks first never signs. One that
// signs at once has the signature checked by the library, and is refused all the
// same: no key opens anything.
func (r *recorder) publicKey(m cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
	r.sess.AddAttempt(report.Attempt{Username: clean(m.User(), report.MaxUsername), KeyFingerprint: cryptossh.FingerprintSHA256(key)})
	return nil, errRefused
}

// other records a client that tries a method that the honeypot does not offer,
// such as keyboard-interactive, which still costs one of its failures. It is a
// login of the session, without a password. So is every "none" after the first,
// which asks for the methods and costs nothing. A password and a key are
// recorded by their own callbacks.
func (r *recorder) other(m cryptossh.ConnMetadata, method string, _ error) {
	switch method {
	case "password", "publickey":
		return
	case "none":
		if r.nones++; r.nones == 1 {
			return
		}
	}
	r.sess.AddAttempt(report.Attempt{Username: clean(m.User(), report.MaxUsername)})
}

// clean returns a text that a client chose in a form that the server accepts:
// valid UTF-8 of at most limit bytes. The server removes characters that do not
// show; what it cannot repair is a text that is not UTF-8 or that is longer than
// its columns.
func clean(s string, limit int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	// The cut may have ended in the middle of a character.
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
