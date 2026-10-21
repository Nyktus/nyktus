// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeypot_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"nyktus.org/nyktus/internal/honeypot"
)

// An SSH honeypot of the console, a sensor with the entry that the console
// shows and a host key that the operator created: a login becomes an event with
// the attempts, the fingerprint of the key and the version of the client, and a
// client that never gets as far as a login is an event of its own.
//
// It does not run in parallel with the test of Telnet: each takes a port that it
// finds free and gives back, which two at the same moment could both find.
func TestSensor_SSH_EndToEnd(t *testing.T) { //nolint:paralleltest // see above.

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := cryptossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	// The file is the one that the entry of the console names, next to the
	// configuration.
	env := startEndToEnd(t, honeypot.ServiceSSH, ":22", false, func(dir string, created honeypot.Created) {
		block, err := cryptossh.MarshalPrivateKey(priv, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "ssh_host_key_"+created.ID), pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	addr := fmt.Sprintf("127.0.0.1:%d", env.port)

	// An attacker tries a password and a key.
	clientKey, err := cryptossh.NewSignerFromKey(mustEd25519(t))
	if err != nil {
		t.Fatal(err)
	}
	var shown cryptossh.PublicKey
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	_, _, _, err = cryptossh.NewClientConn(conn, addr, &cryptossh.ClientConfig{
		User: "mallory-typed-this",
		Auth: []cryptossh.AuthMethod{cryptossh.Password("hunter2-typed-this"), cryptossh.PublicKeys(clientKey)},
		HostKeyCallback: func(_ string, _ net.Addr, k cryptossh.PublicKey) error {
			shown = k
			return nil
		},
		ClientVersion: "SSH-2.0-OpenSSH_9.6",
	})
	if err == nil {
		t.Fatal("the login succeeded, want it refused")
	}
	if shown == nil || cryptossh.FingerprintSHA256(shown) != cryptossh.FingerprintSHA256(hostKey.PublicKey()) {
		t.Errorf("the honeypot showed %v, want the key of the file", shown)
	}

	var eventID string
	eventually(t, "the event of the login", func() bool {
		return env.owner.QueryRow(t.Context(), `SELECT id FROM events WHERE resource_id = $1 AND sensor_event_type = 'login_attempt'`, env.created.ID).Scan(&eventID) == nil
	})
	var (
		channel, service, version string
		techniques                []string
	)
	if err := env.owner.QueryRow(t.Context(), `SELECT channel, sensor_service, sensor_client_version, techniques FROM events WHERE id = $1`, eventID).
		Scan(&channel, &service, &version, &techniques); err != nil {
		t.Fatal(err)
	}
	slices.Sort(techniques)
	if channel != "sensor" || service != "ssh" || version != "SSH-2.0-OpenSSH_9.6" || !slices.Equal(techniques, []string{"T1021.004", "T1110"}) {
		t.Errorf("event = %s %s %q %v, want a login attempt at the SSH honeypot with the version of the client and the techniques of brute force and SSH", channel, service, version, techniques)
	}
	rows, err := env.owner.Query(t.Context(), `SELECT username, password_length, key_fingerprint FROM event_attempts WHERE event_id = $1 ORDER BY ordinal`, eventID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type attempt struct {
		user        string
		length      *int
		fingerprint *string
	}
	var attempts []attempt
	for rows.Next() {
		var a attempt
		if err := rows.Scan(&a.user, &a.length, &a.fingerprint); err != nil {
			t.Fatal(err)
		}
		attempts = append(attempts, a)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	wantFingerprint := cryptossh.FingerprintSHA256(clientKey.PublicKey())
	if len(attempts) != 2 ||
		attempts[0].user != "mallory-typed-this" || attempts[0].length == nil || *attempts[0].length != 18 || attempts[0].fingerprint != nil ||
		attempts[1].user != "mallory-typed-this" || attempts[1].length != nil || attempts[1].fingerprint == nil || *attempts[1].fingerprint != wantFingerprint {
		t.Errorf("attempts = %+v, want the password of 18 bytes and then the key %s", attempts, wantFingerprint)
	}

	// A client that never logs in is a connection with its version.
	raw, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Write([]byte("SSH-2.0-libssh_0.9.6\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()
	eventually(t, "the event of the aborted handshake", func() bool {
		var n int
		err := env.owner.QueryRow(t.Context(), `
SELECT count(*) FROM events WHERE resource_id = $1 AND sensor_event_type = 'connection' AND sensor_client_version = 'SSH-2.0-libssh_0.9.6'`, env.created.ID).Scan(&n)
		return err == nil && n == 1
	})

	// The password is nowhere: not in the events, not in their attempts.
	var stored string
	if err := env.owner.QueryRow(t.Context(), `
SELECT coalesce(string_agg(row_to_json(e)::text, ' '), '') || coalesce((SELECT string_agg(row_to_json(a)::text, ' ') FROM event_attempts a), '')
FROM events e`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "hunter2") {
		t.Errorf("the database holds the password: %s", stored)
	}

	if err := env.process.stop(t); err != nil {
		t.Errorf("the sensor ended with %v, want a clean exit", err)
	}
	logs := env.process.log()
	for _, forbidden := range []string{string(env.created.Secret), "mallory-typed-this", "hunter2", wantFingerprint, "OpenSSH_9.6", "libssh"} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("the log of the sensor holds %q:\n%s", forbidden, logs)
		}
	}
}

func mustEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}
