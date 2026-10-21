// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ssh_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	cryptossh "golang.org/x/crypto/ssh"

	"nyktus.org/nyktus/sensor/internal/clock"
	"nyktus.org/nyktus/sensor/internal/clock/clocktest"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/session"
	"nyktus.org/nyktus/sensor/internal/ssh"
)

const honeypotID = "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d"

func newSigner(t *testing.T) cryptossh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// honeypot is a running SSH honeypot that serves one connection.
type honeypot struct {
	addr string
	cfg  ssh.Config
	done chan *session.Session
}

func serve(t *testing.T) *honeypot {
	t.Helper()
	return serveWith(t, ssh.Config{Version: ssh.DefaultVersion, HostKey: newSigner(t)}, clocktest.New())
}

func serveWith(t *testing.T, cfg ssh.Config, clk clock.Clock) *honeypot {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	h := &honeypot{addr: ln.Addr().String(), cfg: cfg, done: make(chan *session.Session, 1)}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck // nothing to do about a failed close in a test.
		hp := &session.Honeypot{ID: honeypotID, Service: "ssh", Secret: "x"}
		s, err := session.Start(clk, hp, netip.MustParseAddrPort("203.0.113.9:51000"), netip.MustParseAddrPort("10.0.0.5:22"))
		if err != nil {
			panic(err)
		}
		ssh.New(cfg, clk).Serve(t.Context(), conn, s)
		s.End()
		h.done <- s
	}()
	return h
}

// session waits until the honeypot has ended the connection and returns what it
// recorded. A honeypot that does not end it fails the test.
func (h *honeypot) session(t *testing.T) *session.Session {
	t.Helper()
	select {
	case s := <-h.done:
		return s
	case <-time.After(10 * time.Second):
		t.Fatal("the honeypot did not end the connection")
		return nil
	}
}

func (h *honeypot) report(t *testing.T) report.Session {
	t.Helper()
	rep, ok := h.session(t).Report(0)
	if !ok {
		t.Fatal("Report() = not ok")
	}
	return rep
}

// login connects with the client configuration and returns the error of the
// handshake. Every login fails, so the error is expected.
func (h *honeypot) login(t *testing.T, cc *cryptossh.ClientConfig) error {
	t.Helper()
	if cc.ClientVersion == "" {
		cc.ClientVersion = "SSH-2.0-OpenSSH_9.6"
	}
	cc.HostKeyCallback = cryptossh.FixedHostKey(h.cfg.HostKey.PublicKey())
	cc.Timeout = 10 * time.Second
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(t.Context(), "tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck // nothing to do about a failed close in a test.
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	c, chans, reqs, err := cryptossh.NewClientConn(conn, h.addr, cc)
	if err == nil {
		_ = cryptossh.NewClient(c, chans, reqs).Close()
	}
	return err
}

// raw connects, sends the bytes and closes the connection.
func (h *honeypot) raw(t *testing.T, data []byte) {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(t.Context(), "tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck // nothing to do about a failed close in a test.
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}
}

func TestServe_Password_RecordsTheUserAndTheLengthOfThePassword(t *testing.T) {
	t.Parallel()

	h := serve(t)
	err := h.login(t, &cryptossh.ClientConfig{User: "root", Auth: []cryptossh.AuthMethod{cryptossh.Password("p4ssw0rd")}})
	if err == nil {
		t.Fatal("the login succeeded, want it refused")
	}
	rep := h.report(t)
	if len(rep.Attempts) != 1 || rep.Attempts[0].Username != "root" || rep.Attempts[0].PasswordLength == nil || *rep.Attempts[0].PasswordLength != 8 || rep.Attempts[0].KeyFingerprint != "" {
		t.Errorf("attempts = %+v, want one login of root with a password of 8 bytes", rep.Attempts)
	}
	if rep.ClientVersion != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("client_version = %q, want the version of the client", rep.ClientVersion)
	}
}

func TestServe_EmptyPassword_IsALoginWithLengthZero(t *testing.T) {
	t.Parallel()

	h := serve(t)
	_ = h.login(t, &cryptossh.ClientConfig{User: "root", Auth: []cryptossh.AuthMethod{cryptossh.Password("")}})
	rep := h.report(t)
	if len(rep.Attempts) != 1 || rep.Attempts[0].PasswordLength == nil || *rep.Attempts[0].PasswordLength != 0 {
		t.Errorf("attempts = %+v, want one login with a password of length 0", rep.Attempts)
	}
}

var fingerprintFormat = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

func TestServe_PublicKey_RecordsTheFingerprintAndRefusesTheKey(t *testing.T) {
	t.Parallel()

	h := serve(t)
	key := newSigner(t)
	err := h.login(t, &cryptossh.ClientConfig{User: "admin", Auth: []cryptossh.AuthMethod{cryptossh.PublicKeys(key)}})
	if err == nil {
		t.Fatal("the login succeeded, want it refused")
	}
	rep := h.report(t)
	want := cryptossh.FingerprintSHA256(key.PublicKey())
	if len(rep.Attempts) != 1 || rep.Attempts[0].Username != "admin" || rep.Attempts[0].KeyFingerprint != want || rep.Attempts[0].PasswordLength != nil {
		t.Errorf("attempts = %+v, want one login of admin with the key %s and no password", rep.Attempts, want)
	}
	if !fingerprintFormat.MatchString(rep.Attempts[0].KeyFingerprint) {
		t.Errorf("key_fingerprint = %q, want the form the server accepts", rep.Attempts[0].KeyFingerprint)
	}
}

func TestServe_SeveralKeys_AreSeveralLogins(t *testing.T) {
	t.Parallel()

	h := serve(t)
	a, b := newSigner(t), newSigner(t)
	_ = h.login(t, &cryptossh.ClientConfig{User: "deploy", Auth: []cryptossh.AuthMethod{cryptossh.PublicKeys(a, b)}})
	rep := h.report(t)
	got := make([]string, 0, len(rep.Attempts))
	for _, at := range rep.Attempts {
		got = append(got, at.KeyFingerprint)
	}
	want := []string{cryptossh.FingerprintSHA256(a.PublicKey()), cryptossh.FingerprintSHA256(b.PublicKey())}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("key fingerprints = %v, want %v in the order offered", got, want)
	}
}

// Whatever a client offers, no login succeeds, so the library never returns a
// connection: there is no channel, no shell, no command, no forwarded port and
// no subsystem to refuse.
func TestServe_EveryMethodOfLogin_Fails(t *testing.T) {
	t.Parallel()

	key := newSigner(t)
	methods := map[string][]cryptossh.AuthMethod{
		"none":                 nil,
		"password":             {cryptossh.Password("root")},
		"empty password":       {cryptossh.Password("")},
		"public key":           {cryptossh.PublicKeys(key)},
		"keyboard-interactive": {cryptossh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) { return []string{"root"}, nil })},
	}
	for name, auth := range methods {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := serve(t)
			if err := h.login(t, &cryptossh.ClientConfig{User: "root", Auth: auth}); err == nil {
				t.Fatal("the login succeeded, want it refused")
			}
			h.session(t)
		})
	}
}

func TestServe_SeventhLogin_IsNeverOffered(t *testing.T) {
	t.Parallel()

	h := serve(t)
	next := 0
	auth := cryptossh.RetryableAuthMethod(cryptossh.PasswordCallback(func() (string, error) {
		next++
		return strings.Repeat("x", next), nil
	}), 10)
	if err := h.login(t, &cryptossh.ClientConfig{User: "root", Auth: []cryptossh.AuthMethod{auth}}); err == nil {
		t.Fatal("the login succeeded, want it refused")
	}
	rep := h.report(t)
	if len(rep.Attempts) != session.MaxAttempts {
		t.Fatalf("attempts = %d, want %d: the sixth refusal ends the connection", len(rep.Attempts), session.MaxAttempts)
	}
	for i, a := range rep.Attempts {
		if a.PasswordLength == nil || *a.PasswordLength != i+1 {
			t.Errorf("attempt %d = %+v, want a password of %d bytes", i, a, i+1)
		}
	}
	if next != session.MaxAttempts {
		t.Errorf("the client was asked for %d passwords, want %d", next, session.MaxAttempts)
	}
}

// The report of a session has the members of the golden file, in every login
// and in the session, and no others: the server decodes the same document.
func TestServe_Report_HasTheShapeOfTheGoldenSessionOfSSH(t *testing.T) {
	t.Parallel()

	h := serve(t)
	auth := []cryptossh.AuthMethod{cryptossh.Password("p4ssw0rd"), cryptossh.PublicKeys(newSigner(t))}
	_ = h.login(t, &cryptossh.ClientConfig{User: "root", Auth: auth})
	got, err := json.Marshal(h.report(t))
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile("../report/testdata/session_ssh.json")
	if err != nil {
		t.Fatal(err)
	}
	var want, have any
	if err := json.Unmarshal(golden, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &have); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(shape(want)) != fmt.Sprint(shape(have)) {
		t.Errorf("report = %s, want the members of session_ssh.json: %s", got, golden)
	}
}

// shape replaces the values of a document by their kind, so that two documents
// with the same members have the same shape.
func shape(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range v {
			out[k] = shape(e)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = shape(e)
		}
		return out
	default:
		return fmt.Sprintf("%T", v)
	}
}

func TestServe_Password_AndKey_NeverReachTheReportOrTheLog(t *testing.T) {
	t.Parallel()

	const password = "Tr0ub4dor&3-hunter2"
	h := serve(t)
	key := newSigner(t)
	_ = h.login(t, &cryptossh.ClientConfig{User: "root", Auth: []cryptossh.AuthMethod{cryptossh.Password(password), cryptossh.PublicKeys(key)}})
	s := h.session(t)
	rep, _ := s.Report(0)
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	slog.New(slog.NewJSONHandler(&log, nil)).Info("sensor: session", s.Attr())
	slog.New(slog.NewJSONHandler(&log, nil)).Info("sensor: session", slog.Any("session", s))
	blob := base64Key(key)
	for name, text := range map[string]string{"report": string(data), "log": log.String()} {
		if strings.Contains(text, password) || strings.Contains(text, blob) {
			t.Errorf("the %s holds the password or the key: %s", name, text)
		}
	}
}

func base64Key(s cryptossh.Signer) string {
	line := string(cryptossh.MarshalAuthorizedKey(s.PublicKey()))
	_, b64, _ := strings.Cut(strings.TrimSpace(line), " ")
	return b64
}

func TestServe_AbortedHandshake_ReportsTheVersionOfTheClient(t *testing.T) {
	t.Parallel()

	h := serve(t)
	h.raw(t, []byte("SSH-2.0-libssh_0.9.6\r\n"))
	rep := h.report(t)
	if rep.ClientVersion != "SSH-2.0-libssh_0.9.6" || len(rep.Attempts) != 0 {
		t.Errorf("client_version = %q, attempts = %+v, want the version and no login", rep.ClientVersion, rep.Attempts)
	}
}

func TestServe_FailedKeyExchange_ReportsTheVersionOfTheClient(t *testing.T) {
	t.Parallel()

	h := serve(t)
	h.raw(t, append([]byte("SSH-2.0-paramiko_1.7\r\n"), bytes.Repeat([]byte{0xff}, 64)...))
	if got := h.report(t).ClientVersion; got != "SSH-2.0-paramiko_1.7" {
		t.Errorf("client_version = %q, want the version of the client", got)
	}
}

func TestServe_ClientThatOffersOnlyAnotherHostKey_FailsTheExchangeWithItsVersion(t *testing.T) {
	t.Parallel()

	h := serve(t)
	err := h.login(t, &cryptossh.ClientConfig{
		User:              "root",
		Auth:              []cryptossh.AuthMethod{cryptossh.Password("x")},
		HostKeyAlgorithms: []string{cryptossh.KeyAlgoRSASHA256},
		ClientVersion:     "SSH-2.0-old",
	})
	if err == nil {
		t.Fatal("the exchange succeeded, want it to fail: the honeypot has an Ed25519 key only")
	}
	rep := h.report(t)
	if rep.ClientVersion != "SSH-2.0-old" || len(rep.Attempts) != 0 {
		t.Errorf("client_version = %q, attempts = %+v, want the version and no login", rep.ClientVersion, rep.Attempts)
	}
}

func TestServe_NoVersionLine_ReportsNoVersion(t *testing.T) {
	t.Parallel()

	for name, data := range map[string]string{
		"http":    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"nothing": "",
		"binary":  "\x16\x03\x01\x02\x00\x01\x00",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := serve(t)
			h.raw(t, []byte(data))
			rep := h.report(t)
			if rep.ClientVersion != "" || len(rep.Attempts) != 0 {
				t.Errorf("client_version = %q, attempts = %+v, want neither", rep.ClientVersion, rep.Attempts)
			}
		})
	}
}

func TestServe_LinesBeforeTheVersion_AreSkipped(t *testing.T) {
	t.Parallel()

	h := serve(t)
	h.raw(t, []byte("hello\r\nworld\nSSH-2.0-Go\n"))
	if got := h.report(t).ClientVersion; got != "SSH-2.0-Go" {
		t.Errorf("client_version = %q, want the first line that starts with SSH-", got)
	}
}

func TestServe_LongVersion_IsCutToWhatTheServerAccepts(t *testing.T) {
	t.Parallel()

	h := serve(t)
	h.raw(t, []byte("SSH-2.0-"+strings.Repeat("a", 200)+"\r\n"))
	got := h.report(t).ClientVersion
	if len(got) != report.MaxClientVersion || !strings.HasPrefix(got, "SSH-2.0-aaaa") {
		t.Errorf("client_version has %d bytes, want %d", len(got), report.MaxClientVersion)
	}
}

func TestServe_UserName_IsValidUTF8OfAtMost256Bytes(t *testing.T) {
	t.Parallel()

	methods := map[string]func(t *testing.T) cryptossh.AuthMethod{
		"password": func(*testing.T) cryptossh.AuthMethod { return cryptossh.Password("x") },
		"key": func(t *testing.T) cryptossh.AuthMethod {
			t.Helper()
			return cryptossh.PublicKeys(newSigner(t))
		},
	}
	for method, auth := range methods {
		for name, user := range map[string]string{
			"invalid bytes": "ro\xff\xfeot",
			"long":          strings.Repeat("a", 5000),
			"long wide":     strings.Repeat("\u00e9", 300),
			"cut inside":    strings.Repeat("a", 255) + "\u00e9",
		} {
			t.Run(method+" "+name, func(t *testing.T) {
				t.Parallel()
				h := serve(t)
				_ = h.login(t, &cryptossh.ClientConfig{User: user, Auth: []cryptossh.AuthMethod{auth(t)}})
				rep := h.report(t)
				if len(rep.Attempts) != 1 {
					t.Fatalf("attempts = %+v, want one", rep.Attempts)
				}
				got := rep.Attempts[0].Username
				if !utf8.ValidString(got) || len(got) > report.MaxUsername {
					t.Errorf("username has %d bytes, valid UTF-8 %v, want valid UTF-8 of at most %d bytes", len(got), utf8.ValidString(got), report.MaxUsername)
				}
			})
		}
	}
}

// A client that sends more than a login needs is cut off where it has sent 16
// KiB, and does not keep the connection for the idle time of 30 seconds.
func TestServe_MoreThan16KiB_EndsTheSession(t *testing.T) {
	t.Parallel()

	h := serve(t)
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(t.Context(), "tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck // nothing to do about a failed close in a test.
	// Lines before the version are skipped by the library, up to 1024 of them:
	// 20,000 bytes in fewer lines than that only end at the limit of bytes.
	if _, err := conn.Write(bytes.Repeat([]byte(strings.Repeat("a", 19)+"\n"), 1000)); err != nil {
		t.Fatal(err)
	}
	h.session(t)
}

func TestServe_CanceledContext_ReadsAndWritesNothing(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close() //nolint:errcheck // nothing to do about a failed close in a test.
	defer server.Close() //nolint:errcheck // nothing to do about a failed close in a test.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	clk := clocktest.New()
	hp := &session.Honeypot{ID: honeypotID, Service: "ssh"}
	s, err := session.Start(clk, hp, netip.MustParseAddrPort("203.0.113.9:1"), netip.MustParseAddrPort("10.0.0.5:22"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		ssh.New(ssh.Config{Version: ssh.DefaultVersion, HostKey: newSigner(t)}, clk).Serve(ctx, server, s)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return for a canceled context")
	}
}

func TestServe_Version_IsWhatTheConfigurationSays(t *testing.T) {
	t.Parallel()

	key := newSigner(t)
	h := serveWith(t, ssh.Config{Version: "SSH-2.0-dropbear_2022.83", HostKey: key}, clocktest.New())
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(t.Context(), "tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck // nothing to do about a failed close in a test.
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(buf[:n]), "SSH-2.0-dropbear_2022.83\r\n"; got != want {
		t.Errorf("first bytes = %q, want %q", got, want)
	}
}

func TestServe_HostKey_IsTheConfiguredOneAndNothingElse(t *testing.T) {
	t.Parallel()

	key := newSigner(t)
	for range 2 {
		h := serveWith(t, ssh.Config{Version: ssh.DefaultVersion, HostKey: key}, clocktest.New())
		var seen cryptossh.PublicKey
		cc := &cryptossh.ClientConfig{
			User: "root",
			Auth: []cryptossh.AuthMethod{cryptossh.Password("x")},
			HostKeyCallback: func(_ string, _ net.Addr, k cryptossh.PublicKey) error {
				seen = k
				return nil
			},
		}
		conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(t.Context(), "tcp", h.addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, _ = cryptossh.NewClientConn(conn, h.addr, cc)
		_ = conn.Close()
		h.session(t)
		if seen == nil || !bytes.Equal(seen.Marshal(), key.PublicKey().Marshal()) {
			t.Fatalf("host key offered = %v, want the configured key on every start", seen)
		}
	}
}

func TestNew_MissingParts_Panics(t *testing.T) {
	t.Parallel()

	key := newSigner(t)
	for name, f := range map[string]func(){
		"clock":    func() { ssh.New(ssh.Config{Version: ssh.DefaultVersion, HostKey: key}, nil) },
		"host key": func() { ssh.New(ssh.Config{Version: ssh.DefaultVersion}, clocktest.New()) },
		"version":  func() { ssh.New(ssh.Config{HostKey: key}, clocktest.New()) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("New without a %s did not panic", name)
				}
			}()
			f()
		}()
	}
}
