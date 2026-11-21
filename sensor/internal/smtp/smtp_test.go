// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package smtp_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"nyktus.org/nyktus/sensor/internal/clock/clocktest"
	"nyktus.org/nyktus/sensor/internal/conntest"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/session"
	"nyktus.org/nyktus/sensor/internal/smtp"
	"nyktus.org/nyktus/sensor/internal/tlscert"
	"nyktus.org/nyktus/sensor/internal/tlscert/tlscerttest"
)

const (
	hostname    = "mail.example.com"
	secretValue = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

var (
	remote = netip.MustParseAddrPort("203.0.113.9:51000")
	local  = netip.MustParseAddrPort("10.0.0.5:587")
)

func start(t *testing.T, clk *clocktest.Fake) *session.Session {
	t.Helper()
	hp := &session.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: "smtp", Secret: secretValue}
	s, err := session.Start(clk, hp, remote, local)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func sessionReport(t *testing.T, s *session.Session) report.Session {
	t.Helper()
	rep, ok := s.Report(0)
	if !ok {
		t.Fatal("Report() = not ok")
	}
	return rep
}

// none stands for an attempt without a password in the comparison of logins.
const none = "(no password)"

type login struct {
	user string
	pass string
}

func logins(rep report.Session) []login {
	var out []login
	for _, a := range rep.Attempts {
		p := none
		if a.Password != nil {
			p = *a.Password
		}
		out = append(out, login{a.Username, p})
	}
	return out
}

func config(mode smtp.Mode, cert *tlscert.Certificate) smtp.Config {
	return smtp.Config{Hostname: hostname, Banner: "Postfix (Debian/GNU)", Mode: mode, Certificate: cert}
}

// client speaks to the honeypot over a pipe, one command and one reply at a
// time, as a client without pipelining does.
type client struct {
	t *testing.T
	// raw is the connection as the client reads it, with the bytes it read.
	raw  *recorder
	conn io.ReadWriter
	r    *bufio.Reader
	cert *tlscert.Certificate
	sess *session.Session
	done chan struct{}
	// maxVersion, if set, limits the version of TLS that the client offers.
	maxVersion uint16
	// tlsStart is where TLS began in what the client read.
	tlsStart int
}

// recorder keeps what is read from a connection.
type recorder struct {
	net.Conn
	read bytes.Buffer
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.read.Write(p[:n])
	return n, err
}

// lastRecordType returns the type of the last record of TLS in b, which holds
// records from their start.
func lastRecordType(t *testing.T, b []byte) byte {
	t.Helper()
	var last byte
	for len(b) >= 5 {
		n := 5 + int(b[3])<<8 + int(b[4])
		if n > len(b) {
			t.Fatalf("a record of %d bytes in %d", n, len(b))
		}
		last, b = b[0], b[n:]
	}
	return last
}

// dial starts the honeypot and returns a client connected to it. In implicit
// mode the client starts TLS before anything else.
func dial(t *testing.T, mode smtp.Mode) *client {
	t.Helper()
	return dialTLS(t, mode, 0)
}

// dialTLS is dial with a client that offers TLS up to maxVersion, or the
// default for 0.
func dialTLS(t *testing.T, mode smtp.Mode, maxVersion uint16) *client {
	t.Helper()
	clk := clocktest.New()
	cert := tlscerttest.New(t, hostname)
	clientConn, serverConn := net.Pipe()
	raw := &recorder{Conn: clientConn}
	c := &client{t: t, raw: raw, conn: raw, maxVersion: maxVersion, r: bufio.NewReader(clientConn), cert: cert, sess: start(t, clk), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		defer func() { _ = serverConn.Close() }()
		smtp.New(config(mode, cert), clk).Serve(t.Context(), serverConn, c.sess)
	}()
	t.Cleanup(func() {
		_ = clientConn.Close()
		<-c.done
	})
	if mode == smtp.Implicit {
		c.handshake()
	}
	return c
}

// handshake starts TLS and checks that the server presents the certificate
// that it was given.
func (c *client) handshake() {
	c.t.Helper()
	pool := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(c.cert.Certificate.Certificate[0])
	if err != nil {
		c.t.Fatal(err)
	}
	pool.AddCert(leaf)
	c.tlsStart = c.raw.read.Len()
	tc := tls.Client(c.raw, &tls.Config{RootCAs: pool, ServerName: hostname, MinVersion: tls.VersionTLS12, MaxVersion: c.maxVersion})
	if err := tc.HandshakeContext(c.t.Context()); err != nil {
		c.t.Fatalf("handshake: %v", err)
	}
	c.conn, c.r = tc, bufio.NewReader(tc)
}

func (c *client) send(line string) {
	c.t.Helper()
	if _, err := io.WriteString(c.conn, line+"\r\n"); err != nil {
		c.t.Fatalf("send %q: %v", line, err)
	}
}

// reply reads a reply of one or more lines and returns its lines.
func (c *client) reply() []string {
	c.t.Helper()
	var lines []string
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Fatalf("reply after %q: %v", lines, err)
		}
		if !strings.HasSuffix(line, "\r\n") {
			c.t.Fatalf("line %q does not end with CRLF", line)
		}
		line = strings.TrimSuffix(line, "\r\n")
		lines = append(lines, line)
		if len(line) < 4 || line[3] != '-' {
			return lines
		}
	}
}

// expect reads a reply of one line and checks it.
func (c *client) expect(want string) {
	c.t.Helper()
	if got := c.reply(); len(got) != 1 || got[0] != want {
		c.t.Fatalf("reply = %q, want %q", got, want)
	}
}

// do sends a command and checks its reply of one line.
func (c *client) do(line, want string) {
	c.t.Helper()
	c.send(line)
	c.expect(want)
}

// closed checks that the server has ended the connection.
func (c *client) closed() {
	c.t.Helper()
	if b, err := c.r.ReadByte(); err == nil {
		c.t.Fatalf("read %q, want the end of the connection", b)
	}
}

// finish closes the connection and returns the report of the session.
func (c *client) finish() report.Session {
	c.t.Helper()
	_ = c.raw.Close()
	<-c.done
	c.sess.End()
	return sessionReport(c.t, c.sess)
}

// signIn greets, starts TLS and greets again, as a mail client does.
func (c *client) signIn() {
	c.t.Helper()
	c.expect("220 mail.example.com ESMTP Postfix (Debian/GNU)")
	c.send("EHLO client.example")
	c.reply()
	c.do("STARTTLS", "220 2.0.0 Ready to start TLS")
	c.handshake()
	c.send("EHLO client.example")
	c.reply()
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestServe_EHLO_OffersSTARTTLSBeforeAndAUTHOnlyAfterTLS(t *testing.T) {
	t.Parallel()

	c := dial(t, smtp.StartTLS)
	c.expect("220 mail.example.com ESMTP Postfix (Debian/GNU)")
	c.send("EHLO client.example")
	plain := []string{"250-mail.example.com", "250-SIZE 10240000", "250-STARTTLS", "250-ENHANCEDSTATUSCODES", "250-8BITMIME", "250 DSN"}
	if got := c.reply(); !reflect.DeepEqual(got, plain) {
		t.Errorf("EHLO before TLS = %q, want %q", got, plain)
	}
	c.do("STARTTLS", "220 2.0.0 Ready to start TLS")
	c.handshake()
	c.send("EHLO client.example")
	encrypted := []string{"250-mail.example.com", "250-SIZE 10240000", "250-AUTH PLAIN LOGIN", "250-ENHANCEDSTATUSCODES", "250-8BITMIME", "250 DSN"}
	if got := c.reply(); !reflect.DeepEqual(got, encrypted) {
		t.Errorf("EHLO after TLS = %q, want %q", got, encrypted)
	}
	c.do("STARTTLS", "554 5.5.1 Error: TLS already active")
	c.do("HELO client.example", "250 mail.example.com")
	c.do("QUIT", "221 2.0.0 Bye")
	c.closed()
	if rep := c.finish(); rep.ClientVersion != "client.example" || len(rep.Attempts) != 0 {
		t.Errorf("report = %+v, want the name of the client and no login", rep)
	}
}

// A server that signs in over TLS only offers no AUTH before it and refuses
// every command of a transaction, so no password travels in clear text.
func TestServe_BeforeTLS_RefusesAUTHAndMail(t *testing.T) {
	t.Parallel()

	c := dial(t, smtp.StartTLS)
	c.expect("220 mail.example.com ESMTP Postfix (Debian/GNU)")
	c.send("EHLO client.example")
	c.reply()
	for _, line := range []string{"AUTH PLAIN " + b64("\x00admin\x00secret"), "AUTH LOGIN", "MAIL FROM:<a@example.com>", "RCPT TO:<b@example.com>", "DATA"} {
		c.do(line, "530 5.7.0 Must issue a STARTTLS command first")
	}
	if rep := c.finish(); len(rep.Attempts) != 0 {
		t.Errorf("attempts = %+v, want none", rep.Attempts)
	}
}

func TestServe_AUTH_RecordsEveryLoginAndRefusesIt(t *testing.T) {
	t.Parallel()

	c := dial(t, smtp.StartTLS)
	c.signIn()
	const failed = "535 5.7.8 Error: authentication failed: authentication failure"
	c.do("AUTH PLAIN "+b64("\x00admin\x00Winter2026!"), failed)
	c.do("auth plain", "334 ")
	c.do(b64("someone\x00backup\x00hunter2"), failed)
	c.do("AUTH LOGIN", "334 VXNlcm5hbWU6")
	c.do(b64("postmaster"), "334 UGFzc3dvcmQ6")
	c.do(b64("letmein"), failed)
	c.do("AUTH LOGIN "+b64("info"), "334 UGFzc3dvcmQ6")
	c.do(b64(""), failed)
	// A space after the mechanism is no response; the server asks for one.
	c.do("AUTH PLAIN ", "334 ")
	c.do(b64("\x00trailing\x00space"), failed)
	got := logins(c.finish())
	want := []login{{"admin", "Winter2026!"}, {"backup", "hunter2"}, {"postmaster", "letmein"}, {"info", ""}, {"trailing", "space"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("logins = %+v, want %+v", got, want)
	}
}

// The user of AUTH LOGIN is recorded once it is known, also when the password
// never arrives or the client cancels.
func TestServe_AUTHLOGIN_RecordsTheUserWithoutAPassword(t *testing.T) {
	t.Parallel()

	c := dial(t, smtp.StartTLS)
	c.signIn()
	c.do("AUTH LOGIN "+b64("aborted"), "334 UGFzc3dvcmQ6")
	c.do("*", "501 5.7.0 Authentication aborted")
	c.do("AUTH LOGIN "+b64("gone"), "334 UGFzc3dvcmQ6")
	got := logins(c.finish())
	if want := []login{{"aborted", none}, {"gone", none}}; !reflect.DeepEqual(got, want) {
		t.Errorf("logins = %+v, want %+v", got, want)
	}
}

func TestServe_AUTH_RefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()

	c := dial(t, smtp.StartTLS)
	c.signIn()
	c.do("AUTH", "501 5.5.4 Syntax: AUTH mechanism")
	c.do("AUTH CRAM-MD5", "535 5.7.8 Error: authentication failed: Invalid authentication mechanism")
	c.do("AUTH PLAIN not-base64", "501 5.5.2 Cannot decode response")
	c.do("AUTH PLAIN "+b64("only-a-name"), "535 5.7.8 Error: authentication failed: authentication failure")
	c.do("AUTH PLAIN", "334 ")
	c.do("*", "501 5.7.0 Authentication aborted")
	c.do("AUTH LOGIN", "334 VXNlcm5hbWU6")
	c.do("%%%", "501 5.5.2 Cannot decode response")
	if rep := c.finish(); len(rep.Attempts) != 0 {
		t.Errorf("attempts = %+v, want none", rep.Attempts)
	}
}

// A session keeps a fixed number of logins. The server records them and sends
// away the client that wants more.
func TestServe_AUTH_EndsTheConnectionAfterTheLoginsThatASessionKeeps(t *testing.T) {
	t.Parallel()

	c := dial(t, smtp.StartTLS)
	c.signIn()
	for range session.MaxAttempts {
		c.do("AUTH PLAIN "+b64("\x00admin\x00pw"), "535 5.7.8 Error: authentication failed: authentication failure")
	}
	c.do("AUTH PLAIN "+b64("\x00admin\x00one-more"), "421 4.7.0 mail.example.com Error: too many errors")
	c.closed()
	if got := c.finish().Attempts; len(got) != session.MaxAttempts {
		t.Errorf("%d attempts, want %d", len(got), session.MaxAttempts)
	}
}

// The server never relays and never reads a message, and it names no address
// that the client sent.
func TestServe_Mail_IsNeverRelayedAndNoMessageIsRead(t *testing.T) {
	t.Parallel()

	c := dial(t, smtp.StartTLS)
	c.signIn()
	c.do("RCPT TO:<x@example.org>", "503 5.5.1 Error: need MAIL command")
	c.do("DATA", "503 5.5.1 Error: need RCPT command")
	c.do("MAIL FROM:<ceo@example.com>", "250 2.1.0 Ok")
	c.do("MAIL FROM:<ceo@example.com>", "503 5.5.1 Error: nested MAIL command")
	c.do("AUTH PLAIN "+b64("\x00a\x00b"), "503 5.5.1 Error: MAIL transaction in progress")
	c.do("RCPT TO:<victim@example.org>", "554 5.7.1 Relay access denied")
	c.do("RCPT victim@example.org", "501 5.5.4 Syntax: RCPT TO:<address>")
	c.do("DATA", "554 5.5.1 Error: no valid recipients")
	// What would have been the message is read as commands, and refused.
	c.do("Subject: invoice", "502 5.5.2 Error: command not recognized")
	c.do("RSET", "250 2.0.0 Ok")
	c.do("MAIL to@example.org", "501 5.5.4 Syntax: MAIL FROM:<address>")
	c.do("NOOP", "250 2.0.0 Ok")
	c.do("VRFY root", "502 5.5.1 VRFY command is disabled")
	if rep := c.finish(); len(rep.Attempts) != 0 {
		t.Errorf("attempts = %+v, want none", rep.Attempts)
	}
}

// What the client sent in clear text after its STARTTLS, before TLS, must not
// count as said inside TLS: anyone on the way could have added it.
func TestServe_LinesAfterSTARTTLS_AreDropped(t *testing.T) {
	t.Parallel()

	c := dial(t, smtp.StartTLS)
	c.expect("220 mail.example.com ESMTP Postfix (Debian/GNU)")
	c.send("EHLO client.example")
	c.reply()
	// One write, so that the server reads the injected line with STARTTLS.
	if _, err := io.WriteString(c.conn, "STARTTLS\r\nEHLO injected.example\r\n"); err != nil {
		t.Fatal(err)
	}
	c.expect("220 2.0.0 Ready to start TLS")
	c.handshake()
	// The dialog starts again, and the injected greeting did not count.
	c.do("MAIL FROM:<a@example.com>", "503 5.5.1 Error: send HELO/EHLO first")
	if rep := c.finish(); rep.ClientVersion != "client.example" {
		t.Errorf("client version = %q, want the one sent before STARTTLS", rep.ClientVersion)
	}
}

func TestServe_Implicit_SpeaksTLSFromTheFirstByte(t *testing.T) {
	t.Parallel()

	c := dial(t, smtp.Implicit)
	c.expect("220 mail.example.com ESMTP Postfix (Debian/GNU)")
	c.send("EHLO client.example")
	if got := c.reply(); !reflect.DeepEqual(got, []string{"250-mail.example.com", "250-SIZE 10240000", "250-AUTH PLAIN LOGIN", "250-ENHANCEDSTATUSCODES", "250-8BITMIME", "250 DSN"}) {
		t.Errorf("EHLO = %q, want AUTH and no STARTTLS", got)
	}
	c.do("STARTTLS", "554 5.5.1 Error: TLS already active")
	c.do("AUTH PLAIN "+b64("\x00admin\x00pw"), "535 5.7.8 Error: authentication failed: authentication failure")
	if got := logins(c.finish()); !reflect.DeepEqual(got, []login{{"admin", "pw"}}) {
		t.Errorf("logins = %+v", got)
	}
}

// A client that speaks plain text to the port of implicit TLS gets nothing
// back, as from a real server.
func TestServe_Implicit_SaysNothingInClearText(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := conntest.New([]byte("EHLO client.example\r\n"))
	s := start(t, clk)
	smtp.New(config(smtp.Implicit, tlscerttest.New(t, hostname)), clk).Serve(t.Context(), conn, s)
	s.End()
	if bytes.Contains(conn.Written(), []byte("220")) || bytes.Contains(conn.Written(), []byte("250")) {
		t.Errorf("written = %q, want no answer of SMTP", conn.Written())
	}
	if rep := sessionReport(t, s); rep.ClientVersion != "" {
		t.Errorf("client version = %q, want none", rep.ClientVersion)
	}
}

func TestServe_Greeting_WithoutABanner(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := conntest.New([]byte("QUIT\r\n"))
	cfg := config(smtp.StartTLS, tlscerttest.New(t, hostname))
	cfg.Banner = ""
	smtp.New(cfg, clk).Serve(t.Context(), conn, start(t, clk))
	if got := string(conn.Written()); got != "220 mail.example.com ESMTP\r\n221 2.0.0 Bye\r\n" {
		t.Errorf("written = %q", got)
	}
}

// play runs a honeypot in plain text against a client that sends script.
func play(t *testing.T, script string) (*session.Session, string) {
	t.Helper()
	clk := clocktest.New()
	conn := conntest.New([]byte(script))
	s := start(t, clk)
	smtp.New(config(smtp.StartTLS, tlscerttest.New(t, hostname)), clk).Serve(t.Context(), conn, s)
	s.End()
	return s, string(conn.Written())
}

func TestServe_SyntaxErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		line, want string
	}{
		{"EHLO", "501 Syntax: EHLO hostname"},
		{"HELO", "501 Syntax: HELO hostname"},
		{"", "500 5.5.2 Error: bad syntax"},
		{"HELP", "502 5.5.2 Error: command not recognized"},
		{"STARTTLS now", "501 5.5.4 Syntax: STARTTLS"},
		{strings.Repeat("A", 3000), "500 5.5.2 Error: bad syntax"},
	}
	for _, tt := range tests {
		_, written := play(t, tt.line+"\r\nNOOP\r\n")
		if want := "220 mail.example.com ESMTP Postfix (Debian/GNU)\r\n" + tt.want + "\r\n250 2.0.0 Ok\r\n"; written != want {
			t.Errorf("%.20q: written = %q, want %q", tt.line, written, want)
		}
	}
}

// Lines end with CRLF or a bare LF, and commands are read in any case.
func TestServe_ReadsBareLFAndCommandsInAnyCase(t *testing.T) {
	t.Parallel()

	s, written := play(t, "ehlo client.example\nnoop\r\nQuIt\n")
	if !strings.HasSuffix(written, "250 DSN\r\n250 2.0.0 Ok\r\n221 2.0.0 Bye\r\n") {
		t.Errorf("written = %q", written)
	}
	if rep := sessionReport(t, s); rep.ClientVersion != "client.example" {
		t.Errorf("client version = %q", rep.ClientVersion)
	}
}

func TestServe_EndsTheConnectionAfterTooManyErrors(t *testing.T) {
	t.Parallel()

	_, written := play(t, strings.Repeat("HELP\r\n", 25))
	if got := strings.Count(written, "502 5.5.2 Error: command not recognized\r\n"); got != 20 {
		t.Errorf("%d refusals, want 20", got)
	}
	if !strings.HasSuffix(written, "502 5.5.2 Error: command not recognized\r\n421 4.7.0 mail.example.com Error: too many errors\r\n") {
		t.Errorf("written ends with %q, want the end of the connection", written[len(written)-80:])
	}
}

// The name that the client gives is recorded within the limits of the report,
// and is the one part of what it sent that the server does not refuse; it is
// never sent back.
func TestServe_TheNameOfTheClient_IsRecordedAndNeverSentBack(t *testing.T) {
	t.Parallel()

	name := "x\xff" + strings.Repeat("n", 300)
	s, written := play(t, "EHLO "+name+"\r\nMAIL FROM:<mark@example.com>\r\nVRFY mark\r\nmark\r\n")
	rep := sessionReport(t, s)
	if len(rep.ClientVersion) > report.MaxClientVersion || !strings.HasPrefix(rep.ClientVersion, "x\uFFFDnnn") {
		t.Errorf("client version = %q, want the name cut and made valid UTF-8", rep.ClientVersion)
	}
	if strings.Contains(written, "nnn") || strings.Contains(written, "mark") {
		t.Errorf("written = %q, want nothing of what the client sent", written)
	}
}

func TestNew_PanicsWithoutWhatItNeeds(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	cert := tlscerttest.New(t, hostname)
	for name, tt := range map[string]struct {
		cfg   smtp.Config
		clock *clocktest.Fake
	}{
		"clock":       {config(smtp.StartTLS, cert), nil},
		"certificate": {config(smtp.StartTLS, nil), clk},
		"hostname":    {smtp.Config{Mode: smtp.StartTLS, Certificate: cert}, clk},
		"mode":        {config("tls", cert), clk},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("New without %s did not panic", name)
				}
			}()
			if tt.clock == nil {
				smtp.New(tt.cfg, nil)
				return
			}
			smtp.New(tt.cfg, tt.clock)
		}()
	}
}

// A mail server ends TLS with its alert before it closes the connection. A
// client that gets none reports a cut connection, which would set the
// honeypot apart. TLS 1.2 shows the type of the alert on the wire.
func TestServe_QUIT_EndsTLSWithItsAlert(t *testing.T) {
	t.Parallel()

	for _, mode := range []smtp.Mode{smtp.StartTLS, smtp.Implicit} {
		c := dialTLS(t, mode, tls.VersionTLS12)
		if mode == smtp.StartTLS {
			c.signIn()
		} else {
			c.expect("220 mail.example.com ESMTP Postfix (Debian/GNU)")
		}
		c.do("QUIT", "221 2.0.0 Bye")
		c.closed()
		const alert = 21
		if got := lastRecordType(t, c.raw.read.Bytes()[c.tlsStart:]); got != alert {
			t.Errorf("%s: the last record has the type %d, want the alert that ends TLS", mode, got)
		}
	}
}
