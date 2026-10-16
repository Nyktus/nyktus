// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"nyktus.org/nyktus/internal/platform/smtp/smtptest"
)

const testPassword = "correct horse battery staple"

var testCredentials = &smtptest.Credentials{Username: "nyktus", Password: testPassword}

// client returns a client of the server s in mode m, with the credentials of
// testCredentials and a fixed date. It knows the server by its name, as a
// client in production does, and connects to its address.
func client(s *smtptest.Server, m TLSMode) *Client {
	c := New(Options{
		Host: smtptest.Name, TLS: m, Username: testCredentials.Username, Password: testCredentials.Password,
		From: "nyktus@example.com", HeloName: "worker.example.com", RootCAs: s.RootCAs,
	})
	c.addr = s.Addr()
	c.now = func() time.Time { return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC) }
	return c
}

func testMessage() Message {
	return Message{
		To: []string{"soc@example.com", "oncall@example.org"}, Subject: "Nyktus: test message",
		ID: "8f1c6a3e-3b0e-4d4b-9a51-0d7e2f0c9b11", Body: "This channel receives the alerts of Nyktus.\n",
	}
}

func send(t *testing.T, c *Client, m Message) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	return c.Send(ctx, m)
}

func TestSend_DeliversOverEveryModeOfTLS(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		mode    TLSMode
		opts    smtptest.Options
		withTLS bool
	}{
		{TLSStartTLS, smtptest.Options{Auth: testCredentials}, true},
		{TLSImplicit, smtptest.Options{ImplicitTLS: true, Auth: testCredentials}, true},
		// Plain SMTP is for development, where the password goes to the
		// loopback interface only.
		{TLSNone, smtptest.Options{NoSTARTTLS: true, Auth: testCredentials}, false},
	} {
		t.Run(string(tt.mode), func(t *testing.T) {
			t.Parallel()
			s := smtptest.New(t, tt.opts)
			c := client(s, tt.mode)
			if tt.mode == TLSNone {
				c.opts.Host = s.Host
			}
			if err := send(t, c, testMessage()); err != nil {
				t.Fatalf("Send = %v", err)
			}
			got := s.Messages()
			if len(got) != 1 {
				t.Fatalf("messages = %d, want 1", len(got))
			}
			m := got[0]
			if m.From != "nyktus@example.com" || !slices.Equal(m.To, testMessage().To) || m.TLS != tt.withTLS ||
				m.Username != "nyktus" {
				t.Errorf("message = from %q to %v, TLS %v, user %q", m.From, m.To, m.TLS, m.Username)
			}
			if !strings.Contains(string(m.Data), "\r\n\r\nThis channel receives the alerts of Nyktus.\r\n") {
				t.Errorf("data = %q", m.Data)
			}
		})
	}
}

func TestSend_AuthenticatesWithLoginWhereThatIsAllTheServerOffers(t *testing.T) {
	t.Parallel()

	for _, mode := range []TLSMode{TLSStartTLS, TLSImplicit} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			s := smtptest.New(t, smtptest.Options{ImplicitTLS: mode == TLSImplicit, Auth: testCredentials, LoginOnly: true})
			if err := send(t, client(s, mode), testMessage()); err != nil {
				t.Fatalf("Send = %v", err)
			}
			if got := s.Messages(); len(got) != 1 || got[0].Username != "nyktus" || !got[0].TLS {
				t.Errorf("messages = %+v, want one over TLS from nyktus", got)
			}
		})
	}
	t.Run("wrong password", func(t *testing.T) {
		t.Parallel()
		s := smtptest.New(t, smtptest.Options{
			Auth: &smtptest.Credentials{Username: "nyktus", Password: "other"}, LoginOnly: true,
		})
		err := send(t, client(s, TLSStartTLS), testMessage())
		var re *ReplyError
		if !errors.As(err, &re) || re.Code != 535 || strings.Contains(err.Error(), testPassword) {
			t.Fatalf("Send = %v, want a refusal of AUTH with 535 without the password", err)
		}
	})
	t.Run("plain text", func(t *testing.T) {
		t.Parallel()
		s := smtptest.New(t, smtptest.Options{NoSTARTTLS: true, Auth: testCredentials, LoginOnly: true})
		if err := send(t, client(s, TLSNone), testMessage()); !errors.Is(err, errUnencrypted) {
			t.Fatalf("Send = %v, want errUnencrypted", err)
		}
		if slices.Contains(s.Commands(), "AUTH") {
			t.Errorf("commands = %v, want no AUTH in plain text to another host", s.Commands())
		}
	})
}

func TestSend_WithoutUsernameDoesNotAuthenticate(t *testing.T) {
	t.Parallel()

	s := smtptest.New(t, smtptest.Options{})
	c := client(s, TLSStartTLS)
	c.opts.Username, c.opts.Password = "", ""
	if err := send(t, c, testMessage()); err != nil {
		t.Fatalf("Send = %v", err)
	}
	if slices.Contains(s.Commands(), "AUTH") {
		t.Errorf("commands = %v, want no AUTH", s.Commands())
	}
}

func TestSend_PlainTextSendsThePasswordToTheLoopbackInterfaceOnly(t *testing.T) {
	t.Parallel()

	s := smtptest.New(t, smtptest.Options{NoSTARTTLS: true, Auth: testCredentials})
	if err := send(t, client(s, TLSNone), testMessage()); err == nil {
		t.Fatal("Send = nil, want an error")
	}
	if slices.Contains(s.Commands(), "AUTH") {
		t.Errorf("commands = %v, want no AUTH in plain text to another host", s.Commands())
	}
}

func TestSend_RefusesAServerWithoutSTARTTLS(t *testing.T) {
	t.Parallel()

	s := smtptest.New(t, smtptest.Options{NoSTARTTLS: true, Auth: testCredentials})
	err := send(t, client(s, TLSStartTLS), testMessage())
	if !errors.Is(err, ErrNoSTARTTLS) {
		t.Fatalf("Send = %v, want ErrNoSTARTTLS", err)
	}
	// Nothing is sent in plain text after the greeting, least of all the
	// password.
	if got := s.Commands(); !slices.Equal(got, []string{"EHLO"}) {
		t.Errorf("commands = %v, want only EHLO", got)
	}
}

func TestSend_VerifiesTheCertificate(t *testing.T) {
	t.Parallel()

	for _, mode := range []TLSMode{TLSStartTLS, TLSImplicit} {
		t.Run(string(mode)+"/unknown authority", func(t *testing.T) {
			t.Parallel()
			s := smtptest.New(t, smtptest.Options{ImplicitTLS: mode == TLSImplicit, Auth: testCredentials})
			c := client(s, mode)
			c.opts.RootCAs = smtptest.New(t, smtptest.Options{}).RootCAs
			assertCertificateRefused(t, s, send(t, c, testMessage()))
		})
		t.Run(string(mode)+"/other host", func(t *testing.T) {
			t.Parallel()
			s := smtptest.New(t, smtptest.Options{
				ImplicitTLS: mode == TLSImplicit, Auth: testCredentials, CertHosts: []string{"other.example.test"},
			})
			assertCertificateRefused(t, s, send(t, client(s, mode), testMessage()))
		})
	}
}

func assertCertificateRefused(t *testing.T, s *smtptest.Server, err error) {
	t.Helper()
	var verify *tls.CertificateVerificationError
	if !errors.As(err, &verify) {
		t.Fatalf("Send = %v, want an unverified certificate", err)
	}
	if slices.Contains(s.Commands(), "AUTH") || len(s.Messages()) > 0 {
		t.Errorf("commands = %v after an unverified certificate", s.Commands())
	}
}

func TestSend_RefusalsAreReplyErrors(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name      string
		verb      string
		reply     string
		command   string
		code      int
		temporary bool
	}{
		{"greeting", "GREETING", "554 5.3.2 not now", "greeting", 554, false},
		{"temporary sender", "MAIL", "451 4.3.0 try again later", "MAIL", 451, true},
		{"rejected message", "MESSAGE", "550 5.7.1 rejected", "message", 550, false},
		{"full mailbox", "MESSAGE", "452 4.2.2 over quota", "message", 452, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := smtptest.New(t, smtptest.Options{Auth: testCredentials, Respond: func(verb, _ string) string {
				if verb == tt.verb {
					return tt.reply
				}
				return ""
			}})
			err := send(t, client(s, TLSStartTLS), testMessage())
			var re *ReplyError
			if !errors.As(err, &re) || re.Command != tt.command || re.Code != tt.code || re.Temporary() != tt.temporary {
				t.Fatalf("Send = %v, want a refusal of %s with %d", err, tt.command, tt.code)
			}
			// The text of the server stays out of the error.
			if strings.Contains(err.Error(), tt.reply[4:]) {
				t.Errorf("error = %q, holds the text of the server", err)
			}
		})
	}
}

func TestSend_WrongPasswordNeverReachesTheError(t *testing.T) {
	t.Parallel()

	s := smtptest.New(t, smtptest.Options{Auth: &smtptest.Credentials{Username: "nyktus", Password: "other"}})
	err := send(t, client(s, TLSStartTLS), testMessage())
	var re *ReplyError
	if !errors.As(err, &re) || re.Command != "AUTH" || re.Code != 535 {
		t.Fatalf("Send = %v, want a refusal of AUTH with 535", err)
	}
	if strings.Contains(err.Error(), testPassword) {
		t.Errorf("error = %q, holds the password", err)
	}
	if slices.Contains(s.Commands(), "MAIL") {
		t.Errorf("commands = %v, want no MAIL after a failed authentication", s.Commands())
	}
}

func TestSend_ServerWithoutAuthIsRefusedWithAUsername(t *testing.T) {
	t.Parallel()

	s := smtptest.New(t, smtptest.Options{})
	if err := send(t, client(s, TLSStartTLS), testMessage()); !errors.Is(err, ErrNoAuth) {
		t.Fatalf("Send = %v, want ErrNoAuth", err)
	}
}

func TestSend_RefusedRecipientSendsNothing(t *testing.T) {
	t.Parallel()

	s := smtptest.New(t, smtptest.Options{Auth: testCredentials, Respond: func(verb, arg string) string {
		if verb == "RCPT" && strings.Contains(arg, "oncall@example.org") {
			return "550 5.1.1 no such user"
		}
		return ""
	}})
	err := send(t, client(s, TLSStartTLS), testMessage())
	var re *ReplyError
	if !errors.As(err, &re) || re.Command != "RCPT" || re.Code != 550 {
		t.Fatalf("Send = %v, want a refusal of RCPT with 550", err)
	}
	if slices.Contains(s.Commands(), "DATA") || len(s.Messages()) > 0 {
		t.Errorf("commands = %v, want no DATA once a recipient is refused", s.Commands())
	}
}

func TestSend_HangupIsANetworkError(t *testing.T) {
	t.Parallel()

	s := smtptest.New(t, smtptest.Options{Auth: testCredentials, Respond: func(verb, _ string) string {
		if verb == "MESSAGE" {
			return smtptest.Hangup
		}
		return ""
	}})
	err := send(t, client(s, TLSStartTLS), testMessage())
	var re *ReplyError
	if err == nil || errors.As(err, &re) {
		t.Fatalf("Send = %v, want an error of the connection", err)
	}
}

func TestSend_StalledServerEndsOnTheDeadline(t *testing.T) {
	t.Parallel()

	s := smtptest.New(t, smtptest.Options{Auth: testCredentials, Respond: func(verb, _ string) string {
		if verb == "MAIL" {
			return smtptest.Stall
		}
		return ""
	}})
	c := client(s, TLSStartTLS)
	// The deadline of the context ends the conversation, not its own bound.
	c.timeout = time.Hour
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Send(ctx, testMessage()) }()
	select {
	case err := <-done:
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("Send = %v, want a timeout", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Send did not end on the deadline of the context")
	}
}

func TestSend_CancelEndsTheConversation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	s := smtptest.New(t, smtptest.Options{Auth: testCredentials, Respond: func(verb, _ string) string {
		if verb == "MAIL" {
			cancel()
			return smtptest.Stall
		}
		return ""
	}})
	done := make(chan error, 1)
	go func() { done <- client(s, TLSStartTLS).Send(ctx, testMessage()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Send = nil after cancel")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Send did not end after cancel")
	}
}

func TestSend_RepliesAreBounded(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		reply string
	}{
		{"one long line", "250 " + strings.Repeat("x", maxReplyBytes)},
		{"many lines", strings.Repeat("250-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n", maxReplyBytes/32) + "250 HELP"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := smtptest.New(t, smtptest.Options{Auth: testCredentials, Respond: func(verb, _ string) string {
				if verb == "EHLO" {
					return tt.reply
				}
				return ""
			}})
			if err := send(t, client(s, TLSStartTLS), testMessage()); !errors.Is(err, ErrRepliesTooLarge) {
				t.Fatalf("Send = %v, want ErrRepliesTooLarge", err)
			}
		})
	}
}

func TestSend_InvalidMessageIsRefusedBeforeConnecting(t *testing.T) {
	t.Parallel()

	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	c := New(Options{
		Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, TLS: TLSStartTLS, From: "nyktus@example.com",
		HeloName: "worker.example.com",
	})
	m := testMessage()
	m.Subject = "Nyktus\r\nBcc: attacker@example.net"
	if err := send(t, c, m); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("Send = %v, want ErrInvalidMessage", err)
	}
	// A connection that the client opened waits in the backlog of the
	// listener already, so Accept would return it at once.
	if err := l.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if conn, err := l.Accept(); err == nil {
		_ = conn.Close()
		t.Error("the client connected before it checked the message")
	}
}

func TestSend_StalledServerEndsAfterTheTimeoutOfTheConversation(t *testing.T) {
	t.Parallel()

	s := smtptest.New(t, smtptest.Options{Auth: testCredentials, Respond: func(verb, _ string) string {
		if verb == "MAIL" {
			return smtptest.Stall
		}
		return ""
	}})
	c := client(s, TLSStartTLS)
	c.timeout = 200 * time.Millisecond
	// The context has no deadline: the conversation ends on its own bound.
	done := make(chan error, 1)
	go func() { done <- c.Send(context.WithoutCancel(t.Context()), testMessage()) }()
	select {
	case err := <-done:
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("Send = %v, want a timeout", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Send did not end after the timeout of the conversation")
	}
}

func TestOptions_LogValueOmitsThePassword(t *testing.T) {
	t.Parallel()

	o := Options{Host: "mail.example.com", Username: "nyktus", Password: testPassword, From: "nyktus@example.com"}
	if got := o.LogValue().String(); strings.Contains(got, testPassword) {
		t.Errorf("LogValue = %s, holds the password", got)
	}
}

func TestNew_RejectsIncompleteOptions(t *testing.T) {
	t.Parallel()

	valid := Options{Host: "mail.example.com", TLS: TLSStartTLS, From: "nyktus@example.com", HeloName: "worker.example.com"}
	for name, change := range map[string]func(*Options){
		"host":     func(o *Options) { o.Host = "" },
		"mode":     func(o *Options) { o.TLS = "ssl" },
		"sender":   func(o *Options) { o.From = "Nyktus <nyktus@example.com>" },
		"greeting": func(o *Options) { o.HeloName = "" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			o := valid
			change(&o)
			defer func() {
				if recover() == nil {
					t.Error("New did not panic")
				}
			}()
			New(o)
		})
	}
	if c := New(valid); c.addr != "mail.example.com:587" {
		t.Errorf("address = %s, want the default port of STARTTLS", c.addr)
	}
}

func TestTLSMode_DefaultPort(t *testing.T) {
	t.Parallel()

	for mode, want := range map[TLSMode]int{TLSStartTLS: 587, TLSImplicit: 465, TLSNone: 25} {
		if got := mode.DefaultPort(); got != want {
			t.Errorf("%s.DefaultPort() = %d, want %d", mode, got, want)
		}
	}
}
