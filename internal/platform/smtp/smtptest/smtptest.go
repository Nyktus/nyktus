// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package smtptest provides an SMTP server for tests. It speaks enough of the
// protocol for the client of Nyktus: EHLO, STARTTLS, TLS from the start, AUTH
// PLAIN, MAIL, RCPT and DATA. Tests choose the replies, let the server hang up
// or stall, and read the messages it received.
package smtptest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/netip"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Special replies of Respond.
const (
	// Hangup closes the connection instead of replying.
	Hangup = "\x00hangup"
	// Stall never replies; the connection stays open until the test ends.
	Stall = "\x00stall"
)

// Credentials are a username and password that the server accepts.
type Credentials struct {
	Username, Password string
}

// Options configures a Server.
type Options struct {
	// ImplicitTLS speaks TLS from the start.
	ImplicitTLS bool
	// NoSTARTTLS leaves STARTTLS out of the extensions.
	NoSTARTTLS bool
	// Auth offers AUTH PLAIN and accepts these credentials only.
	Auth *Credentials
	// LoginOnly offers AUTH LOGIN instead of PLAIN.
	LoginOnly bool
	// CertHosts are the names and addresses that the certificate of the
	// server holds. The default is Name.
	CertHosts []string
	// Respond chooses the reply to a command, named by its verb in upper case,
	// with its argument. "GREETING" stands for the greeting and "MESSAGE" for
	// the end of the data. It returns the reply, lines separated by "\n",
	// Hangup, Stall or "" for the default reply.
	Respond func(verb, arg string) string
}

// Message is a message that the server received.
type Message struct {
	From string
	To   []string
	// Data is the message as sent, with CRLF line ends and leading dots
	// unescaped.
	Data []byte
	// TLS reports whether the message came over TLS.
	TLS bool
	// Username is the user who authenticated, or "".
	Username string
}

// Name is the name of every server, which clients pass as the host of the
// server while they connect to Addr. A client that knows the server by an
// address of the loopback interface behaves differently: net/smtp sends the
// password there without TLS.
const Name = "smtp.example.test"

// Server is an SMTP server on the loopback interface.
type Server struct {
	// Host and Port are where the server listens.
	Host string
	Port int
	// RootCAs holds the authority that issued the certificate of the server.
	RootCAs *x509.CertPool

	opts     Options
	tls      *tls.Config
	listener net.Listener
	// ctx ends when the test ends, and with it every stalled reply.
	ctx  context.Context
	stop context.CancelFunc
	wg   sync.WaitGroup

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	messages []Message
	commands []string
}

// New starts a Server that stops when the test ends.
func New(tb testing.TB, o Options) *Server {
	tb.Helper()
	if len(o.CertHosts) == 0 {
		o.CertHosts = []string{Name}
	}
	roots, cert := certificate(tb, o.CertHosts)
	ctx, cancel := context.WithCancel(context.Background())
	l, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		tb.Fatalf("smtptest: listen: %v", err)
	}
	s := &Server{
		Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, RootCAs: roots, opts: o,
		tls: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, listener: l,
		ctx: ctx, stop: cancel, conns: map[net.Conn]struct{}{},
	}
	s.wg.Go(s.serve)
	tb.Cleanup(s.close)
	return s
}

// Messages returns the messages that the server received.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.messages...)
}

// Commands returns the verbs of every command that the server received, in
// order, such as "EHLO" and "AUTH".
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

func (s *Server) close() {
	s.stop()
	_ = s.listener.Close()
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) serve() {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		if s.opts.ImplicitTLS {
			c = tls.Server(c, s.tls)
		}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Go(func() {
			defer func() {
				s.mu.Lock()
				delete(s.conns, c)
				s.mu.Unlock()
				_ = c.Close()
			}()
			s.handle(c)
		})
	}
}

// session is the state of a conversation.
type session struct {
	conn     net.Conn
	text     *textproto.Conn
	tls      bool
	username string
	from     string
	to       []string
}

func (s *Server) handle(c net.Conn) {
	ss := &session{conn: c, text: textproto.NewConn(c), tls: s.opts.ImplicitTLS}
	if !s.reply(ss, "GREETING", "", "220 smtptest ESMTP") {
		return
	}
	for {
		line, err := ss.text.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(verb)
		s.mu.Lock()
		s.commands = append(s.commands, verb)
		s.mu.Unlock()
		if !s.command(ss, verb, arg) {
			return
		}
	}
}

// command answers one command and reports whether the conversation goes on.
func (s *Server) command(ss *session, verb, arg string) bool {
	switch verb {
	case "EHLO", "HELO":
		ext := []string{"250-smtptest"}
		if !ss.tls && !s.opts.NoSTARTTLS {
			ext = append(ext, "250-STARTTLS")
		}
		switch {
		case s.opts.Auth != nil && s.opts.LoginOnly:
			ext = append(ext, "250-AUTH LOGIN")
		case s.opts.Auth != nil:
			ext = append(ext, "250-AUTH PLAIN")
		}
		return s.reply(ss, verb, arg, strings.Join(append(ext, "250 HELP"), "\n"))
	case "STARTTLS":
		if ss.tls || s.opts.NoSTARTTLS {
			return s.reply(ss, verb, arg, "503 5.5.1 TLS already active or not offered")
		}
		if !s.reply(ss, verb, arg, "220 2.0.0 ready") {
			return false
		}
		tc := tls.Server(ss.conn, s.tls)
		if err := tc.HandshakeContext(s.ctx); err != nil {
			return false
		}
		s.mu.Lock()
		delete(s.conns, ss.conn)
		s.conns[tc] = struct{}{}
		s.mu.Unlock()
		*ss = session{conn: tc, text: textproto.NewConn(tc), tls: true}
		return true
	case "AUTH":
		return s.reply(ss, verb, arg, s.auth(ss, arg))
	case "MAIL":
		ss.from, ss.to = address(arg), nil
		return s.reply(ss, verb, arg, "250 2.1.0 ok")
	case "RCPT":
		if def := s.respond(verb, arg); def != "" {
			return s.write(ss, def)
		}
		ss.to = append(ss.to, address(arg))
		return s.write(ss, "250 2.1.5 ok")
	case "DATA":
		if !s.reply(ss, verb, arg, "354 go ahead") {
			return false
		}
		data, err := ss.text.ReadDotBytes()
		if err != nil {
			return false
		}
		if r := s.respond("MESSAGE", ""); r != "" {
			return s.write(ss, r)
		}
		s.mu.Lock()
		s.messages = append(s.messages, Message{
			From: ss.from, To: ss.to, Data: crlf(data), TLS: ss.tls, Username: ss.username,
		})
		s.mu.Unlock()
		return s.write(ss, "250 2.0.0 accepted")
	case "RSET":
		ss.from, ss.to = "", nil
		return s.reply(ss, verb, arg, "250 2.0.0 ok")
	case "NOOP":
		return s.reply(ss, verb, arg, "250 2.0.0 ok")
	case "QUIT":
		_ = s.reply(ss, verb, arg, "221 2.0.0 bye")
		return false
	default:
		return s.reply(ss, verb, arg, "502 5.5.2 not implemented")
	}
}

func (s *Server) auth(ss *session, arg string) string {
	mech, initial, _ := strings.Cut(arg, " ")
	switch {
	case s.opts.Auth != nil && s.opts.LoginOnly && strings.EqualFold(mech, "LOGIN"):
		return s.login(ss)
	case s.opts.Auth == nil || s.opts.LoginOnly || !strings.EqualFold(mech, "PLAIN"):
		return "504 5.5.4 mechanism not supported"
	}
	raw, err := base64.StdEncoding.DecodeString(initial)
	if err != nil {
		return "501 5.5.2 cannot decode"
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 3 || parts[1] != s.opts.Auth.Username || parts[2] != s.opts.Auth.Password {
		return "535 5.7.8 authentication failed"
	}
	ss.username = parts[1]
	return "235 2.7.0 authenticated"
}

// login asks for the username and the password of AUTH LOGIN.
func (s *Server) login(ss *session) string {
	var answers []string
	for _, challenge := range []string{"Username:", "Password:"} {
		if err := ss.text.PrintfLine("334 %s", base64.StdEncoding.EncodeToString([]byte(challenge))); err != nil {
			return Hangup
		}
		line, err := ss.text.ReadLine()
		if err != nil {
			return Hangup
		}
		answer, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return "501 5.5.2 cannot decode"
		}
		answers = append(answers, string(answer))
	}
	if answers[0] != s.opts.Auth.Username || answers[1] != s.opts.Auth.Password {
		return "535 5.7.8 authentication failed"
	}
	ss.username = answers[0]
	return "235 2.7.0 authenticated"
}

// reply writes the reply that Respond chooses for verb, or def.
func (s *Server) reply(ss *session, verb, arg, def string) bool {
	if r := s.respond(verb, arg); r != "" {
		def = r
	}
	return s.write(ss, def)
}

func (s *Server) respond(verb, arg string) string {
	if s.opts.Respond == nil {
		return ""
	}
	return s.opts.Respond(verb, arg)
}

// write writes the reply r and reports whether the conversation goes on.
func (s *Server) write(ss *session, r string) bool {
	switch r {
	case Hangup:
		return false
	case Stall:
		<-s.ctx.Done()
		return false
	}
	for line := range strings.SplitSeq(r, "\n") {
		if err := ss.text.PrintfLine("%s", line); err != nil {
			return false
		}
	}
	return true
}

// address returns the address in angle brackets of a MAIL or RCPT argument.
func address(arg string) string {
	_, rest, _ := strings.Cut(arg, "<")
	addr, _, _ := strings.Cut(rest, ">")
	return addr
}

// crlf restores the CRLF line ends that textproto turns into "\n".
func crlf(b []byte) []byte {
	return []byte(strings.ReplaceAll(string(b), "\n", "\r\n"))
}

// certificate returns a new authority and a certificate for hosts that it
// issued. Both live only as long as the test, so that no key is committed.
func certificate(tb testing.TB, hosts []string) (*x509.CertPool, tls.Certificate) {
	tb.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("smtptest: generate key: %v", err)
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "smtptest CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		tb.Fatalf("smtptest: create authority: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		tb.Fatalf("smtptest: parse authority: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("smtptest: generate key: %v", err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: hosts[0]},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip, err := netip.ParseAddr(h); err == nil {
			leaf.IPAddresses = append(leaf.IPAddresses, ip.AsSlice())
		} else {
			leaf.DNSNames = append(leaf.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		tb.Fatalf("smtptest: create certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Addr returns host and port of s, for messages of tests.
func (s *Server) Addr() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }
