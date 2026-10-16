// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package smtp sends mail through the SMTP server of the operator.
//
// The server is configured by the operator, never by a user of the console,
// and is often reachable only internally. Like the client of the identity
// provider, this client therefore does not go through the SSRF guard. It
// verifies the certificate of the server, never continues without TLS unless
// the operator chose plain SMTP for development, ignores proxies from the
// environment, and bounds the time of a conversation and the size of the
// replies of the server.
package smtp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	netsmtp "net/smtp"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"time"
)

// TLSMode says how the connection to the server is encrypted.
type TLSMode string

// Modes of encryption.
const (
	// TLSStartTLS connects in plain text and switches to TLS with STARTTLS
	// before anything else is sent. A server that does not offer STARTTLS is
	// refused, so that nobody on the way can strip it.
	TLSStartTLS TLSMode = "starttls"
	// TLSImplicit speaks TLS from the start, as on port 465.
	TLSImplicit TLSMode = "tls"
	// TLSNone sends in plain text. It is for development only.
	TLSNone TLSMode = "none"
)

// TLSModes lists every mode, in the order of the documentation.
var TLSModes = []TLSMode{TLSStartTLS, TLSImplicit, TLSNone}

// DefaultPort returns the usual port of the mode m.
func (m TLSMode) DefaultPort() int {
	switch m {
	case TLSImplicit:
		return 465
	case TLSNone:
		return 25
	default:
		return 587
	}
}

// Limits of a conversation.
const (
	// dialTimeout bounds connecting, including the handshake of implicit TLS.
	dialTimeout = 10 * time.Second
	// conversationTimeout bounds a conversation from the connection to the
	// end of the message, unless the context of the call ends it earlier.
	conversationTimeout = 30 * time.Second
	// maxReplyBytes bounds what the server can send in a conversation, also
	// within a single reply, which net/textproto reads without a limit.
	maxReplyBytes = 64 << 10
)

// Errors of the client. Errors of the network and of TLS, such as an
// unverified certificate, are returned as they are.
var (
	// ErrNoSTARTTLS means that the server does not offer STARTTLS.
	ErrNoSTARTTLS = errors.New("smtp: server does not offer STARTTLS")
	// ErrNoAuth means that a username is configured, but the server offers
	// no authentication.
	ErrNoAuth = errors.New("smtp: server does not offer authentication")
	// ErrRepliesTooLarge means that the server sent more than the limit.
	ErrRepliesTooLarge = errors.New("smtp: replies of the server exceed the limit")
)

// ReplyError is a reply of the server that refuses a command. It holds the
// code, never the text, which the server chooses.
type ReplyError struct {
	// Command names the command that was refused, such as "RCPT".
	Command string
	Code    int
}

func (e *ReplyError) Error() string {
	return fmt.Sprintf("smtp: server refused %s with %d", e.Command, e.Code)
}

// Temporary reports whether the server asks to try again later (4xx).
func (e *ReplyError) Temporary() bool { return e.Code >= 400 && e.Code < 500 }

// Options configures a Client.
type Options struct {
	Host string
	// Port is the port of the server; 0 chooses the default of the mode.
	Port int
	TLS  TLSMode
	// Username and Password authenticate with AUTH PLAIN or, where the server
	// offers only that, AUTH LOGIN. An empty username sends mail without
	// authentication, as to a relay that admits the address of the worker.
	Username string
	Password string
	// From is the address that mail is sent from.
	From string
	// HeloName is the name with which the client greets the server.
	HeloName string
	// RootCAs verifies the certificate of the server. Nil uses the roots of
	// the system, which SSL_CERT_FILE and SSL_CERT_DIR extend.
	RootCAs *x509.CertPool
}

// LogValue keeps the password out of logs.
func (o Options) LogValue() slog.Value {
	return slog.GroupValue(slog.String("host", o.Host), slog.Int("port", o.Port), slog.String("tls", string(o.TLS)),
		slog.String("username", o.Username), slog.String("from", o.From))
}

// Client sends mail through one server. It is safe for concurrent use; every
// message is sent in a conversation of its own.
type Client struct {
	opts Options
	addr string
	// now returns the date of a message, and timeout bounds a conversation.
	// Tests replace them.
	now     func() time.Time
	timeout time.Duration
}

// New returns a Client for o. It panics on a missing host, sender or name to
// greet with, or an unknown mode, which the configuration rules out.
func New(o Options) *Client {
	if o.Host == "" || o.HeloName == "" || ValidateAddress(o.From) != nil || !validMode(o.TLS) {
		panic("smtp: client needs a host, a sender, a name to greet with and a mode of encryption")
	}
	if o.Port == 0 {
		o.Port = o.TLS.DefaultPort()
	}
	return &Client{
		opts: o, addr: net.JoinHostPort(o.Host, strconv.Itoa(o.Port)), now: time.Now, timeout: conversationTimeout,
	}
}

func validMode(m TLSMode) bool {
	for _, known := range TLSModes {
		if m == known {
			return true
		}
	}
	return false
}

// Send sends m in a conversation of its own. It checks m before it connects,
// and sends nothing unless the server accepts every recipient: a message never
// reaches only some of them.
func (c *Client) Send(ctx context.Context, m Message) error {
	data, err := m.build(c.opts.From, c.now())
	if err != nil {
		return err
	}
	conn, limited, stop, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer stop()

	client, err := netsmtp.NewClient(conn, c.opts.Host)
	if err != nil {
		_ = conn.Close()
		return reply("greeting", limited.err(err))
	}
	defer func() { _ = client.Close() }()
	if err := c.converse(client, m.To, data); err != nil {
		return limited.err(err)
	}
	// The message was accepted; a failed goodbye changes nothing.
	_ = client.Quit()
	return nil
}

// dial connects to the server, with TLS from the start in the implicit mode,
// and bounds the conversation in time and the replies in size. The dialer
// reads no proxy from the environment. The returned function releases the
// context.
//
// TLS wraps the limited connection, not the other way round: net/smtp knows
// that a connection is encrypted only if it is a *tls.Conn, and sends the
// password only then.
func (c *Client) dial(ctx context.Context) (net.Conn, *limitedConn, func() bool, error) {
	raw, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("smtp: connect: %w", err)
	}
	if err := raw.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		_ = raw.Close()
		return nil, nil, nil, fmt.Errorf("smtp: set deadline: %w", err)
	}
	// net/smtp takes no context; a context that ends, canceled or on its
	// deadline, ends the conversation through the deadline of the connection.
	stop := context.AfterFunc(ctx, func() { _ = raw.SetDeadline(time.Unix(1, 0)) })
	limited := &limitedConn{Conn: raw, remaining: maxReplyBytes}
	if c.opts.TLS != TLSImplicit {
		return limited, limited, stop, nil
	}
	conn := tls.Client(limited, c.tlsConfig())
	if err := conn.HandshakeContext(ctx); err != nil {
		stop()
		_ = raw.Close()
		return nil, nil, nil, fmt.Errorf("smtp: connect: %w", limited.err(err))
	}
	return conn, limited, stop, nil
}

func (c *Client) tlsConfig() *tls.Config {
	return &tls.Config{ServerName: c.opts.Host, MinVersion: tls.VersionTLS12, RootCAs: c.opts.RootCAs}
}

// converse greets the server, secures the connection, authenticates and sends
// data to the recipients to.
func (c *Client) converse(client *netsmtp.Client, to []string, data []byte) error {
	if err := client.Hello(c.opts.HeloName); err != nil {
		return reply("EHLO", err)
	}
	if c.opts.TLS == TLSStartTLS {
		// Without STARTTLS, the connection stays in plain text; nothing is
		// sent then, least of all the password.
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return ErrNoSTARTTLS
		}
		if err := client.StartTLS(c.tlsConfig()); err != nil {
			return reply("STARTTLS", err)
		}
	}
	if c.opts.Username != "" {
		auth, err := c.auth(client)
		if err != nil {
			return err
		}
		if err := client.Auth(auth); err != nil {
			return reply("AUTH", err)
		}
	}
	if err := client.Mail(c.opts.From); err != nil {
		return reply("MAIL", err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return reply("RCPT", err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return reply("DATA", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("smtp: write message: %w", err)
	}
	if err := w.Close(); err != nil {
		return reply("message", err)
	}
	return nil
}

// auth chooses PLAIN, or LOGIN if the server offers only that, as Microsoft
// Exchange does. Both send the password only over TLS, or to the loopback
// interface in development.
func (c *Client) auth(client *netsmtp.Client) (netsmtp.Auth, error) {
	ok, mechanisms := client.Extension("AUTH")
	if !ok {
		return nil, ErrNoAuth
	}
	offered := strings.Fields(strings.ToUpper(mechanisms))
	switch {
	case slices.Contains(offered, "PLAIN"):
		return netsmtp.PlainAuth("", c.opts.Username, c.opts.Password, c.opts.Host), nil
	case slices.Contains(offered, "LOGIN"):
		return &loginAuth{username: c.opts.Username, password: c.opts.Password}, nil
	default:
		return nil, ErrNoAuth
	}
}

// errUnencrypted means that a password would be sent without TLS.
var errUnencrypted = errors.New("smtp: refusing to send the password without TLS")

// loginAuth implements the mechanism LOGIN, which asks for the username and
// then the password. Like PlainAuth, it sends them only over TLS, with a
// verified certificate, or to the loopback interface.
type loginAuth struct {
	username, password string
	step               int
}

func (a *loginAuth) Start(server *netsmtp.ServerInfo) (string, []byte, error) {
	if !server.TLS && !loopback(server.Name) {
		return "", nil, errUnencrypted
	}
	return "LOGIN", nil, nil
}

// Next answers the challenges in order: the first with the username, the
// second with the password. Servers word the challenges differently.
func (a *loginAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.step++
	switch a.step {
	case 1:
		return []byte(a.username), nil
	case 2:
		return []byte(a.password), nil
	default:
		return nil, errors.New("smtp: unexpected challenge of LOGIN")
	}
}

// loopback reports whether host names the loopback interface, as net/smtp
// decides for PlainAuth.
func loopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// reply turns a refusal of the server into a *ReplyError, without the text of
// the server, and wraps other errors with the command.
func reply(command string, err error) error {
	var te *textproto.Error
	if errors.As(err, &te) {
		return &ReplyError{Command: command, Code: te.Code}
	}
	return fmt.Errorf("smtp: %s: %w", command, err)
}

// limitedConn ends a conversation once the server has sent maxReplyBytes.
type limitedConn struct {
	net.Conn
	remaining int
	exceeded  bool
}

func (c *limitedConn) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		c.exceeded = true
		return 0, ErrRepliesTooLarge
	}
	if len(p) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= n
	return n, err
}

// err returns ErrRepliesTooLarge if the limit ended the conversation, because
// net/smtp may report it as a malformed reply instead.
func (c *limitedConn) err(err error) error {
	if c.exceeded && !errors.Is(err, ErrRepliesTooLarge) {
		return fmt.Errorf("%w: %w", ErrRepliesTooLarge, err)
	}
	return err
}
