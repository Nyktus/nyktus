// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package smtp emulates the sign-in of a mail server: it greets the client,
// offers TLS, asks for credentials with AUTH PLAIN or AUTH LOGIN once the
// connection is encrypted, and refuses them.
//
// It never accepts a message. A client that tries to send one without signing
// in is told that the server does not relay, and DATA is refused, so nothing
// of a message is ever read. The answers are those of Postfix on a submission
// port, which many real servers share; the texts that differ between
// installations, the name of the server and the rest of its greeting, come
// from the operator and have no default.
//
// What the client sent is read, counted and recorded in the session: the name
// it gives in EHLO and the credentials it signs in with. None of it is sent
// back.
package smtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"

	"nyktus.org/nyktus/sensor/internal/clock"
	"nyktus.org/nyktus/sensor/internal/guard"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/session"
	"nyktus.org/nyktus/sensor/internal/tlscert"
)

// Mode is how a client reaches TLS.
type Mode string

// Modes of TLS.
const (
	// StartTLS speaks plain text first and offers STARTTLS, as on ports 25 and
	// 587.
	StartTLS Mode = "starttls"
	// Implicit speaks TLS from the first byte, as on port 465.
	Implicit Mode = "implicit"
)

// Valid reports whether m is a known mode.
func (m Mode) Valid() bool { return m == StartTLS || m == Implicit }

// Config holds the settings of a honeypot.
type Config struct {
	// Hostname is the name of the server in its greeting and in its answer to
	// EHLO.
	Hostname string
	// Banner, if set, follows "ESMTP" in the greeting, such as the name of the
	// software.
	Banner string
	Mode   Mode
	// Certificate is what the server presents for TLS. It is required, because
	// a mail server without TLS looks like one that nobody uses, and it comes
	// from the operator: one that the sensor made would identify it.
	Certificate *tlscert.Certificate
}

// Limits of the dialog, within those of the connection.
const (
	// maxLine is the longest line that is read, as Postfix reads by default
	// (line_length_limit). The base64 of a login within the limits of the
	// report is shorter. A longer line is a syntax error and is dropped.
	maxLine = 2048
	// maxErrors is the number of refused commands after which the server ends
	// the connection, as Postfix does (smtpd_hard_error_limit).
	maxErrors = 20
)

// Answers that hold no value of the honeypot.
const (
	replyOK             = "250 2.0.0 Ok"
	replyMailOK         = "250 2.1.0 Ok"
	replyBye            = "221 2.0.0 Bye"
	replyReadyForTLS    = "220 2.0.0 Ready to start TLS"
	replyTLSActive      = "554 5.5.1 Error: TLS already active"
	replyNeedTLS        = "530 5.7.0 Must issue a STARTTLS command first"
	replyNeedHelo       = "503 5.5.1 Error: send HELO/EHLO first"
	replyNestedMail     = "503 5.5.1 Error: nested MAIL command"
	replyNeedMail       = "503 5.5.1 Error: need MAIL command"
	replyNeedRcpt       = "503 5.5.1 Error: need RCPT command"
	replyMailInProgress = "503 5.5.1 Error: MAIL transaction in progress"
	replyRelayDenied    = "554 5.7.1 Relay access denied"
	replyNoRecipients   = "554 5.5.1 Error: no valid recipients"
	replyBadSyntax      = "500 5.5.2 Error: bad syntax"
	replyUnknown        = "502 5.5.2 Error: command not recognized"
	replyVrfyDisabled   = "502 5.5.1 VRFY command is disabled"
	replyAuthSyntax     = "501 5.5.4 Syntax: AUTH mechanism"
	replyAuthAborted    = "501 5.7.0 Authentication aborted"
	replyCannotDecode   = "501 5.5.2 Cannot decode response"
	replyAuthFailed     = "535 5.7.8 Error: authentication failed: authentication failure"
	replyUnknownMech    = "535 5.7.8 Error: authentication failed: Invalid authentication mechanism"
	promptPlain         = "334 "
	// The prompts of AUTH LOGIN, "Username:" and "Password:" in base64.
	promptFirst          = "334 VXNlcm5hbWU6"
	promptSecond         = "334 UGFzc3dvcmQ6"
	syntaxEhlo           = "501 Syntax: EHLO hostname"
	syntaxHelo           = "501 Syntax: HELO hostname"
	syntaxMail           = "501 5.5.4 Syntax: MAIL FROM:<address>"
	syntaxRcpt           = "501 5.5.4 Syntax: RCPT TO:<address>"
	syntaxData           = "501 5.5.4 Syntax: DATA"
	syntaxStartTLS       = "501 5.5.4 Syntax: STARTTLS"
	messageSizeLimitText = "10240000"
)

// Service is the SMTP honeypot.
type Service struct {
	clock    clock.Clock
	tls      *tls.Config
	mode     Mode
	hostname string
	greeting string
	// ehloPlain and ehloTLS answer EHLO before and after TLS: STARTTLS is
	// offered before, AUTH only after, as on a server that signs in over TLS
	// only.
	ehloPlain string
	ehloTLS   string
	tooMany   string
}

// New returns an SMTP honeypot. It panics if clk is nil or the configuration
// is incomplete, which the configuration of the sensor has refused before.
func New(cfg Config, clk clock.Clock) *Service {
	switch {
	case clk == nil:
		panic("smtp: missing clock")
	case cfg.Certificate == nil:
		panic("smtp: missing certificate")
	case cfg.Hostname == "":
		panic("smtp: missing hostname")
	case !cfg.Mode.Valid():
		panic("smtp: unknown mode of TLS")
	}
	greeting := "220 " + cfg.Hostname + " ESMTP"
	if cfg.Banner != "" {
		greeting += " " + cfg.Banner
	}
	ehlo := func(tlsLine string) string {
		return strings.Join([]string{
			"250-" + cfg.Hostname,
			"250-SIZE " + messageSizeLimitText,
			"250-" + tlsLine,
			"250-ENHANCEDSTATUSCODES",
			"250-8BITMIME",
			"250 DSN",
		}, "\r\n")
	}
	return &Service{
		clock:     clk,
		tls:       cfg.Certificate.ServerConfig(),
		mode:      cfg.Mode,
		hostname:  cfg.Hostname,
		greeting:  greeting,
		ehloPlain: ehlo("STARTTLS"),
		ehloTLS:   ehlo("AUTH PLAIN LOGIN"),
		tooMany:   "421 4.7.0 " + cfg.Hostname + " Error: too many errors",
	}
}

var (
	errTooLong = errors.New("smtp: line too long")
	errStop    = errors.New("smtp: end of the dialog")
)

// dialog is the state of one connection.
type dialog struct {
	svc  *Service
	sess *session.Session
	// conn is the connection within the limits of the guard. TLS is laid on it,
	// never on the buffer, so that what a client sent in clear text before TLS
	// is never taken for part of the encrypted dialog.
	conn      net.Conn
	w         io.Writer
	r         *bufio.Reader
	tls       *tls.Conn
	encrypted bool
	helo      bool
	mail      bool
	errors    int
}

// Serve plays the dialog on conn and records it in sess. It returns when the
// client quits or has gone, was silent for too long, sent too much or made too
// many errors, and leaves closing the connection to its caller.
func (s *Service) Serve(ctx context.Context, conn net.Conn, sess *session.Session) {
	if ctx.Err() != nil {
		return
	}
	d := s.newDialog(guard.New(conn, s.clock), sess)
	if s.mode == Implicit && !d.startTLS(ctx) {
		return
	}
	d.run(ctx)
	// A mail server ends TLS with its alert before it closes the connection;
	// a client that does not receive it reports a truncated connection, which
	// would set the honeypot apart.
	if d.tls != nil {
		_ = d.tls.CloseWrite()
	}
}

func (s *Service) newDialog(conn net.Conn, sess *session.Session) *dialog {
	return &dialog{svc: s, sess: sess, conn: conn, w: conn, r: bufio.NewReaderSize(conn, maxLine)}
}

// run greets the client and answers its commands until the dialog ends.
func (d *dialog) run(ctx context.Context) {
	if d.reply(d.svc.greeting) != nil {
		return
	}
	for {
		line, err := d.readLine()
		if errors.Is(err, errTooLong) {
			if d.fail(replyBadSyntax) != nil {
				return
			}
			continue
		}
		if err != nil {
			return
		}
		if d.command(ctx, line) != nil {
			return
		}
	}
}

// command answers one line of the client. It returns an error when the dialog
// ends.
func (d *dialog) command(ctx context.Context, line string) error {
	verb, arg, _ := strings.Cut(line, " ")
	arg = strings.TrimLeft(arg, " ")
	switch strings.ToUpper(verb) {
	case "EHLO", "HELO":
		return d.hello(strings.ToUpper(verb) == "EHLO", arg)
	case "STARTTLS":
		switch {
		case d.encrypted:
			return d.fail(replyTLSActive)
		case arg != "":
			return d.fail(syntaxStartTLS)
		}
		if err := d.reply(replyReadyForTLS); err != nil {
			return err
		}
		if !d.startTLS(ctx) {
			return errStop
		}
		return nil
	case "AUTH":
		return d.auth(arg)
	case "MAIL":
		if err := d.transaction(); err != nil || d.mail {
			return d.orFail(err, replyNestedMail)
		}
		if !hasPrefixFold(arg, "FROM:") {
			return d.fail(syntaxMail)
		}
		d.mail = true
		return d.reply(replyMailOK)
	case "RCPT":
		if err := d.transaction(); err != nil || !d.mail {
			return d.orFail(err, replyNeedMail)
		}
		if !hasPrefixFold(arg, "TO:") {
			return d.fail(syntaxRcpt)
		}
		// The address is not named: nothing the client sent is sent back.
		return d.fail(replyRelayDenied)
	case "DATA":
		if err := d.transaction(); err != nil || !d.mail {
			return d.orFail(err, replyNeedRcpt)
		}
		if arg != "" {
			return d.fail(syntaxData)
		}
		// No recipient was ever accepted, so no message is read.
		return d.fail(replyNoRecipients)
	case "RSET":
		d.mail = false
		return d.reply(replyOK)
	case "NOOP":
		return d.reply(replyOK)
	case "QUIT":
		_ = d.reply(replyBye)
		return errStop
	case "VRFY":
		return d.fail(replyVrfyDisabled)
	case "":
		return d.fail(replyBadSyntax)
	default:
		return d.fail(replyUnknown)
	}
}

// hello answers EHLO and HELO, records the name that the client gives, and
// starts a new transaction.
func (d *dialog) hello(extended bool, name string) error {
	if name == "" {
		if extended {
			return d.fail(syntaxEhlo)
		}
		return d.fail(syntaxHelo)
	}
	d.sess.SetClientVersion(report.Clean(name, report.MaxClientVersion))
	d.helo, d.mail = true, false
	switch {
	case !extended:
		return d.reply("250 " + d.svc.hostname)
	case d.encrypted:
		return d.reply(d.svc.ehloTLS)
	default:
		return d.reply(d.svc.ehloPlain)
	}
}

// transaction returns the answer to a command of a mail transaction that comes
// too early: before TLS, which a server that signs in over TLS only requires
// first, or before HELO.
func (d *dialog) transaction() error {
	switch {
	case !d.encrypted:
		return errNeedTLS
	case !d.helo:
		return errNeedHelo
	}
	return nil
}

var (
	errNeedTLS  = errors.New(replyNeedTLS)
	errNeedHelo = errors.New(replyNeedHelo)
)

// orFail refuses a command with the answer of err if it is set, and with
// otherwise if not.
func (d *dialog) orFail(err error, otherwise string) error {
	if err != nil {
		return d.fail(err.Error())
	}
	return d.fail(otherwise)
}

// auth asks for the credentials of AUTH PLAIN or AUTH LOGIN and refuses them.
// A login is recorded once its user name is known, so a password that does not
// arrive leaves a login without one.
func (d *dialog) auth(arg string) error {
	if err := d.transaction(); err != nil {
		return d.fail(err.Error())
	}
	if d.mail {
		return d.fail(replyMailInProgress)
	}
	mechanism, initial, _ := strings.Cut(arg, " ")
	// A space without a response after it is no initial response, and the
	// server asks for one.
	initial = strings.TrimLeft(initial, " ")
	hasInitial := initial != ""
	if mechanism == "" {
		return d.fail(replyAuthSyntax)
	}
	// A session keeps a fixed number of logins; a client that wants more is
	// sent away, as a server that counts its errors does.
	if d.sess.Attempts() >= session.MaxAttempts {
		_ = d.reply(d.svc.tooMany)
		return errStop
	}
	switch strings.ToUpper(mechanism) {
	case "PLAIN":
		return d.authPlain(initial, hasInitial)
	case "LOGIN":
		return d.authLogin(initial, hasInitial)
	default:
		return d.fail(replyUnknownMech)
	}
}

// authPlain reads the one response of AUTH PLAIN: an identity to act as, the
// user name and the password, separated by zero bytes (RFC 4616).
func (d *dialog) authPlain(initial string, hasInitial bool) error {
	resp, err := d.response(promptPlain, initial, hasInitial)
	if err != nil {
		return d.authError(err)
	}
	parts := bytes.Split(resp, []byte{0})
	if len(parts) != 3 {
		return d.fail(replyAuthFailed)
	}
	password := report.Clean(string(parts[2]), report.MaxPassword)
	d.sess.AddAttempt(report.Attempt{Username: report.Clean(string(parts[1]), report.MaxUsername), Password: &password})
	return d.fail(replyAuthFailed)
}

// authLogin asks for the user name and the password one after the other, each
// in base64. The user name may come with the command.
func (d *dialog) authLogin(initial string, hasInitial bool) error {
	user, err := d.response(promptFirst, initial, hasInitial)
	if err != nil {
		return d.authError(err)
	}
	attempt := report.Attempt{Username: report.Clean(string(user), report.MaxUsername)}
	defer func() { d.sess.AddAttempt(attempt) }()
	pass, err := d.response(promptSecond, "", false)
	if err != nil {
		return d.authError(err)
	}
	password := report.Clean(string(pass), report.MaxPassword)
	attempt.Password = &password
	return d.fail(replyAuthFailed)
}

var (
	errAborted   = errors.New(replyAuthAborted)
	errBadBase64 = errors.New(replyCannotDecode)
)

// response returns a response of the client to a prompt, decoded from base64:
// the one that came with the command, or the next line after the prompt. "="
// stands for an empty response that came with the command (RFC 4954), and "*"
// cancels the exchange.
func (d *dialog) response(prompt, initial string, hasInitial bool) ([]byte, error) {
	line := initial
	if !hasInitial {
		if err := d.reply(prompt); err != nil {
			return nil, err
		}
		var err error
		if line, err = d.readLine(); err != nil {
			return nil, err
		}
	} else if line == "=" {
		return nil, nil
	}
	if line == "*" {
		return nil, errAborted
	}
	b, err := base64.StdEncoding.Strict().DecodeString(line)
	if err != nil {
		return nil, errBadBase64
	}
	return b, nil
}

// authError ends an exchange that failed: an answer for a cancel or a response
// that is no base64, the dialog for a connection that failed. A line that was
// too long has been dropped and is a syntax error.
func (d *dialog) authError(err error) error {
	switch {
	case errors.Is(err, errAborted), errors.Is(err, errBadBase64):
		return d.fail(err.Error())
	case errors.Is(err, errTooLong):
		return d.fail(replyBadSyntax)
	default:
		return err
	}
}

// startTLS lays TLS on the connection and drops what the client sent before in
// clear text with the buffer. The dialog starts again: the client greets once
// more, as RFC 3207 requires.
func (d *dialog) startTLS(ctx context.Context) bool {
	tc := tls.Server(d.conn, d.svc.tls)
	if tc.HandshakeContext(ctx) != nil {
		return false
	}
	d.tls, d.w, d.r = tc, tc, bufio.NewReaderSize(tc, maxLine)
	d.encrypted, d.helo, d.mail = true, false, false
	return true
}

// readLine reads a line without its end, which is CRLF or a bare LF. A line
// longer than maxLine is read to its end and dropped.
func (d *dialog) readLine() (string, error) {
	b, err := d.r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = d.r.ReadSlice('\n')
		}
		if err != nil {
			return "", err
		}
		return "", errTooLong
	}
	if err != nil {
		return "", err
	}
	b = bytes.TrimSuffix(bytes.TrimSuffix(b, []byte("\n")), []byte("\r"))
	return string(b), nil
}

// reply sends an answer of one or more lines.
func (d *dialog) reply(text string) error {
	_, err := io.WriteString(d.w, text+"\r\n")
	return err
}

// fail sends a refusal and counts it. The refusal that reaches the limit is
// followed by the end of the connection.
func (d *dialog) fail(text string) error {
	if err := d.reply(text); err != nil {
		return err
	}
	d.errors++
	if d.errors >= maxErrors {
		_ = d.reply(d.svc.tooMany)
		return errStop
	}
	return nil
}

// hasPrefixFold reports whether s starts with prefix, compared without case.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
