// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package alerting manages the channels that alerts are delivered to.
//
// A channel is a URL that receives a POST with the alert, formatted for its
// type. The URL is a secret: a chat webhook accepts messages from whoever
// knows it. A webhook may send one header in addition, whose value is a secret
// as well. Secrets are encrypted at rest, bound to their channel and purpose,
// and never logged; the console writes them but cannot read them back.
package alerting

import (
	"errors"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ResourceType names channels in the audit log.
const ResourceType = "alert_channel"

// Type is the type of a channel. It chooses the format of the request body.
type Type string

// Types of channels.
const (
	// TypeWebhook receives the alert as JSON, for receivers such as SOAR
	// platforms and SIEMs.
	TypeWebhook Type = "webhook"
	// TypeSlack is an incoming webhook of Slack.
	TypeSlack Type = "slack"
	// TypeTeams is a workflow of Microsoft Teams that posts to a channel.
	TypeTeams Type = "teams"
)

// Types lists every type, in the order of the documentation.
var Types = []Type{TypeWebhook, TypeSlack, TypeTeams}

// Valid reports whether t is a known type.
func (t Type) Valid() bool { return slices.Contains(Types, t) }

// Limits of the fields.
const (
	MaxNameLength = 64
	// MaxURLLength matches the limit of the SSRF guard.
	MaxURLLength         = 2048
	MaxHeaderNameLength  = 64
	MaxHeaderValueLength = 1024
	// MaxChannels bounds the channels of an installation. Every alert is
	// delivered to every channel.
	MaxChannels = 20
)

// Errors of the channels.
var (
	ErrNotFound           = errors.New("alert channel not found")
	ErrInvalidType        = errors.New("invalid alert channel type")
	ErrInvalidName        = errors.New("invalid alert channel name")
	ErrInvalidURL         = errors.New("invalid alert channel URL")
	ErrInvalidHeaderName  = errors.New("invalid header name")
	ErrInvalidHeaderValue = errors.New("invalid header value")
	// ErrHeaderNotAllowed means that a header was set for a channel whose
	// receiver reads none.
	ErrHeaderNotAllowed = errors.New("only a webhook sends a header")
	ErrNameTaken        = errors.New("alert channel name is already in use")
	ErrTooManyChannels  = errors.New("too many alert channels")
	// ErrEnabled means that a channel must be disabled before it is deleted.
	ErrEnabled = errors.New("alert channel is enabled")
)

// Secret is a value that is shown once and never logged, such as the URL of a
// channel.
type Secret string

// String keeps the value out of formatted output.
func (Secret) String() string { return "[redacted]" }

// GoString keeps the value out of %#v.
func (Secret) GoString() string { return "[redacted]" }

// LogValue keeps the value out of logs.
func (Secret) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// MarshalJSON keeps the value out of JSON, such as a log that encodes a struct
// that holds it. Responses never contain a secret.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

// Header is a header that a webhook sends with every request, such as the
// token of the receiver.
type Header struct {
	Name  string
	Value Secret
}

// LogValue names the header, without its value.
func (h Header) LogValue() slog.Value { return slog.GroupValue(slog.String("name", h.Name)) }

// Channel describes a channel without its secrets.
type Channel struct {
	ID      string
	Name    string
	Type    Type
	Enabled bool
	// Target is the scheme, host and port of the URL, which is shown
	// instead of it.
	Target string
	// HeaderName is the name of the header that a webhook sends, or nil.
	HeaderName *string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// LogValue names the channel by its identifier and type.
func (c Channel) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", c.ID), slog.String("type", string(c.Type)))
}

// Spec describes a channel to create. The caller checks the URL with the SSRF
// guard; Validate checks its form only.
type Spec struct {
	Name    string
	Type    Type
	Enabled bool
	URL     Secret
	Header  *Header
}

// LogValue names the type of the channel, without its secrets.
func (s Spec) LogValue() slog.Value { return slog.GroupValue(slog.String("type", string(s.Type))) }

// Validate checks every field of s.
func (s Spec) Validate() error {
	if !s.Type.Valid() {
		return ErrInvalidType
	}
	if err := ValidateName(s.Name); err != nil {
		return err
	}
	if _, err := Target(s.URL); err != nil {
		return err
	}
	if s.Header != nil {
		if s.Type != TypeWebhook {
			return ErrHeaderNotAllowed
		}
		return s.Header.validate()
	}
	return nil
}

// Change describes changes to a channel. A nil field stays as it is. The type
// never changes.
type Change struct {
	Name    *string
	Enabled *bool
	URL     *Secret
	// Header replaces the header of a webhook.
	Header *Header
	// RemoveHeader removes the header.
	RemoveHeader bool
}

// LogValue keeps the secrets of the change out of logs.
func (Change) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// IsEmpty reports whether c changes nothing.
func (c Change) IsEmpty() bool {
	return c.Name == nil && c.Enabled == nil && c.URL == nil && c.Header == nil && !c.RemoveHeader
}

// NeedsConfirmation reports whether c must be confirmed with the password of
// the administrator: every change other than a new name decides where alerts
// go, what authenticates them at the receiver, or whether they go at all. A
// taken-over session could otherwise silence the alerts, or send them again to
// a target that an administrator disabled, for example after its domain
// lapsed.
func (c Change) NeedsConfirmation() bool {
	return c.URL != nil || c.Header != nil || c.RemoveHeader || c.Enabled != nil
}

// Validate checks every field of c.
func (c Change) Validate() error {
	if c.Name != nil {
		if err := ValidateName(*c.Name); err != nil {
			return err
		}
	}
	if c.URL != nil {
		if _, err := Target(*c.URL); err != nil {
			return err
		}
	}
	if c.Header != nil {
		return c.Header.validate()
	}
	return nil
}

// ValidateName accepts a name of 1 to MaxNameLength printable characters
// without surrounding whitespace.
func ValidateName(s string) error {
	n := utf8.RuneCountInString(s)
	if n < 1 || n > MaxNameLength || strings.TrimSpace(s) != s || !utf8.ValidString(s) {
		return ErrInvalidName
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return ErrInvalidName
		}
	}
	return nil
}

// Target returns the scheme, host and port of the URL u, which a channel shows
// instead of the URL. It returns ErrInvalidURL unless u is an http or https
// URL in printable ASCII with a host and without user information or fragment.
// Whether its target is allowed, and plain http, is the business of the SSRF
// guard.
func Target(u Secret) (string, error) {
	s := string(u)
	if len(s) > MaxURLLength || (!strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://")) {
		return "", ErrInvalidURL
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return "", ErrInvalidURL
		}
	}
	parsed, err := url.Parse(s)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Fragment != "" {
		return "", ErrInvalidURL
	}
	// The SSRF guard checks the name without a trailing dot, so it is shown
	// without one as well.
	name := strings.TrimSuffix(parsed.Hostname(), ".")
	if name == "" {
		return "", ErrInvalidURL
	}
	host := name
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := parsed.Port(); port != "" {
		host = net.JoinHostPort(name, port)
	}
	return parsed.Scheme + "://" + strings.ToLower(host), nil
}

// reservedHeaders are headers that the client sets itself or that change how
// a request is transferred. The schema rejects the same names.
var reservedHeaders = []string{
	"host", "content-length", "content-type", "content-encoding", "transfer-encoding", "connection",
	"keep-alive", "te", "trailer", "upgrade", "expect",
}

func (h Header) validate() error {
	if err := ValidateHeaderName(h.Name); err != nil {
		return err
	}
	v := string(h.Value)
	if v == "" || len(v) > MaxHeaderValueLength || strings.TrimSpace(v) != v {
		return ErrInvalidHeaderValue
	}
	for i := range len(v) {
		if v[i] < 0x20 || v[i] > 0x7e {
			return ErrInvalidHeaderValue
		}
	}
	return nil
}

// ValidateHeaderName accepts a token of RFC 9110 of 1 to MaxHeaderNameLength
// characters, other than a header that the client sets itself or one that
// changes how the request is transferred.
func ValidateHeaderName(s string) error {
	if s == "" || len(s) > MaxHeaderNameLength {
		return ErrInvalidHeaderName
	}
	for i := range len(s) {
		c := s[i]
		alphanumeric := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alphanumeric && strings.IndexByte("!#$%&'*+-.^_`|~", c) < 0 {
			return ErrInvalidHeaderName
		}
	}
	lower := strings.ToLower(s)
	if slices.Contains(reservedHeaders, lower) || strings.HasPrefix(lower, "proxy-") {
		return ErrInvalidHeaderName
	}
	return nil
}
