// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package honeytoken manages honeytokens: trigger primitives that raise an
// event when their trigger value is requested or resolved.
//
// Honeytokens are part of the inventory, the most sensitive data of Nyktus:
// whoever reads it can avoid every decoy. Only the console manages them. The
// internet-facing trigger and DNS role never import this package; they resolve
// one trigger value at a time through a database function.
package honeytoken

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"log/slog"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"nyktus.org/nyktus/internal/attack"
	"nyktus.org/nyktus/internal/platform/text"
	"nyktus.org/nyktus/internal/severity"
)

// Type is the kind of a honeytoken, which decides how it is triggered and what
// the trigger answers.
type Type string

// Types of honeytokens.
const (
	// TypeWebURL is a URL that is triggered when it is opened, for example
	// through a link in a document, or a QR code. The trigger redirects the
	// browser, so that the click raises no suspicion.
	TypeWebURL Type = "web_url"
	// TypeWebImage is an image that is triggered when it is loaded, for example
	// when a document or mail that embeds it is opened.
	TypeWebImage Type = "web_image"
	// TypeDNS is a host name that is triggered when it is resolved, for example
	// by a tool that connects to a host from a configuration file. It has a
	// name under every zone of the DNS role instead of a URL.
	TypeDNS Type = "dns"
)

// ResourceType names honeytokens where other records refer to them, such as
// audit entries, events and incidents.
const ResourceType = "honeytoken"

// Types lists every type, in the order in which documentation names them.
var Types = []Type{TypeWebURL, TypeWebImage, TypeDNS}

// Valid reports whether t is a known type.
func (t Type) Valid() bool {
	return slices.Contains(Types, t)
}

// defaultSeverity is the severity of a honeytoken of each type unless another
// one is chosen. Without knowing what the honeytoken pretends to be, it only
// reflects how much harmless traffic triggers it.
var defaultSeverity = map[Type]severity.Level{
	// Opening a URL is deliberate, but whatever it pretends to lead to is
	// unknown.
	TypeWebURL: severity.Medium,
	// Mail gateways, previews and scanners load images without a human
	// opening anything.
	TypeWebImage: severity.Low,
	// Resolving a name is deliberate, as for a URL.
	TypeDNS: severity.Medium,
}

// DefaultSeverity returns the severity of a honeytoken of type t unless
// another one is chosen, or "" for an unknown type.
func (t Type) DefaultSeverity() severity.Level {
	return defaultSeverity[t]
}

// Limits of the fields of a honeytoken, as the database enforces them.
const (
	MaxNameLength        = 100
	MaxNotesLength       = 2000
	MaxRedirectURLLength = 2048
	MaxTechniques        = 20
)

// Names of the fields of a change, as recorded in the audit log.
const (
	FieldName        = "name"
	FieldNotes       = "notes"
	FieldEnabled     = "enabled"
	FieldRedirectURL = "redirect_url"
	FieldTechniques  = "techniques"
	FieldSeverity    = "severity"
	FieldScenarioID  = "scenario_id"
)

// Validation errors.
var (
	ErrInvalidType        = errors.New("invalid honeytoken type")
	ErrInvalidName        = errors.New("invalid honeytoken name")
	ErrInvalidNotes       = errors.New("invalid honeytoken notes")
	ErrInvalidRedirectURL = errors.New("invalid redirect URL")
	// ErrRedirectNotAllowed means that the honeytoken is of a type that is not
	// clicked, so it never redirects.
	ErrRedirectNotAllowed = errors.New("only a honeytoken of the type web_url redirects")
	ErrInvalidTechniques  = errors.New("invalid ATT&CK techniques")
	// ErrInvalidSeverity means that a severity is unknown or info, which only
	// an analyst gives an incident.
	ErrInvalidSeverity = errors.New("invalid honeytoken severity")
)

// Honeytoken is a stored honeytoken.
type Honeytoken struct {
	ID      string
	Type    Type
	Name    string
	Notes   string
	Enabled bool
	// RedirectURL is the target of the redirect of a URL, or nil for the
	// default target of the trigger.
	RedirectURL *string
	// Techniques are the identifiers of the ATT&CK techniques that a trigger
	// suggests.
	Techniques []string
	// Severity is the severity that its events receive.
	Severity severity.Level
	// TriggerValue is the value that triggers the honeytoken, as part of its
	// URL.
	TriggerValue string
	// ScenarioID is the scenario that the honeytoken belongs to, or nil if it
	// stands alone.
	ScenarioID *string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// TriggerPath returns the path of the URL of the honeytoken, or "" for a type
// without a URL. The URL of an image ends with ".gif": the trigger answers every
// such request with an image and every other one with a redirect, so that its
// answer never depends on whether a value belongs to a honeytoken or of which
// type it is.
func (h Honeytoken) TriggerPath() string {
	switch h.Type {
	case TypeWebImage:
		return "/" + h.TriggerValue + ".gif"
	case TypeDNS:
		return ""
	default:
		return "/" + h.TriggerValue
	}
}

// TriggerNames returns the host names of a DNS honeytoken, its trigger value
// under each of zones, and none for every other type. The value is a valid DNS
// label, and the DNS role finds it as the label directly below a zone.
func (h Honeytoken) TriggerNames(zones []string) []string {
	if h.Type != TypeDNS {
		return []string{}
	}
	names := make([]string, len(zones))
	for i, zone := range zones {
		names[i] = h.TriggerValue + "." + zone
	}
	return names
}

// LogValue names the honeytoken by its identifier and type. Its name, notes and
// trigger value are inventory and stay out of logs.
func (h Honeytoken) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", h.ID), slog.String("type", string(h.Type)))
}

// Spec describes a honeytoken to create.
type Spec struct {
	Type        Type
	Name        string
	Notes       string
	Enabled     bool
	RedirectURL *string
	Techniques  []string
	// Severity is the severity of the honeytoken, or nil for the default of
	// its type.
	Severity *severity.Level
	// ScenarioID is the scenario the honeytoken joins when it is created, or
	// empty for one that stands alone.
	ScenarioID string
}

func (s Spec) validate() error {
	if !s.Type.Valid() {
		return ErrInvalidType
	}
	if err := ValidateName(s.Name); err != nil {
		return err
	}
	if err := ValidateNotes(s.Notes); err != nil {
		return err
	}
	if s.RedirectURL != nil {
		if s.Type != TypeWebURL {
			return ErrRedirectNotAllowed
		}
		if err := ValidateRedirectURL(*s.RedirectURL); err != nil {
			return err
		}
	}
	if s.Severity != nil && !s.Severity.IsSuggested() {
		return ErrInvalidSeverity
	}
	return ValidateTechniques(s.Techniques)
}

// Change describes changes to a honeytoken. A nil field stays as it is. The
// type and the trigger value never change.
type Change struct {
	Name    *string
	Notes   *string
	Enabled *bool
	// RedirectURL sets the target of the redirect. An empty string removes it.
	RedirectURL *string
	// Techniques replace the techniques of the honeytoken.
	Techniques []string
	// SetTechniques reports whether Techniques is part of the change, so that
	// an empty list can remove every technique.
	SetTechniques bool
	// Severity replaces the severity, which applies to later events only.
	Severity *severity.Level
}

// IsEmpty reports whether c changes nothing.
func (c Change) IsEmpty() bool {
	return c.Name == nil && c.Notes == nil && c.Enabled == nil && c.RedirectURL == nil && !c.SetTechniques &&
		c.Severity == nil
}

func (c Change) validate() error {
	if c.Name != nil {
		if err := ValidateName(*c.Name); err != nil {
			return err
		}
	}
	if c.Notes != nil {
		if err := ValidateNotes(*c.Notes); err != nil {
			return err
		}
	}
	if c.RedirectURL != nil && *c.RedirectURL != "" {
		if err := ValidateRedirectURL(*c.RedirectURL); err != nil {
			return err
		}
	}
	if c.Severity != nil && !c.Severity.IsSuggested() {
		return ErrInvalidSeverity
	}
	if c.SetTechniques {
		return ValidateTechniques(c.Techniques)
	}
	return nil
}

// ValidateName accepts a name of 1 to MaxNameLength characters, as
// text.ValidName describes.
func ValidateName(s string) error {
	if !text.ValidName(s, MaxNameLength) {
		return ErrInvalidName
	}
	return nil
}

// ValidateNotes accepts notes of up to MaxNotesLength characters, as
// text.ValidNotes describes.
func ValidateNotes(s string) error {
	if !text.ValidNotes(s, MaxNotesLength) {
		return ErrInvalidNotes
	}
	return nil
}

// ValidateRedirectURL accepts an absolute http or https URL of up to
// MaxRedirectURLLength characters, written in printable ASCII with a lowercase
// scheme, whose host is a name, not an IP address, and that carries no user
// information. The trigger sends the browser of whoever opens a honeytoken
// there. A link to a bare IP address looks unlike the links an organization
// places, and user information in front of the host is a common way to disguise
// the real target of a link. Whether the host is reachable from where the
// honeytoken is opened is the choice of the operator.
func ValidateRedirectURL(s string) error {
	if len(s) > MaxRedirectURLLength || (!strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://")) {
		return ErrInvalidRedirectURL
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return ErrInvalidRedirectURL
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.User != nil || u.Opaque != "" || u.Hostname() == "" || isIPHost(u.Hostname()) {
		return ErrInvalidRedirectURL
	}
	return nil
}

// isIPHost reports whether a browser reads host as an IP address. Beyond the
// usual notations, the URL standard reads a host whose last label is a number,
// such as 2130706433 or 0x7f.1, as an IPv4 address.
func isIPHost(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	last := strings.ToLower(labels[len(labels)-1])
	if hex, ok := strings.CutPrefix(last, "0x"); ok {
		return strings.Trim(hex, "0123456789abcdef") == ""
	}
	return last != "" && strings.Trim(last, "0123456789") == ""
}

// ValidateTechniques accepts up to MaxTechniques distinct identifiers of
// techniques of the bundled version of ATT&CK.
func ValidateTechniques(ids []string) error {
	if len(ids) > MaxTechniques {
		return ErrInvalidTechniques
	}
	for i, id := range ids {
		if _, ok := attack.Lookup(id); !ok || slices.Contains(ids[:i], id) {
			return ErrInvalidTechniques
		}
	}
	return nil
}

// triggerValueBytes is the entropy of a trigger value: 128 bits, which nobody
// guesses, in 26 characters of base32, short enough for a DNS label.
const triggerValueBytes = 16

var triggerEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func newTriggerValue() string {
	b := make([]byte, triggerValueBytes)
	// crypto/rand.Read never fails; it crashes the program instead.
	_, _ = rand.Read(b)
	return triggerEncoding.EncodeToString(b)
}
