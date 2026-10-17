// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package user manages the accounts that sign in to the console.
package user

import (
	"errors"
	"log/slog"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"nyktus.org/nyktus/internal/platform/text"
)

// Role determines what a user may do in the console.
type Role string

// Roles of a user.
const (
	RoleAdmin  Role = "admin"
	RoleUser   Role = "user"
	RoleViewer Role = "viewer"
)

// Valid reports whether r is a known role. An unknown role has no permissions.
func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleUser, RoleViewer:
		return true
	default:
		return false
	}
}

// Status is the lifecycle state of an account.
type Status string

// Statuses of an account.
const (
	// StatusPending accounts have been created but have not set a password yet.
	StatusPending Status = "pending"
	// StatusActive accounts can sign in.
	StatusActive Status = "active"
	// StatusDeactivated accounts cannot sign in. Their password hash, if any, is
	// kept so that they can be reactivated.
	StatusDeactivated Status = "deactivated"
)

// User is an account of the console.
type User struct {
	ID          string
	Email       string
	DisplayName string
	Role        Role
	Status      Status
	// PasswordHash is the encoded Argon2id hash. It is empty while the user has
	// not set a password, and for an account of the identity provider.
	PasswordHash string
	// Identity is set for an account of the identity provider, which signs in
	// through OpenID Connect and has no password.
	Identity  *Identity
	CreatedAt time.Time
	UpdatedAt time.Time
	// TOTPEnabled reports whether the account has a confirmed TOTP factor, so
	// that signing in takes a code in addition to the password.
	TOTPEnabled bool
}

// Identity names an account of an OpenID Connect provider.
type Identity struct {
	Issuer  string
	Subject string
}

// MaxSubjectLength bounds the subject of an identity (OpenID Connect Core 1.0,
// section 2), and MaxIssuerLength the URL of its issuer.
const (
	MaxSubjectLength = 255
	MaxIssuerLength  = 2048
)

// ErrInvalidIdentity is returned for an identity that the schema would reject.
var ErrInvalidIdentity = errors.New("invalid identity")

// Valid reports whether the schema accepts id: an issuer of printable ASCII
// without spaces and a subject of printable ASCII, each within its limit.
func (id Identity) Valid() bool {
	return asciiWithin(id.Issuer, MaxIssuerLength, '!') && asciiWithin(id.Subject, MaxSubjectLength, ' ')
}

func asciiWithin(s string, limit int, lowest byte) bool {
	if s == "" || len(s) > limit {
		return false
	}
	for i := range len(s) {
		if s[i] < lowest || s[i] > '~' {
			return false
		}
	}
	return true
}

// SignInMethod is how an account signs in.
type SignInMethod string

// Sign-in methods of an account.
const (
	SignInPassword SignInMethod = "password"
	SignInOIDC     SignInMethod = "oidc"
)

// SignInMethod returns how u signs in.
func (u User) SignInMethod() SignInMethod {
	if u.Identity != nil {
		return SignInOIDC
	}
	return SignInPassword
}

// Response is the representation of an account in API responses. It leaves out
// the password hash and every other field that a client has no use for.
type Response struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Role        Role   `json:"role"`
	Status      Status `json:"status"`
	TOTPEnabled bool   `json:"totp_enabled"`
	// SignInMethod tells clients whether the account has a password that it
	// can change, or signs in through the identity provider.
	SignInMethod SignInMethod `json:"sign_in_method"`
}

// Response returns the representation of u in API responses.
func (u User) Response() Response {
	return Response{
		ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, Role: u.Role, Status: u.Status,
		TOTPEnabled: u.TOTPEnabled, SignInMethod: u.SignInMethod(),
	}
}

// LogValue keeps the password hash and the address out of logs. A hash allows
// offline guessing of the password, and the address is personal data.
func (u User) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", u.ID),
		slog.String("role", string(u.Role)),
		slog.String("status", string(u.Status)),
	)
}

// Limits for account fields. An email address is limited by the length of a path
// in SMTP (RFC 5321).
const (
	MaxEmailLength       = 254
	MaxDisplayNameLength = 100
)

// Validation errors.
var (
	ErrInvalidEmail       = errors.New("invalid email address")
	ErrInvalidDisplayName = errors.New("invalid display name")
	ErrInvalidRole        = errors.New("invalid role")
	// ErrInvalidPasswordHash is returned for a password hash that is not an
	// encoded Argon2id hash, such as a plain-text password passed by mistake.
	ErrInvalidPasswordHash = errors.New("invalid password hash")
)

// ParseEmail accepts a single bare address, such as "jane@example.com", and
// returns it in lower case and NFC normalization. Display names, comments,
// quoted local parts and whitespace are rejected.
//
// The address is the sign-in name, so every spelling of the same address must
// map to one account. Mail systems treat the local part as case-insensitive in
// practice, and the same non-ASCII address can arrive precomposed or decomposed
// depending on the client.
func ParseEmail(s string) (string, error) {
	if strings.ContainsAny(s, "\" ") || !printable(s) {
		return "", ErrInvalidEmail
	}
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Name != "" || addr.Address != s || strings.Count(s, "@") != 1 {
		return "", ErrInvalidEmail
	}
	// Lowercasing and normalization can change the length in bytes, so the limit
	// applies afterwards.
	normalized := norm.NFC.String(strings.ToLower(s))
	if len(normalized) > MaxEmailLength {
		return "", ErrInvalidEmail
	}
	return normalized, nil
}

// ParseDisplayName accepts a name of 1 to MaxDisplayNameLength characters, as
// text.ValidName describes, and returns it unchanged.
func ParseDisplayName(s string) (string, error) {
	if !text.ValidName(s, MaxDisplayNameLength) {
		return "", ErrInvalidDisplayName
	}
	return s, nil
}

// printable reports whether s is valid UTF-8 and consists of printable
// characters. unicode.IsPrint rejects control and format characters, and every
// space except U+0020.
func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
