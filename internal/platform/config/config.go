// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config reads and validates the configuration from the environment. It is
// the only package that reads environment variables.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"nyktus.org/nyktus/internal/platform/logging"
	"nyktus.org/nyktus/internal/platform/secretbox"
)

const prefix = "NYKTUS_"

// Environment selects development conveniences. Every check that is relaxed in
// development is enforced in production.
type Environment string

// Supported environments.
const (
	Development Environment = "development"
	Production  Environment = "production"
)

// Role is a part of the server that can run in a process.
type Role string

// Implemented server roles.
const (
	RoleConsole Role = "console"
)

// Roles lists every implemented role in a stable order.
var Roles = []Role{RoleConsole}

// ParseRoles parses a comma-separated list of role names. An empty list selects
// all roles.
func ParseRoles(s string) ([]Role, error) {
	if strings.TrimSpace(s) == "" {
		return slices.Clone(Roles), nil
	}
	var roles []Role
	for name := range strings.SplitSeq(s, ",") {
		role := Role(strings.TrimSpace(name))
		if !slices.Contains(Roles, role) {
			return nil, fmt.Errorf("unknown role %q", role)
		}
		if !slices.Contains(roles, role) {
			roles = append(roles, role)
		}
	}
	return roles, nil
}

// Secret holds a sensitive value. Its string, Go-syntax and log representations are
// redacted, so the value cannot leak through formatting or logging by accident.
type Secret string

const redacted = "[redacted]"

// Value returns the secret in clear text.
func (s Secret) Value() string { return string(s) }

func (Secret) String() string { return redacted }

// GoString implements fmt.GoStringer.
func (Secret) GoString() string { return redacted }

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText implements encoding.TextMarshaler, which also covers JSON encoding.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Source provides the raw configuration values.
type Source struct {
	Getenv   func(key string) string
	ReadFile func(name string) ([]byte, error)
}

// FromEnvironment returns the Source backed by the process environment.
func FromEnvironment() Source {
	return Source{Getenv: os.Getenv, ReadFile: os.ReadFile}
}

// Common holds the settings shared by all commands.
type Common struct {
	Environment Environment
	LogLevel    slog.Level
}

// Console holds the settings of the console role.
type Console struct {
	Addr string
	// URL is the address under which users reach the console, such as
	// "https://nyktus.example.com", without a trailing slash. Links that the
	// console hands out, such as the setup URL, start with it.
	URL         string
	DatabaseURL Secret
	// SessionIdleTimeout ends a session after this long without a request.
	SessionIdleTimeout time.Duration
	// SessionMaxAge ends a session this long after sign-in, however active it is.
	SessionMaxAge time.Duration
	// OIDC configures the sign-in through an OpenID Connect provider. It is nil
	// if the sign-in is not enabled.
	OIDC *OIDC
	// LocalLogin says which accounts sign in with a password.
	LocalLogin LocalLogin
	// TriggerURL is the public address of the trigger, such as
	// "https://t.example.com", without a trailing slash. The URL of a
	// honeytoken is this address followed by its trigger value.
	TriggerURL string
}

// LocalLogin says which accounts sign in with a password.
type LocalLogin string

// Accounts that sign in with a password.
const (
	// LocalLoginAll lets every account with a password sign in with it.
	LocalLoginAll LocalLogin = "all"
	// LocalLoginAdmins lets only administrators sign in with a password, as
	// emergency access while every other user signs in through the identity
	// provider.
	LocalLoginAdmins LocalLogin = "admins"
	// LocalLoginOff lets nobody sign in with a password.
	LocalLoginOff LocalLogin = "off"
)

// OIDC configures the sign-in through an OpenID Connect provider. Accounts are
// created at their first sign-in, and their role follows their groups at the
// provider with every sign-in.
type OIDC struct {
	// Issuer is the URL of the provider, exactly as its tokens name it.
	Issuer       string
	ClientID     string
	ClientSecret Secret
	// Scopes are requested in addition to openid, which is always requested.
	Scopes []string
	// GroupsClaim names the claim of the ID token that lists the groups of the
	// user.
	GroupsClaim string
	// The groups whose members receive a role. The highest role of the groups
	// of a user wins; a user in none of them cannot sign in.
	AdminGroups, UserGroups, ViewerGroups []string
}

// oidcVariables are the settings of the sign-in through OpenID Connect other
// than the issuer, which enables it.
var oidcVariables = []string{
	"OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_CLIENT_SECRET_FILE", "OIDC_SCOPES", "OIDC_GROUPS_CLAIM",
	"OIDC_ADMIN_GROUPS", "OIDC_USER_GROUPS", "OIDC_VIEWER_GROUPS",
}

// Limits of the session durations. A session must be able to outlast a short
// pause, and must end within a month at the latest.
const (
	minSessionIdleTimeout = 5 * time.Minute
	maxSessionIdleTimeout = 24 * time.Hour
	maxSessionMaxAge      = 30 * 24 * time.Hour
)

// Serve is the configuration of the serve command.
type Serve struct {
	Common
	Roles []Role
	// TrustedProxies are the address ranges of reverse proxies whose
	// X-Forwarded-For header is believed. Empty means that only the socket
	// address counts.
	TrustedProxies []netip.Prefix
	// EncryptionKeys encrypt the secrets that the instance stores and must read
	// back, such as the secrets of second factors. They belong to the instance,
	// not to a role, because every role that reads such a secret needs the same
	// keys. They are read only if an enabled role uses them.
	EncryptionKeys *secretbox.Keyring
	Console        Console
}

// Has reports whether role is enabled.
func (c Serve) Has(role Role) bool { return slices.Contains(c.Roles, role) }

// Migrate is the configuration of the migrate command.
type Migrate struct {
	Common
	DatabaseURL Secret
}

// Admin is the configuration of the admin commands. They work on the database
// with the role of the console, which holds every privilege they need, and
// print links that start with the address of the console.
type Admin struct {
	Common
	ConsoleURL  string
	DatabaseURL Secret
}

// LoadServe reads the configuration for the given roles. Settings of roles that are
// not enabled are neither read nor required.
func LoadServe(src Source, roles []Role) (Serve, error) {
	r := reader{src: src}
	cfg := Serve{Common: r.common(), Roles: roles, TrustedProxies: r.prefixes("TRUSTED_PROXIES")}
	if cfg.Has(RoleConsole) {
		addr := r.addr("CONSOLE_ADDR", "127.0.0.1:8080")
		cfg.Console = Console{
			Addr:        addr,
			URL:         r.consoleURL("CONSOLE_URL", cfg.Environment, addr),
			DatabaseURL: r.requiredSecret("CONSOLE_DATABASE_URL"),
			SessionIdleTimeout: r.duration("SESSION_IDLE_TIMEOUT", time.Hour,
				minSessionIdleTimeout, maxSessionIdleTimeout),
		}
		cfg.Console.SessionMaxAge = r.duration("SESSION_MAX_AGE", 12*time.Hour,
			max(cfg.Console.SessionIdleTimeout, minSessionIdleTimeout), maxSessionMaxAge)
		cfg.Console.OIDC = r.oidc(cfg.Environment)
		cfg.Console.LocalLogin = r.localLogin(cfg.Console.OIDC != nil)
		cfg.Console.TriggerURL = r.triggerURL("TRIGGER_URL", cfg.Environment, cfg.Console.URL)
		cfg.EncryptionKeys = r.keyring("ENCRYPTION_KEYS")
	}
	return cfg, r.err()
}

// LoadAdmin reads the configuration of the admin commands from the settings of
// the console, so that they need no configuration of their own.
func LoadAdmin(src Source) (Admin, error) {
	r := reader{src: src}
	cfg := Admin{Common: r.common()}
	cfg.ConsoleURL = r.consoleURL("CONSOLE_URL", cfg.Environment, r.addr("CONSOLE_ADDR", "127.0.0.1:8080"))
	cfg.DatabaseURL = r.requiredSecret("CONSOLE_DATABASE_URL")
	return cfg, r.err()
}

// LoadMigrate reads the configuration of the migrate command.
func LoadMigrate(src Source) (Migrate, error) {
	r := reader{src: src}
	cfg := Migrate{Common: r.common(), DatabaseURL: r.requiredSecret("DATABASE_URL")}
	return cfg, r.err()
}

// reader collects every problem instead of stopping at the first, so that an
// operator can fix the configuration in one pass.
type reader struct {
	src  Source
	errs []error
}

func (r *reader) err() error { return errors.Join(r.errs...) }

func (r *reader) fail(format string, args ...any) {
	r.errs = append(r.errs, fmt.Errorf(format, args...))
}

func (r *reader) common() Common {
	c := Common{Environment: Production, LogLevel: slog.LevelInfo}

	switch env := Environment(r.get("ENV")); env {
	case "", Production:
	case Development:
		c.Environment = Development
	default:
		r.fail("%sENV: must be %q or %q, got %q", prefix, Production, Development, env)
	}

	if s := r.get("LOG_LEVEL"); s != "" {
		level, err := logging.ParseLevel(s)
		if err != nil {
			r.fail("%sLOG_LEVEL: %w", prefix, err)
		}
		c.LogLevel = level
	}
	return c
}

func (r *reader) get(name string) string {
	return strings.TrimSpace(r.src.Getenv(prefix + name))
}

func (r *reader) addr(name, fallback string) string {
	addr := r.get(name)
	if addr == "" {
		return fallback
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		r.fail("%s%s: %w", prefix, name, err)
	}
	return addr
}

// duration reads a duration in the notation of Go, such as "90m" or "12h", within
// [lowest, highest].
func (r *reader) duration(name string, fallback, lowest, highest time.Duration) time.Duration {
	value := r.get(name)
	if value == "" {
		return fallback
	}
	d, err := time.ParseDuration(value)
	switch {
	case err != nil:
		r.fail("%s%s: %q is not a duration such as 90m or 12h", prefix, name, value)
	case d < lowest || d > highest:
		r.fail("%s%s: must be between %v and %v, got %v", prefix, name, lowest, highest, d)
	default:
		return d
	}
	return fallback
}

// consoleURL reads the external address of the console. It is required outside
// development, because links handed out to users must reach the console through
// its reverse proxy. In development, it defaults to the listen address.
func (r *reader) consoleURL(name string, env Environment, addr string) string {
	if r.get(name) == "" && env == Development {
		return developmentURL(addr)
	}
	return r.origin(name, env)
}

// triggerURL reads the public address of the trigger, which the URLs of
// honeytokens start with. It is required in every environment, because the
// console shows these URLs. Its host must differ from the host of the console:
// every placed URL names it, and a decoy that leads to the console would reveal
// it. In development, both may run on one host with different ports.
func (r *reader) triggerURL(name string, env Environment, consoleURL string) string {
	u := r.origin(name, env)
	if u == "" || consoleURL == "" {
		return u
	}
	trigger, errTrigger := url.Parse(u)
	console, errConsole := url.Parse(consoleURL)
	same := strings.EqualFold(trigger.Hostname(), console.Hostname())
	if env == Development {
		same = strings.EqualFold(u, consoleURL)
	}
	if errTrigger == nil && errConsole == nil && same {
		r.fail("%s%s: must name another host than %sCONSOLE_URL; the trigger is reached from the internet, the console must not be", prefix, name, prefix)
		return ""
	}
	return u
}

// origin reads a required address that consists of scheme, host and port only.
// Nyktus appends paths to it, and user information, a query or a fragment would
// end up in front of them. It must use https outside development.
func (r *reader) origin(name string, env Environment) string {
	value := r.get(name)
	if value == "" {
		r.fail("%s%s is required", prefix, name)
		return ""
	}

	u, err := url.Parse(value)
	switch {
	case err != nil:
		r.fail("%s%s: %q is not a URL", prefix, name, value)
	case u.Scheme != "https" && (u.Scheme != "http" || env != Development):
		r.fail("%s%s: must start with https:// (http:// is allowed in development only)", prefix, name)
	case u.Host == "" || u.Hostname() == "":
		r.fail("%s%s: must name a host", prefix, name)
	case u.User != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.HasSuffix(value, "#"):
		r.fail("%s%s: must consist of scheme, host and port only, such as https://nyktus.example.com", prefix, name)
	default:
		return u.Scheme + "://" + u.Host
	}
	return ""
}

// developmentURL derives the console URL from the listen address. A listener on
// all interfaces is reached through localhost.
func developmentURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	if ip, err := netip.ParseAddr(host); host == "" || (err == nil && ip.IsUnspecified()) {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port)
}

// oidc reads the sign-in through OpenID Connect, which NYKTUS_OIDC_ISSUER
// enables. Its other settings are rejected without the issuer, so that a typo in
// the name of the issuer does not silently leave the sign-in disabled.
func (r *reader) oidc(env Environment) *OIDC {
	if r.get("OIDC_ISSUER") == "" {
		for _, name := range oidcVariables {
			if r.get(name) != "" {
				r.fail("%s%s is set, but %sOIDC_ISSUER is not; set it to enable the sign-in through OpenID Connect", prefix, name, prefix)
			}
		}
		return nil
	}
	c := &OIDC{
		Issuer:       r.issuer("OIDC_ISSUER", env),
		ClientID:     r.get("OIDC_CLIENT_ID"),
		ClientSecret: r.requiredSecret("OIDC_CLIENT_SECRET"),
		Scopes:       []string{"email", "profile"},
		GroupsClaim:  r.get("OIDC_GROUPS_CLAIM"),
		AdminGroups:  r.list("OIDC_ADMIN_GROUPS"),
		UserGroups:   r.list("OIDC_USER_GROUPS"),
		ViewerGroups: r.list("OIDC_VIEWER_GROUPS"),
	}
	if c.ClientID == "" {
		r.fail("%sOIDC_CLIENT_ID is required with %sOIDC_ISSUER", prefix, prefix)
	}
	if value := r.get("OIDC_SCOPES"); value != "" {
		c.Scopes = nil
		for scope := range strings.FieldsSeq(value) {
			if !validScope(scope) {
				r.fail("%sOIDC_SCOPES: %q is not a scope", prefix, scope)
			}
			if scope != "openid" && !slices.Contains(c.Scopes, scope) {
				c.Scopes = append(c.Scopes, scope)
			}
		}
	}
	if c.GroupsClaim == "" {
		c.GroupsClaim = "groups"
	}
	if len(c.AdminGroups)+len(c.UserGroups)+len(c.ViewerGroups) == 0 {
		r.fail("%sOIDC_ADMIN_GROUPS, %sOIDC_USER_GROUPS or %sOIDC_VIEWER_GROUPS is required with %sOIDC_ISSUER; without groups, nobody can sign in",
			prefix, prefix, prefix, prefix)
	}
	return c
}

// validScope accepts the characters that a scope may contain (RFC 6749,
// section 3.3).
func validScope(s string) bool {
	for i := range len(s) {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return s != ""
}

// issuer reads the URL of an OpenID Connect provider. Discovery appends a path
// to it, and the tokens of the provider name it exactly, so it is kept as it is
// written. It must use https outside development, because the provider vouches
// for the identity of every user who signs in through it.
func (r *reader) issuer(name string, env Environment) string {
	value := r.get(name)
	u, err := url.Parse(value)
	switch {
	case err != nil:
		r.fail("%s%s: %q is not a URL", prefix, name, value)
	case u.Scheme != "https" && (u.Scheme != "http" || env != Development):
		r.fail("%s%s: must start with https:// (http:// is allowed in development only)", prefix, name)
	case u.Host == "" || u.Hostname() == "":
		r.fail("%s%s: must name a host", prefix, name)
	case u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.HasSuffix(value, "#"):
		r.fail("%s%s: must not contain user information, a query or a fragment", prefix, name)
	case len(value) > maxIssuerLength:
		r.fail("%s%s: must not be longer than %d characters", prefix, name, maxIssuerLength)
	default:
		return value
	}
	return ""
}

// maxIssuerLength is the longest issuer that the database stores with an
// account.
const maxIssuerLength = 2048

// localLogin reads which accounts sign in with a password. With the sign-in
// through OpenID Connect, only administrators do by default, as emergency
// access. Without it, every account must, or some users could not sign in at
// all.
func (r *reader) localLogin(oidc bool) LocalLogin {
	switch value := LocalLogin(r.get("LOCAL_LOGIN")); {
	case value == "" && oidc:
		return LocalLoginAdmins
	case value == "" || value == LocalLoginAll:
		return LocalLoginAll
	case (value == LocalLoginAdmins || value == LocalLoginOff) && oidc:
		return value
	case value == LocalLoginAdmins || value == LocalLoginOff:
		r.fail("%sLOCAL_LOGIN: %q requires %sOIDC_ISSUER; otherwise some users could not sign in", prefix, value, prefix)
	default:
		r.fail("%sLOCAL_LOGIN: must be %q, %q or %q, got %q", prefix, LocalLoginAll, LocalLoginAdmins, LocalLoginOff, value)
	}
	return LocalLoginAll
}

// list reads a comma-separated list. Entries are trimmed, so that names may
// contain inner spaces, and empty or repeated entries are dropped.
func (r *reader) list(name string) []string {
	var entries []string
	for entry := range strings.SplitSeq(r.get(name), ",") {
		if entry = strings.TrimSpace(entry); entry != "" && !slices.Contains(entries, entry) {
			entries = append(entries, entry)
		}
	}
	return entries
}

// prefixes reads a comma-separated list of address ranges in CIDR notation. A
// single address stands for a range of one address.
//
// Ranges must be written in their canonical form: "10.0.0.1/8" is rejected
// rather than read as "10.0.0.0/8", because it suggests that only one address
// is trusted. IPv4 ranges written in IPv6 notation are rejected as well, because
// client addresses are compared in their IPv4 form and would never match.
func (r *reader) prefixes(name string) []netip.Prefix {
	value := r.get(name)
	if value == "" {
		return nil
	}
	var prefixes []netip.Prefix
	for entry := range strings.SplitSeq(value, ",") {
		entry = strings.TrimSpace(entry)
		p, err := parsePrefix(entry)
		if err != nil {
			r.fail("%s%s: %w", prefix, name, err)
			continue
		}
		prefixes = append(prefixes, p)
	}
	return prefixes
}

func parsePrefix(s string) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		addr, err := netip.ParseAddr(s)
		if err != nil || addr.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("%q is not an address range", s)
		}
		s = netip.PrefixFrom(addr, addr.BitLen()).String()
	}
	p, err := netip.ParsePrefix(s)
	switch {
	case err != nil:
		return netip.Prefix{}, fmt.Errorf("%q is not an address range", s)
	case p != p.Masked():
		return netip.Prefix{}, fmt.Errorf("%q has host bits set; write %q", s, p.Masked())
	case p.Addr().Is4In6():
		return netip.Prefix{}, fmt.Errorf("%q is an IPv4 range in IPv6 notation; write it as an IPv4 range", s)
	}
	return p, nil
}

// keyring reads the keys that encrypt secrets at rest. They are required in
// every environment: a key derived from another secret or generated at each
// start would make the stored secrets unreadable or tie them to that secret.
func (r *reader) keyring(name string) *secretbox.Keyring {
	value := r.requiredSecret(name)
	if value == "" {
		return nil
	}
	k, err := secretbox.ParseKeyring(value.Value())
	if err != nil {
		// The error names the variable that the operator set.
		source := prefix + name
		if strings.TrimSpace(r.src.Getenv(source+"_FILE")) != "" {
			source += "_FILE"
		}
		r.fail("%s: %w", source, err)
		return nil
	}
	return k
}

// requiredSecret reads a secret either from NAME or from the file named by
// NAME_FILE, so that container secrets do not have to appear in the environment.
func (r *reader) requiredSecret(name string) Secret {
	key, fileKey := prefix+name, prefix+name+"_FILE"
	value, file := r.src.Getenv(key), strings.TrimSpace(r.src.Getenv(fileKey))

	switch {
	case value != "" && file != "":
		r.fail("%s and %s are both set; set only one", key, fileKey)
		return ""
	case file != "":
		content, err := r.src.ReadFile(file)
		if err != nil {
			r.fail("%s: read secret file: %w", fileKey, err)
			return ""
		}
		value = strings.TrimRight(string(content), "\r\n")
	}

	if value == "" {
		r.fail("%s or %s is required", key, fileKey)
	}
	return Secret(value)
}
