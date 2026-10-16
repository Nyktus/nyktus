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
	"strconv"
	"strings"
	"time"

	"nyktus.org/nyktus/internal/honeytoken"
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
	RoleTrigger Role = "trigger"
	RoleDNS     Role = "dns"
	RoleWorker  Role = "worker"
)

// Roles lists every implemented role in a stable order.
var Roles = []Role{RoleConsole, RoleTrigger, RoleDNS, RoleWorker}

// ParseRoles parses a comma-separated list of role names. The list is required:
// the roles are meant for different hosts, and some of them listen on the
// internet, so a process never starts a role that nobody asked for.
func ParseRoles(s string) ([]Role, error) {
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("--roles is required; choose from %s", joinRoles(Roles))
	}
	var roles []Role
	for name := range strings.SplitSeq(s, ",") {
		role := Role(strings.TrimSpace(name))
		if !slices.Contains(Roles, role) {
			return nil, fmt.Errorf("unknown role %q; choose from %s", role, joinRoles(Roles))
		}
		if !slices.Contains(roles, role) {
			roles = append(roles, role)
		}
	}
	return roles, nil
}

func joinRoles(roles []Role) string {
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = string(r)
	}
	return strings.Join(names, ", ")
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
	// DNSZones are the zones that the DNS role answers, in lower case without a
	// trailing dot. The names of a DNS honeytoken are its trigger value under
	// each of them. Empty if DNS honeytokens are not set up.
	DNSZones []string
}

// Trigger holds the settings of the trigger role, which answers the requests of
// honeytokens from the internet. Its public address, NYKTUS_TRIGGER_URL, is a
// setting of the console, which hands out the URLs; the trigger answers every
// host name.
type Trigger struct {
	Addr        string
	DatabaseURL Secret
	// DefaultRedirect is where the trigger sends every client that it does not
	// send to the redirect target of a honeytoken: requests of unknown values
	// and other paths, and requests it failed to record.
	DefaultRedirect string
}

// DNS holds the settings of the DNS role, which answers the zones delegated to
// it as an authoritative name server and records the queries of DNS
// honeytokens.
type DNS struct {
	Addr        string
	DatabaseURL Secret
	// DatabaseMaxConns bounds the connections to the database, and with them
	// the queries recorded at a time.
	DatabaseMaxConns int
	// Zones are the zones to answer, in lower case without a trailing dot.
	Zones []string
	// Nameservers are the host names of the name servers of the zones, which
	// the answers name in NS and SOA records. They lie outside the zones.
	Nameservers []string
	// AnswerIPv4 and AnswerIPv6 are the addresses with which every name of the
	// zones resolves, or the zero Addr for no address of that family.
	AnswerIPv4, AnswerIPv6 netip.Addr
	// TTL is the time to live of every answer, also of negative answers.
	TTL time.Duration
}

// Worker holds the settings of the worker role, which correlates events into
// incidents and delivers their alerts. It listens on no port.
type Worker struct {
	DatabaseURL Secret
	// Concurrency bounds the events that the worker processes at a time, and
	// with them its connections to the database.
	Concurrency int
	// DeliveryConcurrency bounds the alerts that the worker delivers at a
	// time. A delivery holds a connection to the database only while it
	// claims and records an attempt, not while it waits for the receiver.
	DeliveryConcurrency int
	// ConsoleURL is the address of the console, to which an alert links its
	// incident.
	ConsoleURL string
}

// defaultConsoleAddr is the address that the console listens on by default.
const defaultConsoleAddr = "127.0.0.1:8080"

// maxWorkerConcurrency bounds the connections of the worker.
const maxWorkerConcurrency = 32

// Limits of the DNS settings.
const (
	maxDNSTTL = time.Hour
	// maxZoneLength leaves room in a name of at most 253 characters for the
	// trigger value and a few labels in front of it.
	maxZoneLength  = 200
	maxNameservers = 8
	// maxDNSDatabaseConns bounds the connections of the DNS role, which is
	// reached from the internet and must not exhaust the database.
	maxDNSDatabaseConns = 100
)

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
// pause, and must end within a month at the latest. The worker removes
// sessions beyond the upper limits, which the schema repeats.
const (
	minSessionIdleTimeout = 5 * time.Minute
	// MaxSessionIdleTimeout is the longest idle timeout of a session.
	MaxSessionIdleTimeout = 24 * time.Hour
	// MaxSessionMaxAge is the longest lifetime of a session.
	MaxSessionMaxAge = 30 * 24 * time.Hour
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
	// AlertingAllowedNetworks are internal networks that alert channels may
	// reach, chosen by the operator. The console checks the targets of
	// channels against them, and the worker connects only within them.
	AlertingAllowedNetworks []netip.Prefix
	Console                 Console
	Trigger                 Trigger
	DNS                     DNS
	Worker                  Worker
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
		addr := r.addr("CONSOLE_ADDR", defaultConsoleAddr)
		cfg.Console = Console{
			Addr:        addr,
			URL:         r.consoleURL("CONSOLE_URL", cfg.Environment, addr),
			DatabaseURL: r.requiredSecret("CONSOLE_DATABASE_URL"),
			SessionIdleTimeout: r.duration("SESSION_IDLE_TIMEOUT", time.Hour,
				minSessionIdleTimeout, MaxSessionIdleTimeout),
		}
		cfg.Console.SessionMaxAge = r.duration("SESSION_MAX_AGE", 12*time.Hour,
			max(cfg.Console.SessionIdleTimeout, minSessionIdleTimeout), MaxSessionMaxAge)
		cfg.Console.OIDC = r.oidc(cfg.Environment)
		cfg.Console.LocalLogin = r.localLogin(cfg.Console.OIDC != nil)
		cfg.Console.TriggerURL = r.triggerURL("TRIGGER_URL", cfg.Environment, cfg.Console.URL)
		cfg.Console.DNSZones = r.zones("DNS_ZONES", false, cfg.Console.URL, cfg.Console.TriggerURL)
	}
	if cfg.Has(RoleTrigger) {
		cfg.Trigger = Trigger{
			Addr:            r.addr("TRIGGER_ADDR", "127.0.0.1:8081"),
			DatabaseURL:     r.requiredSecret("TRIGGER_DATABASE_URL"),
			DefaultRedirect: r.redirect("TRIGGER_DEFAULT_REDIRECT", cfg.Environment),
		}
	}
	if cfg.Has(RoleDNS) {
		// A process with the console has read the zones already, checked
		// against its addresses; reading them again would report every
		// problem twice.
		var zones []string
		switch {
		case !cfg.Has(RoleConsole):
			zones = r.zones("DNS_ZONES", true)
		case r.get("DNS_ZONES") == "":
			r.fail("%sDNS_ZONES is required", prefix)
		default:
			zones = cfg.Console.DNSZones
		}
		cfg.DNS = DNS{
			Addr:             r.addr("DNS_ADDR", "127.0.0.1:8053"),
			DatabaseURL:      r.requiredSecret("DNS_DATABASE_URL"),
			DatabaseMaxConns: r.integer("DNS_DATABASE_MAX_CONNS", 10, 1, maxDNSDatabaseConns),
			Zones:            zones,
			Nameservers:      r.nameservers("DNS_NAMESERVERS", zones),
			AnswerIPv4:       r.answerAddr("DNS_ANSWER_IPV4", false),
			AnswerIPv6:       r.answerAddr("DNS_ANSWER_IPV6", true),
			TTL:              r.ttl("DNS_TTL"),
		}
	}
	if cfg.Has(RoleWorker) {
		consoleURL := cfg.Console.URL
		if !cfg.Has(RoleConsole) {
			consoleURL = r.consoleURL("CONSOLE_URL", cfg.Environment, defaultConsoleAddr)
		}
		cfg.Worker = Worker{
			DatabaseURL:         r.requiredSecret("WORKER_DATABASE_URL"),
			Concurrency:         r.integer("WORKER_CONCURRENCY", 4, 1, maxWorkerConcurrency),
			DeliveryConcurrency: r.integer("WORKER_DELIVERY_CONCURRENCY", 4, 1, maxWorkerConcurrency),
			ConsoleURL:          consoleURL,
		}
	}
	// The console encrypts the secrets of second factors and alert channels,
	// and the worker decrypts the latter; both check the targets of channels.
	if cfg.Has(RoleConsole) || cfg.Has(RoleWorker) {
		cfg.EncryptionKeys = r.keyring("ENCRYPTION_KEYS")
		cfg.AlertingAllowedNetworks = r.prefixes("ALERTING_ALLOWED_NETWORKS")
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

// integer reads a whole number within [lowest, highest].
func (r *reader) integer(name string, fallback, lowest, highest int) int {
	value := r.get(name)
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	switch {
	case err != nil:
		r.fail("%s%s: %q is not a whole number", prefix, name, value)
	case n < lowest || n > highest:
		r.fail("%s%s: must be between %d and %d, got %d", prefix, name, lowest, highest, n)
	default:
		return n
	}
	return fallback
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

// redirect reads the default target of the trigger. It follows the rules of the
// redirect target of a honeytoken, and must use https outside development. It
// has no default: a target built into Nyktus would be the same in every
// installation and identify the trigger as Nyktus.
func (r *reader) redirect(name string, env Environment) string {
	value := r.get(name)
	switch {
	case value == "":
		r.fail("%s%s is required", prefix, name)
	case honeytoken.ValidateRedirectURL(value) != nil:
		r.fail("%s%s: must be an http or https URL of up to %d printable ASCII characters whose host is a name, not an IP address, without user information",
			prefix, name, honeytoken.MaxRedirectURLLength)
	case !strings.HasPrefix(value, "https://") && env != Development:
		r.fail("%s%s: must start with https:// (http:// is allowed in development only)", prefix, name)
	default:
		return value
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

// zones reads the zones of the DNS role. A zone must not contain another, and
// must not hold the host of one of the given URLs: Nyktus would answer that
// host itself, and a DNS honeytoken would name the console or the trigger.
// A zone below such a host is allowed.
func (r *reader) zones(name string, required bool, urls ...string) []string {
	entries := r.list(name)
	if len(entries) == 0 {
		if required {
			r.fail("%s%s is required", prefix, name)
		}
		return nil
	}
	zones := make([]string, 0, len(entries))
	for _, entry := range entries {
		zone, err := parseDomainName(entry)
		if err != nil {
			r.fail("%s%s: %w", prefix, name, err)
			continue
		}
		if len(zone) > maxZoneLength {
			r.fail("%s%s: %q is longer than %d characters", prefix, name, entry, maxZoneLength)
			continue
		}
		if i := slices.IndexFunc(zones, func(z string) bool { return inZone(z, zone) || inZone(zone, z) }); i >= 0 {
			r.fail("%s%s: %q and %q overlap; a zone must not contain another", prefix, name, zones[i], zone)
			continue
		}
		zones = append(zones, zone)
	}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if raw == "" || err != nil {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		for _, zone := range zones {
			if inZone(host, zone) {
				r.fail("%s%s: %q contains %s, the host of %s; choose a zone that holds neither the console nor the trigger",
					prefix, name, zone, host, raw)
			}
		}
	}
	return zones
}

// nameservers reads the name servers of the zones. They must lie outside the
// zones: a name server inside would need an address record in the zone, and
// the DNS role answers every name of its zones in the same way.
func (r *reader) nameservers(name string, zones []string) []string {
	entries := r.list(name)
	switch {
	case len(entries) == 0:
		r.fail("%s%s is required", prefix, name)
		return nil
	case len(entries) > maxNameservers:
		r.fail("%s%s: at most %d name servers", prefix, name, maxNameservers)
		return nil
	}
	servers := make([]string, 0, len(entries))
	for _, entry := range entries {
		server, err := parseDomainName(entry)
		if err != nil {
			r.fail("%s%s: %w", prefix, name, err)
			continue
		}
		if i := slices.IndexFunc(zones, func(z string) bool { return inZone(server, z) }); i >= 0 {
			r.fail("%s%s: %q lies in the zone %q; name servers must lie outside the zones", prefix, name, server, zones[i])
			continue
		}
		if !slices.Contains(servers, server) {
			servers = append(servers, server)
		}
	}
	return servers
}

// answerAddr reads an optional address of one family with which every name of
// the zones resolves. There is no default: an address built into Nyktus would
// be the same in every installation and identify its name servers.
func (r *reader) answerAddr(name string, ipv6 bool) netip.Addr {
	value := r.get(name)
	if value == "" {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(value)
	switch {
	case err != nil || addr.Zone() != "":
		r.fail("%s%s: %q is not an IP address", prefix, name, value)
	case ipv6 && (!addr.Is6() || addr.Is4In6()):
		r.fail("%s%s: %q is not an IPv6 address", prefix, name, value)
	case !ipv6 && !addr.Is4():
		r.fail("%s%s: %q is not an IPv4 address", prefix, name, value)
	default:
		return addr
	}
	return netip.Addr{}
}

// ttl reads the time to live of DNS answers in whole seconds. Shorter times let
// more repeated lookups through the caches of resolvers.
func (r *reader) ttl(name string) time.Duration {
	d := r.duration(name, time.Minute, 0, maxDNSTTL)
	if d%time.Second != 0 {
		r.fail("%s%s: must be whole seconds, got %v", prefix, name, d)
		return time.Minute
	}
	return d
}

// parseDomainName returns a host name in lower case without a trailing dot. It
// accepts letters, digits and hyphens in labels of up to 63 characters, at
// least two labels, and no address.
func parseDomainName(s string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(s, "."))
	labels := strings.Split(name, ".")
	if len(name) > 253 || len(labels) < 2 {
		return "", fmt.Errorf("%q is not a domain name with at least two labels", s)
	}
	for _, label := range labels {
		if !validLabel(label) {
			return "", fmt.Errorf("%q is not a domain name: labels consist of 1 to 63 letters, digits and hyphens, without a hyphen at either end", s)
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", fmt.Errorf("%q is an address, not a domain name", s)
	}
	return name, nil
}

func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := range len(label) {
		if c := label[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// inZone reports whether name is zone or lies below it. Both are in lower case
// without a trailing dot.
func inZone(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}
