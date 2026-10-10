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
	"os"
	"slices"
	"strings"

	"nyktus.org/nyktus/internal/platform/logging"
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
	Addr        string
	DatabaseURL Secret
}

// Serve is the configuration of the serve command.
type Serve struct {
	Common
	Roles   []Role
	Console Console
}

// Has reports whether role is enabled.
func (c Serve) Has(role Role) bool { return slices.Contains(c.Roles, role) }

// Migrate is the configuration of the migrate command.
type Migrate struct {
	Common
	DatabaseURL Secret
}

// LoadServe reads the configuration for the given roles. Settings of roles that are
// not enabled are neither read nor required.
func LoadServe(src Source, roles []Role) (Serve, error) {
	r := reader{src: src}
	cfg := Serve{Common: r.common(), Roles: roles}
	if cfg.Has(RoleConsole) {
		cfg.Console = Console{
			Addr:        r.addr("CONSOLE_ADDR", "127.0.0.1:8080"),
			DatabaseURL: r.requiredSecret("CONSOLE_DATABASE_URL"),
		}
	}
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
