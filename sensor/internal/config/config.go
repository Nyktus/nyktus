// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config reads and validates the configuration file of the sensor.
//
// The sensor reads one YAML file and nothing from its environment. The file is
// decoded into typed structs with unknown fields refused, so that a misspelled
// key is an error and a value such as no is the text it is, not a boolean.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/sensor/internal/secret"
)

// Limits of the file and of its fields.
const (
	maxFileSize    = 1 << 20
	maxSecretFile  = 256
	maxHoneypots   = 32
	maxBanner      = 256
	maxLoginPrompt = 64
	maxTriggerURL  = 512
	otherAccess    = 0o077
)

// Environment tells whether the sensor may report over plain HTTP.
type Environment string

// Environments.
const (
	Production  Environment = "production"
	Development Environment = "development"
)

// Service is the service that a honeypot emulates.
type Service string

// Services of honeypots. The server knows the same names.
const (
	Telnet Service = "telnet"
)

// Config is the configuration of the sensor.
type Config struct {
	Environment Environment `yaml:"environment"`
	LogLevel    string      `yaml:"log_level"`
	// TriggerURL is where reports go: the public address of the trigger.
	TriggerURL string     `yaml:"trigger_url"`
	Honeypots  []Honeypot `yaml:"honeypots"`
}

// Honeypot is one service on one listener.
type Honeypot struct {
	// ID is the identifier of the honeypot in the console. The sensor logs it
	// and sends nothing else with a report to name the honeypot.
	ID      string  `yaml:"id"`
	Service Service `yaml:"service"`
	// Listen is the address to listen on, such as ":23" or "127.0.0.1:2323".
	Listen string `yaml:"listen"`
	// Secret is the secret of the honeypot, from the file itself or from
	// SecretFile. Exactly one of them is set in the file.
	Secret     secret.Secret `yaml:"secret"`
	SecretFile string        `yaml:"secret_file"`
	// Banner is what the service says first. Nil means the default of the
	// service, an empty value no banner at all.
	Banner *string `yaml:"banner"`
	// LoginPrompt is the prompt for the user name; telnet only.
	LoginPrompt *string `yaml:"login_prompt"`
}

var (
	idPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	logLevels       = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	errNoSecret     = errors.New("set secret or secret_file")
	errBothSecrets  = errors.New("set secret or secret_file, not both")
	errSecretFormat = errors.New("the secret does not have the form of a secret: 43 characters of base64url")
)

// Load reads the file at path and returns the configuration, with the secrets
// read from their files. It refuses a configuration that holds a secret and a
// secret file when their group or other users can read or write them. The
// modes are those of Unix systems; a system that reports none, such as
// Windows, is not supported.
func Load(path string) (*Config, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the file.
	if err != nil {
		return nil, fmt.Errorf("open configuration: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat configuration: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("the configuration is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	cfg, err := decode(data)
	if err != nil {
		return nil, err
	}

	// Everything that is wrong is reported at once, not one problem for each
	// run.
	var problems []error
	if err := cfg.validate(); err != nil {
		problems = append(problems, err)
	}
	inline := false
	for i := range cfg.Honeypots {
		hp := &cfg.Honeypots[i]
		if hp.Secret != "" {
			inline = true
			continue
		}
		if hp.SecretFile == "" {
			continue
		}
		s, err := readSecretFile(resolve(filepath.Dir(path), hp.SecretFile))
		if err != nil {
			problems = append(problems, fmt.Errorf("honeypots[%d].secret_file: %w", i, err))
			continue
		}
		hp.Secret = s
	}
	if inline && info.Mode().Perm()&otherAccess != 0 {
		problems = append(problems, fmt.Errorf("the configuration holds a secret and its group or other users can access it: mode %04o, want 0600", info.Mode().Perm()))
	}
	if err := cfg.checkDistinctSecrets(); err != nil {
		problems = append(problems, err)
	}
	if err := errors.Join(problems...); err != nil {
		return nil, err
	}
	return cfg, nil
}

func resolve(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// readSecretFile reads the secret from a file that only its owner can read.
// The mode is taken from the opened file, so that nothing can change between
// the check and the read.
func readSecretFile(path string) (secret.Secret, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the file.
	if err != nil {
		return "", errors.New("cannot open the secret file")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("the secret file is not a regular file")
	}
	if info.Mode().Perm()&otherAccess != 0 {
		return "", fmt.Errorf("the group or other users can access the secret file: mode %04o, want 0600", info.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSecretFile+1))
	if err != nil {
		return "", errors.New("cannot read the secret file")
	}
	// Editors and "echo" end the line.
	s := string(bytes.TrimSpace(data))
	if len(data) > maxSecretFile || !secret.Valid(s) {
		return "", errSecretFormat
	}
	return secret.Secret(s), nil
}

// decode reads the YAML into the types, refusing what they do not have.
func decode(data []byte) (*Config, error) {
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("the configuration is larger than %d bytes", maxFileSize)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the configuration is empty")
		}
		return nil, fmt.Errorf("decode configuration: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("the configuration holds more than one YAML document")
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Environment == "" {
		c.Environment = Production
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	var problems []error
	add := func(format string, args ...any) { problems = append(problems, fmt.Errorf(format, args...)) }

	switch c.Environment {
	case Production, Development:
	default:
		add("environment: must be %q or %q", Production, Development)
	}
	if !logLevels[c.LogLevel] {
		add("log_level: must be debug, info, warn or error")
	}
	u, err := validateTriggerURL(c.TriggerURL, c.Environment)
	if err != nil {
		add("trigger_url: %v", err)
	} else {
		c.TriggerURL = u
	}

	switch n := len(c.Honeypots); {
	case n == 0:
		add("honeypots: at least one honeypot is required")
	case n > maxHoneypots:
		add("honeypots: at most %d honeypots", maxHoneypots)
	}
	ids := map[string]int{}
	for i := range c.Honeypots {
		hp := &c.Honeypots[i]
		for _, err := range hp.validate() {
			add("honeypots[%d].%v", i, err)
		}
		if prev, ok := ids[hp.ID]; ok && hp.ID != "" {
			add("honeypots[%d].id: the same id as honeypots[%d]", i, prev)
		}
		ids[hp.ID] = i
	}
	for i := range c.Honeypots {
		a, okA := parseListen(c.Honeypots[i].Listen)
		for j := range i {
			if b, okB := parseListen(c.Honeypots[j].Listen); okA && okB && a.overlaps(b) {
				add("honeypots[%d].listen: conflicts with honeypots[%d].listen", i, j)
			}
		}
	}
	return errors.Join(problems...)
}

// checkDistinctSecrets reports honeypots that share a secret, whether it stands
// in the file or in a secret file, so that the server can tell them apart. It
// ignores honeypots that have none yet.
func (c *Config) checkDistinctSecrets() error {
	var problems []error
	seen := map[secret.Secret]int{}
	for i, hp := range c.Honeypots {
		if hp.Secret == "" {
			continue
		}
		if prev, ok := seen[hp.Secret]; ok {
			problems = append(problems, fmt.Errorf("honeypots[%d].secret: the same secret as honeypots[%d]; every honeypot has its own", i, prev))
		}
		seen[hp.Secret] = i
	}
	return errors.Join(problems...)
}

// validate returns the problems of a honeypot, each starting with the name of
// its field.
func (hp *Honeypot) validate() []error {
	var problems []error
	add := func(format string, args ...any) { problems = append(problems, fmt.Errorf(format, args...)) }

	if !idPattern.MatchString(hp.ID) {
		add("id: must be the identifier of the honeypot in the console, a lowercase UUID")
	}
	switch hp.Service {
	case Telnet:
	case "":
		add("service: required")
	default:
		add("service: unknown service %q", string(hp.Service))
	}
	if err := validateListen(hp.Listen); err != nil {
		add("listen: %v", err)
	}
	switch {
	case hp.Secret != "" && hp.SecretFile != "":
		add("secret: %v", errBothSecrets)
	case hp.Secret == "" && hp.SecretFile == "":
		add("secret: %v", errNoSecret)
	case hp.Secret != "" && !secret.Valid(string(hp.Secret)):
		add("secret: %v", errSecretFormat)
	}
	if hp.Banner != nil {
		if err := validateText(*hp.Banner, maxBanner, true); err != nil {
			add("banner: %v", err)
		}
	}
	if hp.LoginPrompt != nil {
		if hp.Service != Telnet {
			add("login_prompt: only for telnet")
		} else if err := validateText(*hp.LoginPrompt, maxLoginPrompt, false); err != nil {
			add("login_prompt: %v", err)
		}
	}
	return problems
}

// validateText accepts printable ASCII, and line breaks and tabs where the
// text may have them. A byte of 0xFF would start a command of the Telnet
// protocol, and an escape could move the cursor of whoever connects.
func validateText(s string, maxLen int, multiline bool) error {
	if len(s) > maxLen {
		return fmt.Errorf("at most %d bytes", maxLen)
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 0x20 && c <= 0x7e:
		case multiline && (c == '\r' || c == '\n' || c == '\t'):
		default:
			if multiline {
				return errors.New("printable ASCII, line breaks and tabs only")
			}
			return errors.New("printable ASCII only")
		}
	}
	return nil
}

// portPattern is a port as the system writes it: digits without a sign or a
// leading zero, so that two spellings of one port are not taken for two ports.
var portPattern = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)

// listenAddr is a listen address that has passed validateListen.
type listenAddr struct {
	// host is the address, or the zero Addr for no host, which stands for every
	// address.
	host netip.Addr
	port string
}

// Network returns the network to listen on. An IPv4 address is listened on with
// tcp4, so that 0.0.0.0 takes IPv4 only, as the operator means; with "tcp" Go
// would take IPv6 too. No host, and an IPv6 address, use tcp, which takes both
// families for a wildcard.
func (hp Honeypot) Network() string {
	if a, ok := parseListen(hp.Listen); ok && a.host.Is4() {
		return "tcp4"
	}
	return "tcp"
}

// validateListen accepts "host:port" with an IP address or no host, and a port.
func validateListen(s string) error {
	if _, ok := parseListen(s); !ok {
		return errors.New("must be host:port or :port, with an IP address or no host and a port from 1 to 65535")
	}
	return nil
}

func parseListen(s string) (listenAddr, bool) {
	host, port, err := net.SplitHostPort(s)
	if err != nil || !portPattern.MatchString(port) {
		return listenAddr{}, false
	}
	if n, err := strconv.Atoi(port); err != nil || n > 65535 {
		return listenAddr{}, false
	}
	if host == "" {
		return listenAddr{port: port}, true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return listenAddr{}, false
	}
	return listenAddr{host: addr.Unmap(), port: port}, true
}

// overlaps reports whether the two cannot both be bound: the same port on the
// same address, on an address and on all addresses, or on an IPv4 address and
// on all IPv4 addresses. The wildcard of no host and "::" takes both families,
// "0.0.0.0" only IPv4, so that 0.0.0.0 and ::1 may share a port.
func (a listenAddr) overlaps(b listenAddr) bool {
	if a.port != b.port {
		return false
	}
	if a.dualStack() || b.dualStack() || a.host == b.host {
		return true
	}
	v4 := netip.IPv4Unspecified()
	return (a.host == v4 && b.host.Is4()) || (b.host == v4 && a.host.Is4())
}

func (a listenAddr) dualStack() bool {
	return !a.host.IsValid() || a.host == netip.IPv6Unspecified()
}

// validateTriggerURL returns the URL that reports go to. The trigger accepts
// reports at "/" only, and the certificate of an https address is always
// verified.
func validateTriggerURL(s string, env Environment) (string, error) {
	if s == "" {
		return "", errors.New("required")
	}
	if len(s) > maxTriggerURL {
		return "", fmt.Errorf("at most %d bytes", maxTriggerURL)
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return "", errors.New("printable ASCII without spaces only")
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return "", errors.New("must be an absolute URL such as https://trigger.example.com/")
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && env == Development:
	case u.Scheme == "http":
		return "", errors.New("https is required outside development: the secret travels in a header")
	default:
		return "", errors.New("must start with https://")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("must have no user information, query or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("must have no path: the trigger accepts reports at / only")
	}
	u.Path = "/"
	return u.String(), nil
}
