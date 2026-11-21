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
	"crypto/tls"
	"crypto/x509"
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
	"strings"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/sensor/internal/mcp"
	"nyktus.org/nyktus/sensor/internal/secret"
	"nyktus.org/nyktus/sensor/internal/smtp"
	"nyktus.org/nyktus/sensor/internal/ssh"
	"nyktus.org/nyktus/sensor/internal/tlscert"
)

// Limits of the file and of its fields.
const (
	maxFileSize   = 1 << 20
	maxSecretFile = 256
	maxHoneypots  = 32
	// maxListen is the number of addresses of a honeypot that listens on
	// several, and maxListeners the number of all addresses of a sensor, each of
	// which holds a socket and its own limits.
	maxListen    = 32
	maxListeners = 256
	maxBanner    = 256
	// maxSMTPBanner keeps the greeting of an SMTP server, with the longest
	// hostname, within the 512 bytes of a reply line (RFC 5321, section 4.5.3.1.5).
	maxSMTPBanner = 128
	// maxHostname is the longest name of a host in DNS (RFC 1035).
	maxHostname    = 253
	maxLoginPrompt = 64
	maxHostKeyFile = 8 << 10
	// maxCertFile is the longest certificate chain that is read.
	maxCertFile = 64 << 10
	// maxSSHVersion is the longest identification string that a server may
	// send: 255 bytes with the line ending (RFC 4253, section 4.2).
	maxSSHVersion = 253
	maxTriggerURL = 512
	otherAccess   = 0o077
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
	SSH      Service = "ssh"
	Telnet   Service = "telnet"
	Postgres Service = "postgres"
	LDAP     Service = "ldap"
	MCP      Service = "mcp"
	SMTP     Service = "smtp"
	TCP      Service = "tcp"
)

// Config is the configuration of the sensor.
type Config struct {
	Environment Environment `yaml:"environment"`
	LogLevel    string      `yaml:"log_level"`
	// TriggerURL is where reports go: the public address of the trigger.
	TriggerURL string     `yaml:"trigger_url"`
	Honeypots  []Honeypot `yaml:"honeypots"`
}

// Listen is the address or the addresses of a honeypot. The file holds one
// address as text and several as a list.
type Listen []string

// UnmarshalYAML reads an address or a list of addresses.
func (l *Listen) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var s string
		if err := n.Decode(&s); err != nil {
			return err
		}
		*l = Listen{s}
	case yaml.SequenceNode:
		var list []string
		if err := n.Decode(&list); err != nil {
			return err
		}
		*l = list
	default:
		return errors.New("must be an address or a list of addresses")
	}
	return nil
}

// Honeypot is one service on one or more listeners.
type Honeypot struct {
	// ID is the identifier of the honeypot in the console. The sensor logs it
	// and sends nothing else with a report to name the honeypot.
	ID      string  `yaml:"id"`
	Service Service `yaml:"service"`
	// Listen is the address to listen on, such as ":23" or "127.0.0.1:2323". A
	// tcp honeypot may name several, which share its secret and its status.
	Listen Listen `yaml:"listen"`
	// Secret is the secret of the honeypot, from the file itself or from
	// SecretFile. Exactly one of them is set in the file.
	Secret     secret.Secret `yaml:"secret"`
	SecretFile string        `yaml:"secret_file"`
	// Banner is what the service says first. Nil means the default of the
	// service; tcp has none and says nothing before the client does. An empty
	// value means no banner, which an SSH server cannot do: its first words are
	// its identification string. PostgreSQL, LDAP and MCP say nothing before a
	// client does, so they take none. For smtp it is the rest of the greeting
	// after the hostname and "ESMTP", one line, and has no default either.
	Banner *string `yaml:"banner"`
	// LoginPrompt is the prompt for the user name; telnet only.
	LoginPrompt *string `yaml:"login_prompt"`
	// HostKeyFile names the file with the host key; ssh only, and required
	// there. A key that changes with every start would identify the honeypot,
	// so the sensor never makes one.
	HostKeyFile string `yaml:"host_key_file"`
	// HostKey is the key read from HostKeyFile by Load.
	HostKey ssh.HostKey `yaml:"-"`
	// RSAHostKeyFile names the file with a second host key, an RSA key for
	// clients that know no other; ssh only, and optional.
	RSAHostKeyFile string `yaml:"rsa_host_key_file"`
	// RSAHostKey is the key read from RSAHostKeyFile by Load.
	RSAHostKey ssh.HostKey `yaml:"-"`
	// MCP is what an MCP honeypot presents; mcp only, and required there.
	MCP *mcp.Config `yaml:"mcp"`
	// Hostname is the name of an SMTP server in its greeting and its answer
	// to EHLO, and TLSMode how a client reaches TLS; smtp only, and required
	// there without a default, because a name that every installation shared
	// would identify the honeypot.
	Hostname string    `yaml:"hostname"`
	TLSMode  smtp.Mode `yaml:"tls_mode"`
	// TLSCertFile and TLSKeyFile name the certificate and its key; postgres,
	// mcp and smtp only, always both, optional for postgres and mcp and
	// required for smtp. The sensor never makes a certificate of its own: it
	// would identify the honeypot.
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	// TLSCertificate is what Load read from those two files.
	TLSCertificate *tlscert.Certificate `yaml:"-"`
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
	hostKeys := map[string]int{}
	for i := range cfg.Honeypots {
		hp := &cfg.Honeypots[i]
		// Only an SSH honeypot has a host key; validate refuses the field for any
		// other, and a file that nothing uses is not opened.
		if hp.Service == SSH && hp.HostKeyFile != "" {
			k, err := readHostKey(resolve(filepath.Dir(path), hp.HostKeyFile))
			if err != nil {
				problems = append(problems, fmt.Errorf("honeypots[%d].host_key_file: %w", i, err))
			}
			hp.HostKey = k
			// Two honeypots with one key show the same host key, and anyone
			// who looks can tie them together.
			if err == nil {
				id := string(k.PublicKey().Marshal())
				if prev, ok := hostKeys[id]; ok {
					problems = append(problems, fmt.Errorf("honeypots[%d].host_key_file: the same host key as honeypots[%d]; every honeypot has its own", i, prev))
				}
				hostKeys[id] = i
			}
		}
		if hp.Service == SSH && hp.RSAHostKeyFile != "" {
			k, err := readHostKeyWith(resolve(filepath.Dir(path), hp.RSAHostKeyFile), ssh.ParseRSAHostKey)
			if err != nil {
				problems = append(problems, fmt.Errorf("honeypots[%d].rsa_host_key_file: %w", i, err))
			}
			hp.RSAHostKey = k
			if err == nil {
				id := string(k.PublicKey().Marshal())
				if prev, ok := hostKeys[id]; ok {
					problems = append(problems, fmt.Errorf("honeypots[%d].rsa_host_key_file: the same host key as honeypots[%d]; every honeypot has its own", i, prev))
				}
				hostKeys[id] = i
			}
		}
		if hp.takesCertificate() && hp.TLSCertFile != "" && hp.TLSKeyFile != "" {
			cert, err := readCertificate(resolve(filepath.Dir(path), hp.TLSCertFile), resolve(filepath.Dir(path), hp.TLSKeyFile))
			if err != nil {
				problems = append(problems, fmt.Errorf("honeypots[%d].tls_cert_file: %w", i, err))
			}
			hp.TLSCertificate = cert
			// A client checks the name of the server against its certificate,
			// and one that does not match is a mark that a scanner can see.
			if err == nil && hp.Service == SMTP && validateHostname(hp.Hostname) == nil {
				if err := cert.Leaf.VerifyHostname(hp.Hostname); err != nil {
					problems = append(problems, fmt.Errorf("honeypots[%d].tls_cert_file: the certificate does not name the hostname %q in its subject alternative names", i, hp.Hostname))
				}
			}
		}
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

// readPrivateFile reads a file that holds a secret and that only its owner may
// access. It reads one byte more than limit, so that the caller can tell a file
// that is too large. what names the file in the errors. The mode is taken from
// the opened file, so that nothing can change between the check and the read.
func readPrivateFile(path, what string, limit int) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the file.
	if err != nil {
		return nil, fmt.Errorf("cannot open the %s", what)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("the %s is not a regular file", what)
	}
	if info.Mode().Perm()&otherAccess != 0 {
		return nil, fmt.Errorf("the group or other users can access the %s: mode %04o, want 0600", what, info.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read the %s", what)
	}
	return data, nil
}

// readSecretFile reads the secret from a file that only its owner can read.
func readSecretFile(path string) (secret.Secret, error) {
	data, err := readPrivateFile(path, "secret file", maxSecretFile)
	if err != nil {
		return "", err
	}
	// Editors and "echo" end the line.
	s := string(bytes.TrimSpace(data))
	if len(data) > maxSecretFile || !secret.Valid(s) {
		return "", errSecretFormat
	}
	return secret.Secret(s), nil
}

// readCertificate reads a certificate chain and its key. The key is held to the
// rules of a secret; the chain is public.
func readCertificate(certPath, keyPath string) (*tlscert.Certificate, error) {
	f, err := os.Open(certPath) //nolint:gosec // G304: the operator names the file.
	if err != nil {
		return nil, errors.New("cannot read the certificate file")
	}
	defer func() { _ = f.Close() }()
	chain, err := io.ReadAll(io.LimitReader(f, maxCertFile))
	if err != nil {
		return nil, errors.New("cannot read the certificate file")
	}
	key, err := readPrivateFile(keyPath, "key file of the certificate", maxHostKeyFile)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return nil, errors.New("the certificate and its key do not form a valid pair")
	}
	// X509KeyPair parses the leaf unless GODEBUG says otherwise, and the check
	// of the hostname needs it.
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, errors.New("cannot parse the certificate")
		}
	}
	return &tlscert.Certificate{Certificate: cert}, nil
}

// readHostKey reads the private key of an SSH honeypot from a file that only its
// owner can access.
func readHostKey(path string) (ssh.HostKey, error) {
	return readHostKeyWith(path, ssh.ParseHostKey)
}

func readHostKeyWith(path string, parse func([]byte) (ssh.HostKey, error)) (ssh.HostKey, error) {
	data, err := readPrivateFile(path, "host key file", maxHostKeyFile)
	if err != nil {
		return ssh.HostKey{}, err
	}
	if len(data) > maxHostKeyFile {
		return ssh.HostKey{}, fmt.Errorf("the host key file is larger than %d bytes", maxHostKeyFile)
	}
	return parse(data)
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
	// Every address of every honeypot, in the order of the file, so that a
	// conflict names the later of the two.
	type placed struct {
		addr   listenAddr
		honey  int
		listen int
	}
	var all []placed
	for i := range c.Honeypots {
		for k, s := range c.Honeypots[i].Listen {
			a, ok := parseListen(s)
			if !ok {
				continue
			}
			for _, b := range all {
				if a.overlaps(b.addr) {
					add("honeypots[%d].listen[%d]: conflicts with honeypots[%d].listen[%d]", i, k, b.honey, b.listen)
					break
				}
			}
			all = append(all, placed{a, i, k})
		}
	}
	if len(all) > maxListeners {
		add("honeypots: at most %d addresses to listen on in all", maxListeners)
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
	case Telnet, SSH, Postgres, LDAP, MCP, SMTP, TCP:
	case "":
		add("service: required")
	default:
		add("service: unknown service %q", string(hp.Service))
	}
	if n := len(hp.Listen); n == 0 {
		add("listen: required")
	} else {
		if n > maxListen {
			add("listen: at most %d addresses", maxListen)
		}
		if n > 1 && hp.Service != TCP {
			add("listen: only tcp listens on several addresses")
		}
	}
	for k, l := range hp.Listen {
		if err := validateListen(l); err != nil {
			add("listen[%d]: %v", k, err)
		}
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
		var err error
		switch hp.Service {
		case SSH:
			err = validateSSHVersion(*hp.Banner)
		case Postgres, LDAP, MCP:
			err = errors.New("only for ssh, telnet, smtp and tcp: the service says nothing before the client does")
		case SMTP:
			err = validateText(*hp.Banner, maxSMTPBanner, false)
		default:
			err = validateText(*hp.Banner, maxBanner, true)
		}
		if err != nil {
			add("banner: %v", err)
		}
	}
	switch {
	case hp.Service == SSH && hp.HostKeyFile == "":
		add("host_key_file: required for ssh: a host key that changes with every start would identify the honeypot")
	case hp.Service != SSH && hp.HostKeyFile != "":
		add("host_key_file: only for ssh")
	}
	switch {
	case !hp.takesCertificate() && (hp.TLSCertFile != "" || hp.TLSKeyFile != ""):
		add("tls_cert_file and tls_key_file: only for postgres, mcp and smtp")
	case (hp.TLSCertFile == "") != (hp.TLSKeyFile == ""):
		add("tls_cert_file and tls_key_file: set both or neither")
	case hp.Service == SMTP && hp.TLSCertFile == "":
		add("tls_cert_file and tls_key_file: required for smtp: a mail server without TLS looks like one that nobody uses, and the sensor never makes a certificate")
	}
	if hp.Service == SMTP {
		if err := validateHostname(hp.Hostname); err != nil {
			add("hostname: %v", err)
		}
		if !hp.TLSMode.Valid() {
			add("tls_mode: must be %q or %q", smtp.StartTLS, smtp.Implicit)
		}
	} else {
		if hp.Hostname != "" {
			add("hostname: only for smtp")
		}
		if hp.TLSMode != "" {
			add("tls_mode: only for smtp")
		}
	}
	if hp.Service != SSH && hp.RSAHostKeyFile != "" {
		add("rsa_host_key_file: only for ssh")
	}
	switch {
	case hp.Service == MCP && hp.MCP == nil:
		add("mcp: required for mcp: what every installation shared would identify the honeypot")
	case hp.Service == MCP:
		for _, err := range hp.MCP.Validate() {
			add("mcp.%v", err)
		}
	case hp.MCP != nil:
		add("mcp: only for mcp")
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

// takesCertificate reports whether the service of hp speaks TLS.
func (hp *Honeypot) takesCertificate() bool {
	return hp.Service == Postgres || hp.Service == MCP || hp.Service == SMTP
}

// validateHostname accepts a name of a host in DNS: labels of letters, digits
// and hyphens, which neither start nor end with a hyphen. There is no default,
// because a name that every installation shares would identify the honeypot.
func validateHostname(s string) error {
	err := fmt.Errorf("must be the name of the server, such as mail.example.com: labels of letters, digits and hyphens, at most %d bytes", maxHostname)
	if s == "" {
		return errors.New("required: a name that every installation shared would identify the honeypot")
	}
	if len(s) > maxHostname {
		return err
	}
	for label := range strings.SplitSeq(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return err
		}
		for i := range len(label) {
			if !hostnameByte(label[i]) {
				return err
			}
		}
	}
	return nil
}

// hostnameByte reports whether c may stand in a label of a hostname.
func hostnameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
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

// sshVersionPattern is the identification string of an SSH 2.0 server: the
// protocol version, a software version of printable characters without space
// or minus, and optional comments (RFC 4253, section 4.2).
var sshVersionPattern = regexp.MustCompile(`^SSH-2\.0-[!-,.-~]+( [ -~]*)?$`)

// validateSSHVersion accepts the identification string that an SSH honeypot
// sends first. The line ending is added by the protocol.
func validateSSHVersion(s string) error {
	if len(s) > maxSSHVersion || !sshVersionPattern.MatchString(s) {
		return fmt.Errorf("must be an identification string such as SSH-2.0-OpenSSH_9.2p1 of printable ASCII, at most %d bytes", maxSSHVersion)
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

// Network returns the network to listen on for an address. An IPv4 address
// is listened on with tcp4, so that 0.0.0.0 takes IPv4 only, as the operator
// means; with "tcp" Go would take IPv6 too. No host, and an IPv6 address, use
// tcp, which takes both families for a wildcard.
func Network(listen string) string {
	if a, ok := parseListen(listen); ok && a.host.Is4() {
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
