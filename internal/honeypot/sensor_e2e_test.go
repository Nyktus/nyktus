// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeypot_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/honeypot"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
	"nyktus.org/nyktus/internal/trigger"
)

// buildSensor compiles the sensor, a module of its own, into a binary. The
// tests start the binary instead of importing the module, which the server
// does not depend on.
func buildSensor(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "nyktus-sensor")
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", out, "./cmd/nyktus-sensor") //nolint:gosec // G204: the arguments are constants and the output is a temporary directory of the test.
	cmd.Dir = "../../sensor"
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build the sensor: %v\n%s", err, b)
	}
	return out
}

// freePort returns a port that nothing listens on.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// eventually waits until check holds. The wait is for a state that another
// process reaches; it is bounded, and it orders nothing by its length.
func eventually(t *testing.T, what string, check func() bool) {
	t.Helper()
	deadline := time.After(30 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for !check() {
		select {
		case <-deadline:
			t.Fatalf("timeout waiting for %s", what)
		case <-tick.C:
		}
	}
}

// process is a running sensor.
type process struct {
	cmd *exec.Cmd

	mu    sync.Mutex
	lines []string
	done  chan error
}

func startSensor(t *testing.T, bin, configPath string, env []string) *process {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), bin, "run", "-config", configPath) //nolint:gosec // G204: bin is the binary that the test has built.
	cmd.Env = env
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &process{cmd: cmd, done: make(chan error, 1)}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			p.mu.Lock()
			p.lines = append(p.lines, sc.Text())
			p.mu.Unlock()
		}
	}()
	go func() {
		<-scanned
		p.done <- cmd.Wait()
	}()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return p
}

func (p *process) log() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.lines, "\n")
}

// stop asks the sensor to end, as an init system does, and returns its exit
// error.
func (p *process) stop(t *testing.T) error {
	t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-p.done:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("the sensor did not stop")
		return nil
	}
}

// A honeypot that the console created, a sensor that its entry configures, the
// trigger with its database: a session of an attacker becomes an event with
// its attempts, and a heartbeat makes the honeypot online.
func TestSensor_EndToEnd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// tls puts the trigger behind a certificate that only a private
		// authority signed, which the sensor trusts through SSL_CERT_FILE.
		tls bool
	}{
		{name: "plain HTTP in development"},
		{name: "TLS with a private authority", tls: true},
	}
	// The cases run one after the other: each takes a port that it finds free
	// and gives back, which two at the same moment could both find.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.tls && runtime.GOOS != "linux" {
				// Only Linux reads SSL_CERT_FILE; the system verifier of other
				// systems does not.
				t.Skip("SSL_CERT_FILE is honored on Linux only")
			}
			endToEnd(t, tt.tls)
		})
	}
}

// sensorEnv is a sensor in its own process, configured by the entry of a
// honeypot that the console created, and the trigger with its database behind it.
type sensorEnv struct {
	owner   *pgxpool.Pool
	console *honeypot.Store
	created honeypot.Created
	bin     string
	process *process
	port    int
}

// startEndToEnd creates a honeypot of the service, configures a sensor with the
// entry that the console shows, starts it and waits until the honeypot is
// online. usualPort is the port in that entry, which the test replaces by a free
// one. prepare writes the files that the entry names, next to the configuration.
func startEndToEnd(t *testing.T, service honeypot.Service, usualPort string, useTLS bool, prepare func(dir string, created honeypot.Created)) *sensorEnv {
	t.Helper()
	// The database comes first: without one the test is skipped, and nothing
	// is built.
	ownerURL, consoleURL := schematest.Console(t)
	bin := buildSensor(t)
	_, triggerURL := dbtest.Role(t, ownerURL, "trigger", "IN ROLE "+pgx.Identifier{schematest.TriggerRole}.Sanitize())
	owner := schematest.Open(t, ownerURL)
	console := honeypot.NewStore(schematest.Open(t, consoleURL), secretboxtest.Keyring(t))
	store := trigger.NewStore(schematest.Open(t, triggerURL))

	created, err := console.Create(t.Context(), honeypot.Spec{Service: service, Name: "Switch console", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	h := trigger.New(trigger.Options{
		Logger:          slog.New(slog.DiscardHandler),
		Recorder:        store,
		Reporter:        store,
		DefaultRedirect: "https://example.org/",
	})
	ctx, cancel := context.WithCancel(t.Context())
	var running sync.WaitGroup
	running.Go(func() { h.Run(ctx) })
	t.Cleanup(func() {
		cancel()
		running.Wait()
	})
	srv := httptest.NewUnstartedServer(h)
	env := []string{}
	environment := "development"
	if useTLS {
		srv.StartTLS()
		certFile := filepath.Join(t.TempDir(), "ca.pem")
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
		if err := os.WriteFile(certFile, pemBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		env = append(env, "SSL_CERT_FILE="+certFile)
		environment = "production"
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)

	// The entry is the one that the console shows, with a port that is free.
	port := freePort(t)
	entry := created.SensorConfig()
	listen := fmt.Sprintf("listen: \"127.0.0.1:%d\"", port)
	usual := fmt.Sprintf("listen: %q", usualPort)
	if !strings.Contains(entry, usual) {
		t.Fatalf("entry = %q, want the usual port %s", entry, usualPort)
	}
	entry = strings.Replace(entry, usual, listen, 1)
	data := fmt.Sprintf("environment: %s\ntrigger_url: %s\nhoneypots:\n%s", environment, srv.URL, entry)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "sensor.yaml")
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if prepare != nil {
		prepare(dir, created)
	}

	p := startSensor(t, bin, configPath, env)

	// The heartbeat at the start makes the honeypot online and tells its version.
	eventually(t, "the honeypot to be online", func() bool {
		got, err := console.Get(t.Context(), created.ID)
		return err == nil && got.Status == honeypot.StatusOnline && got.SensorVersion != nil
	})
	// The sensor reports the version that it prints, whatever the build is.
	printed, err := exec.CommandContext(t.Context(), bin, "version").Output() //nolint:gosec // G204: bin is the binary that the test has built.
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := console.Get(t.Context(), created.ID); *got.SensorVersion != strings.TrimSpace(string(printed)) {
		t.Errorf("sensor_version = %q, want %q, the version that the sensor prints", *got.SensorVersion, strings.TrimSpace(string(printed)))
	}
	return &sensorEnv{owner: owner, console: console, created: created, bin: bin, process: p, port: port}
}

func endToEnd(t *testing.T, useTLS bool) {
	t.Helper()
	env := startEndToEnd(t, honeypot.ServiceTelnet, ":23", useTLS, nil)
	owner, created, p, port := env.owner, env.created, env.process, env.port

	// An attacker tries a login.
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(conn)
	readUntil := func(s string) {
		t.Helper()
		var got []byte
		for !bytes.HasSuffix(got, []byte(s)) {
			b, err := r.ReadByte()
			if err != nil {
				t.Fatalf("read until %q: %v (got %q)", s, err, got)
			}
			got = append(got, b)
		}
	}
	readUntil("login: ")
	_, _ = io.WriteString(conn, "mallory-typed-this\r\n")
	readUntil("Password: ")
	_, _ = io.WriteString(conn, "hunter2-typed-this\r\n")
	readUntil("Login incorrect\r\nlogin: ")
	_ = conn.Close()

	var eventID string
	eventually(t, "the event of the session", func() bool {
		err := owner.QueryRow(t.Context(), `SELECT id FROM events WHERE resource_id = $1`, created.ID).Scan(&eventID)
		return err == nil
	})
	var (
		channel, service, eventType, sev string
		sensorPort                       int
		techniques                       []string
		clientIP                         string
	)
	err = owner.QueryRow(t.Context(), `
SELECT channel, sensor_service, sensor_event_type, severity, sensor_port, techniques, client_ip::text
FROM events WHERE id = $1`, eventID).Scan(&channel, &service, &eventType, &sev, &sensorPort, &techniques, &clientIP)
	if err != nil {
		t.Fatal(err)
	}
	if channel != "sensor" || service != "telnet" || eventType != "login_attempt" || sev != "medium" || sensorPort != port ||
		!slices.Equal(techniques, []string{"T1110"}) || !strings.HasPrefix(clientIP, "127.0.0.1") {
		t.Errorf("event = %s %s %s %s port %d %v from %s, want a login attempt at the honeypot", channel, service, eventType, sev, sensorPort, techniques, clientIP)
	}
	var user string
	var passwordLength *int
	if err := owner.QueryRow(t.Context(), `SELECT username, password_length FROM event_attempts WHERE event_id = $1`, eventID).Scan(&user, &passwordLength); err != nil {
		t.Fatal(err)
	}
	if user != "mallory-typed-this" || passwordLength == nil || *passwordLength != 18 {
		t.Errorf("attempt = %q with a password of %v bytes, want the login of the attacker", user, passwordLength)
	}

	// The password is nowhere: not in the event, not in its attempts.
	var stored string
	if err := owner.QueryRow(t.Context(), `
SELECT coalesce(string_agg(row_to_json(e)::text, ' '), '') || coalesce((SELECT string_agg(row_to_json(a)::text, ' ') FROM event_attempts a), '')
FROM events e`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "hunter2") {
		t.Errorf("the database holds the password: %s", stored)
	}

	if err := p.stop(t); err != nil {
		t.Errorf("the sensor ended with %v, want a clean exit", err)
	}
	logs := p.log()
	for _, forbidden := range []string{string(created.Secret), "mallory-typed-this", "hunter2"} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("the log of the sensor holds %q:\n%s", forbidden, logs)
		}
	}
	for _, want := range []string{"sensor: honeypot listening", "sensor: started", "sensor: stopped", created.ID} {
		if !strings.Contains(logs, want) {
			t.Errorf("the log of the sensor lacks %q:\n%s", want, logs)
		}
	}
}

var _ http.Handler = (*trigger.Handler)(nil)
