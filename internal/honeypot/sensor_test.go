// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeypot_test

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nyktus.org/nyktus/internal/auth/token"
	"nyktus.org/nyktus/internal/honeypot"
	"nyktus.org/nyktus/internal/metrics"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
	"nyktus.org/nyktus/internal/trigger"
)

// The trigger does not import the console, so the two sides agree on the
// secret by construction of the hash alone, and a test compares them: the hash
// that the trigger computes is the hash that the console stores.
func TestSecretHash_AgreesWithTheConsole(t *testing.T) {
	t.Parallel()

	secret, err := token.New()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := trigger.SecretHash(secret), token.Hash(secret); !slices.Equal(got, want) {
		t.Errorf("trigger.SecretHash() = %x, want %x", got, want)
	}
}

// A secret that the console created reaches its honeypot at the trigger, with
// the database role of the trigger, and a replaced secret no longer does.
func TestSecret_CreatedByTheConsoleWorksAtTheTrigger(t *testing.T) {
	t.Parallel()
	ownerURL, consoleURL := schematest.Console(t)
	_, triggerURL := dbtest.Role(t, ownerURL, "trigger", "IN ROLE "+pgx.Identifier{schematest.TriggerRole}.Sanitize())
	owner := schematest.Open(t, ownerURL)
	console := honeypot.NewStore(schematest.Open(t, consoleURL), secretboxtest.Keyring(t))
	store := trigger.NewStore(schematest.Open(t, triggerURL))

	c, err := console.Create(t.Context(), honeypot.Spec{Service: honeypot.ServiceSSH, Name: "p", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := store.RecordHeartbeat(t.Context(), trigger.SecretHash(string(c.Secret)), trigger.Heartbeat{SensorVersion: "0.1.0"})
	if err != nil || res.Outcome != trigger.ReportRecorded || res.HoneypotID != c.ID || res.Service != "ssh" {
		t.Fatalf("RecordHeartbeat() = %+v, %v; want the honeypot %s", res, err, c.ID)
	}
	got, err := console.Get(t.Context(), c.ID)
	if err != nil || got.Status != honeypot.StatusOnline || got.SensorVersion == nil || *got.SensorVersion != "0.1.0" {
		t.Errorf("Get() = %+v, %v; want it online with the version of the sensor", got, err)
	}

	replaced, err := console.ReplaceSecret(t.Context(), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	res, err = store.RecordHeartbeat(t.Context(), trigger.SecretHash(string(c.Secret)), trigger.Heartbeat{})
	if err != nil || res.Outcome != trigger.ReportUnknown {
		t.Errorf("RecordHeartbeat(old secret) = %+v, %v; want unknown", res, err)
	}
	res, err = store.RecordHeartbeat(t.Context(), trigger.SecretHash(string(replaced.Secret)), trigger.Heartbeat{})
	if err != nil || res.Outcome != trigger.ReportRecorded {
		t.Errorf("RecordHeartbeat(new secret) = %+v, %v; want recorded", res, err)
	}
	var events int
	if err := owner.QueryRow(t.Context(), "SELECT count(*) FROM events").Scan(&events); err != nil || events != 0 {
		t.Errorf("%d events after heartbeats, %v; want none", events, err)
	}
}

// The Go table of the techniques of a kind of event, the database function that
// applies them, and the services of the honeypots agree: every pair of service
// and event type that Go knows is stored with exactly these techniques, and
// every other pair is refused. A honeypot's own techniques follow them.
func TestKindTechniques_AgreeWithTheFunction(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)

	session := 0
	for _, service := range honeypot.Services {
		c := create(t, d, honeypot.Spec{Service: service, Name: "p", Enabled: true, Techniques: []string{"T1078"}})
		hash := token.Hash(string(c.Secret))
		for _, event := range trigger.EventTypes {
			var base, filter *string
			attempts, toolCalls := `[]`, `[]`
			switch event {
			case trigger.EventConnection:
				// Nothing beyond the connection.
			case trigger.EventLoginAttempt:
				attempts = `[{"username":"u"}]`
			case trigger.EventDirectoryQuery:
				base, filter = ptr("dc=example"), ptr("(cn=*)")
			case trigger.EventToolCall:
				toolCalls = `[{"tool_name":"t","arguments":"{}"}]`
			}
			session++
			id := fmt.Sprintf("%032x", session)
			var outcome string
			err := d.owner.QueryRow(t.Context(), `
SELECT outcome FROM public.record_honeypot_session($1, $2, interval '0', 0, '192.0.2.1', 22, $3, NULL, NULL, NULL, $4, $5, $6::jsonb, $7::jsonb)`,
				hash, id, string(event), base, filter, attempts, toolCalls).Scan(&outcome)
			if err != nil {
				t.Fatalf("%s %s: %v", service, event, err)
			}
			want := trigger.KindTechniques(string(service), event)
			if want == nil {
				if outcome != "invalid" {
					t.Errorf("%s %s: outcome = %s, want invalid, as Go knows no such event", service, event, outcome)
				}
				continue
			}
			var techniques []string
			err = d.owner.QueryRow(t.Context(), `SELECT techniques FROM events WHERE sensor_session_id = $1`, id).Scan(&techniques)
			want = append(want, "T1078")
			if err != nil || outcome != "recorded" || !slices.Equal(techniques, want) {
				t.Errorf("%s %s: outcome = %s with techniques %v, %v; want recorded with %v", service, event, outcome, techniques, err, want)
			}
		}
	}
}

// The status that the console shows and the metric that the monitoring reads
// come from one definition in the database, and both follow OfflineAfter at its
// edge.
func TestStatus_ConsoleAndMetricsShareTheBoundary(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)

	// The margins are seconds, not the time that the test needs between
	// writing a report and reading the status.
	const margin = 5 * time.Second
	tests := []struct {
		name string
		age  *time.Duration
		want honeypot.Status
	}{
		{"never reported", nil, honeypot.StatusNever},
		{"just now", ptr(time.Duration(0)), honeypot.StatusOnline},
		{"before the boundary", ptr(honeypot.OfflineAfter - margin), honeypot.StatusOnline},
		{"at the boundary", ptr(honeypot.OfflineAfter), honeypot.StatusOffline},
		{"after the boundary", ptr(honeypot.OfflineAfter + margin), honeypot.StatusOffline},
	}
	wantCounts := map[honeypot.Status]int{}
	for _, tt := range tests {
		c := create(t, d, honeypot.Spec{Service: honeypot.ServiceTelnet, Name: "p"})
		if tt.age != nil {
			setLastSeen(t, d, c.ID, *tt.age)
		}
		wantCounts[tt.want]++
		got, err := honeypot.NewStore(d.console, nil).Get(t.Context(), c.ID)
		if err != nil || got.Status != tt.want {
			t.Errorf("%s: Get() status = %q, %v; want %q", tt.name, got.Status, err, tt.want)
		}
	}

	srv := httptest.NewServer(metrics.Handler(slog.New(slog.DiscardHandler), d.console))
	defer srv.Close()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range honeypot.Statuses {
		if line := fmt.Sprintf("nyktus_honeypots{status=%q} %d\n", status, wantCounts[status]); !strings.Contains(string(body), line) {
			t.Errorf("metrics lack %q:\n%s", line, body)
		}
	}
}

// The statuses of the code are the labels of the metric, and a honeypot of a
// kind that the code does not know is not counted in silence.
func TestStatuses_AreTheLabelsOfTheMetric(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)

	rows, err := d.console.Query(t.Context(), `SELECT label FROM public.read_metrics() WHERE metric = 'honeypots' ORDER BY label`)
	if err != nil {
		t.Fatal(err)
	}
	labels, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, s := range honeypot.Statuses {
		want = append(want, string(s))
	}
	slices.Sort(want)
	if !slices.Equal(labels, want) {
		t.Errorf("labels of nyktus_honeypots = %v, want %v", labels, want)
	}
}

// The role of the trigger finds a honeypot by the hash of its secret through
// its own function and reads no table, so it can read neither the hash nor the
// sealed secret.
func TestSealedSecret_IsUnreadableForTheTrigger(t *testing.T) {
	t.Parallel()
	ownerURL, _ := schematest.Console(t)
	_, triggerURL := dbtest.Role(t, ownerURL, "trigger", "IN ROLE "+pgx.Identifier{schematest.TriggerRole}.Sanitize())
	trigger := schematest.Open(t, triggerURL)

	for _, statement := range []string{
		"SELECT secret_sealed FROM honeypots",
		"SELECT secret_hash FROM honeypots",
		"INSERT INTO honeypots (service, name, severity, secret_hash, secret_sealed) VALUES ('ssh', 'p', 'low', sha256('a'), sha256('a'))",
		"UPDATE honeypots SET secret_sealed = sha256('a')",
	} {
		_, err := trigger.Exec(t.Context(), statement)
		var pgErr *pgconn.PgError
		// 42501 is insufficient_privilege.
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s: error = %v, want insufficient_privilege", statement, err)
		}
	}
}
