// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/platform/secretbox"
	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
	"nyktus.org/nyktus/internal/platform/ssrf"
)

const consoleURL = "https://nyktus.example.com"

type deliveryFixture struct {
	owner   *pgxpool.Pool
	console *pgxpool.Pool
	worker  *pgxpool.Pool
	keys    *secretbox.Keyring
	logs    *syncBuffer
}

// syncBuffer collects the log of a deliverer, which tests read while the
// deliverer may still write.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newDeliveryFixture(t *testing.T) deliveryFixture {
	t.Helper()
	ownerURL, workerURL := schematest.Worker(t)
	_, consoleURL := dbtest.Role(t, ownerURL, "console", "IN ROLE "+pgx.Identifier{schematest.ConsoleRole}.Sanitize())
	return deliveryFixture{
		owner:   schematest.Open(t, ownerURL),
		console: schematest.Open(t, consoleURL),
		worker:  schematest.Open(t, workerURL),
		keys:    secretboxtest.Keyring(t),
		logs:    &syncBuffer{},
	}
}

func (f deliveryFixture) deliverer(client Sender) *Deliverer {
	return NewDeliverer(DelivererOptions{
		Logger: slog.New(slog.NewJSONHandler(f.logs, nil)), DB: f.worker, Keys: f.keys, Client: client, ConsoleURL: consoleURL,
	})
}

// channel creates a channel with the console's role.
func (f deliveryFixture) channel(t *testing.T, spec Spec) Channel {
	t.Helper()
	var c Channel
	err := pgx.BeginFunc(t.Context(), f.console, func(tx pgx.Tx) error {
		var err error
		c, err = NewStore(tx, f.keys).Create(t.Context(), spec)
		return err
	})
	if err != nil {
		t.Fatalf("create channel %s: %v", spec.Name, err)
	}
	return c
}

// alert opens an incident with its alert as the owner and enqueues its
// deliveries with the worker's role, as the correlation does.
func (f deliveryFixture) alert(t *testing.T) string {
	t.Helper()
	var id string
	err := f.owner.QueryRow(t.Context(), `
INSERT INTO incidents (resource_type, resource_id, severity, techniques, first_event_at, last_event_at, resource_name)
VALUES ('honeytoken', gen_random_uuid(), 'medium', '{T1078}', clock_timestamp(), clock_timestamp(), 'Name')
RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(t.Context(), `INSERT INTO alerts (incident_id, severity, techniques) VALUES ($1, 'medium', '{T1078}')`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := Enqueue(t.Context(), f.worker, id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f deliveryFixture) delivery(t *testing.T, alertID, channelID string) Delivery {
	t.Helper()
	d, err := scanDelivery(f.owner.QueryRow(t.Context(), `SELECT `+deliveryColumns+` FROM alert_deliveries
WHERE alert_id IS NOT DISTINCT FROM $1 AND channel_id = $2`, alertID, channelID))
	if err != nil {
		t.Fatalf("read delivery: %v", err)
	}
	return d
}

// due makes every pending delivery due now, as if its backoff had passed.
func (f deliveryFixture) due(t *testing.T) {
	t.Helper()
	if _, err := f.owner.Exec(t.Context(), `UPDATE alert_deliveries SET not_before = clock_timestamp() - interval '1 second' WHERE status = 'pending'`); err != nil {
		t.Fatal(err)
	}
}

// waitSeconds returns the wait from the last attempt to the next.
func (f deliveryFixture) waitAfterLastAttempt(t *testing.T, id string) time.Duration {
	t.Helper()
	var d time.Duration
	if err := f.owner.QueryRow(t.Context(), `SELECT not_before - last_attempt_at FROM alert_deliveries WHERE id = $1`, id).Scan(&d); err != nil {
		t.Fatal(err)
	}
	return d
}

func process(t *testing.T, d *Deliverer) bool {
	t.Helper()
	found, err := d.Process(t.Context(), func() {})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	return found
}

// receiver is a test server that records the requests it receives and answers
// with status.
type receiver struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*http.Request
	bodies   [][]byte
	status   atomic.Int64
}

func newReceiver(t *testing.T, status int) *receiver {
	t.Helper()
	r := &receiver{}
	r.status.Store(int64(status))
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.requests = append(r.requests, req)
		r.bodies = append(r.bodies, body)
		r.mu.Unlock()
		if s := int(r.status.Load()); s == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "600")
			w.WriteHeader(s)
		} else {
			w.WriteHeader(s)
		}
		_, _ = w.Write([]byte("receiver says the token s3cr3t is wrong"))
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *receiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.requests)
}

func TestProcess_DeliversTheAlertToTheChannel(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	rcv := newReceiver(t, http.StatusNoContent)
	c := f.channel(t, Spec{
		Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: Secret(rcv.URL + "/hook?token=s3cr3t"),
		Header: &Header{Name: "Authorization", Value: "Bearer t0k3n"},
	})
	alertID := f.alert(t)
	d := f.deliverer(http.DefaultClient)

	if !process(t, d) {
		t.Fatal("no delivery was due")
	}
	if process(t, d) {
		t.Fatal("a second delivery was due")
	}
	if rcv.count() != 1 {
		t.Fatalf("requests = %d, want 1", rcv.count())
	}
	req := rcv.requests[0]
	if req.Method != http.MethodPost || req.URL.RawQuery != "token=s3cr3t" || req.Header.Get("Authorization") != "Bearer t0k3n" ||
		req.Header.Get("Content-Type") != "application/json" {
		t.Errorf("request %s %s, headers %v", req.Method, req.URL, req.Header)
	}
	var body struct {
		Version    int    `json:"version"`
		Type       string `json:"type"`
		DeliveryID string `json:"delivery_id"`
		Incident   struct {
			ID         string   `json:"id"`
			URL        string   `json:"url"`
			Severity   string   `json:"severity"`
			Techniques []string `json:"techniques"`
		} `json:"incident"`
	}
	if err := json.Unmarshal(rcv.bodies[0], &body); err != nil {
		t.Fatal(err)
	}
	got := f.delivery(t, alertID, c.ID)
	if body.Version != PayloadVersion || body.Type != "alert" || body.DeliveryID != got.ID || body.Incident.ID != alertID ||
		body.Incident.URL != consoleURL+"/incidents/"+alertID || body.Incident.Severity != "medium" ||
		len(body.Incident.Techniques) != 1 {
		t.Errorf("body = %s", rcv.bodies[0])
	}
	if got.Status != StatusDelivered || got.Attempts != 1 || got.DeliveredAt == nil || got.LastStatusCode == nil ||
		*got.LastStatusCode != http.StatusNoContent || got.LastError != nil || got.LastDurationMs == nil {
		t.Errorf("delivery = %+v", got)
	}
	if !strings.Contains(f.logs.String(), `"msg":"alerting: alert delivered"`) {
		t.Errorf("log = %s", f.logs)
	}
}

// A channel that fails waits for its backoff, while the others are delivered
// at once.
func TestProcess_FailingChannelDoesNotHoldUpOthers(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	broken := newReceiver(t, http.StatusServiceUnavailable)
	working := newReceiver(t, http.StatusOK)
	b := f.channel(t, Spec{Name: "a broken", Type: TypeWebhook, Enabled: true, URL: Secret(broken.URL)})
	w := f.channel(t, Spec{Name: "b working", Type: TypeWebhook, Enabled: true, URL: Secret(working.URL)})
	alertID := f.alert(t)
	d := f.deliverer(http.DefaultClient)

	for process(t, d) {
	}
	if got := f.delivery(t, alertID, w.ID); got.Status != StatusDelivered || working.count() != 1 {
		t.Errorf("working channel: %+v, %d requests", got, working.count())
	}
	got := f.delivery(t, alertID, b.ID)
	if got.Status != StatusPending || got.Attempts != 1 || *got.LastError != FailureHTTPStatus || *got.LastStatusCode != 503 {
		t.Errorf("broken channel: %+v", got)
	}
	if wait := f.waitAfterLastAttempt(t, got.ID); wait != Backoff(1) {
		t.Errorf("wait after the first failure = %v, want %v", wait, Backoff(1))
	}
}

// A delivery is attempted MaxAttempts times with a growing wait, then it is
// dead and attempted no more. Time passes by moving the stored times.
func TestProcess_RetriesWithBackoffThenDies(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	rcv := newReceiver(t, http.StatusInternalServerError)
	c := f.channel(t, Spec{Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: Secret(rcv.URL)})
	alertID := f.alert(t)
	d := f.deliverer(http.DefaultClient)

	for n := 1; n <= MaxAttempts; n++ {
		if !process(t, d) {
			t.Fatalf("attempt %d was not due", n)
		}
		got := f.delivery(t, alertID, c.ID)
		if got.Attempts != n {
			t.Fatalf("after attempt %d: attempts = %d", n, got.Attempts)
		}
		if n < MaxAttempts {
			if got.Status != StatusPending {
				t.Fatalf("after attempt %d: status %s", n, got.Status)
			}
			if wait := f.waitAfterLastAttempt(t, got.ID); wait != Backoff(n) {
				t.Errorf("wait after attempt %d = %v, want %v", n, wait, Backoff(n))
			}
			// Not due before its backoff has passed.
			if process(t, d) {
				t.Fatalf("attempt %d+1 was due before its backoff", n)
			}
			f.due(t)
		}
	}
	got := f.delivery(t, alertID, c.ID)
	if got.Status != StatusDead || rcv.count() != MaxAttempts {
		t.Errorf("after %d attempts: %+v, %d requests", MaxAttempts, got, rcv.count())
	}
	f.due(t)
	if process(t, d) {
		t.Error("a dead delivery was attempted again")
	}
	if !strings.Contains(f.logs.String(), `"msg":"alerting: delivery dead"`) ||
		!strings.Contains(f.logs.String(), `"msg":"alerting: delivery failed"`) {
		t.Errorf("log = %s", f.logs)
	}
}

func TestProcess_HonorsRetryAfter(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	rcv := newReceiver(t, http.StatusTooManyRequests)
	c := f.channel(t, Spec{Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: Secret(rcv.URL)})
	alertID := f.alert(t)

	process(t, f.deliverer(http.DefaultClient))
	got := f.delivery(t, alertID, c.ID)
	if got.Status != StatusPending || *got.LastStatusCode != http.StatusTooManyRequests {
		t.Fatalf("delivery = %+v", got)
	}
	if wait := f.waitAfterLastAttempt(t, got.ID); wait != 10*time.Minute {
		t.Errorf("wait = %v, want the 10 minutes of Retry-After", wait)
	}
}

func TestProcess_PermanentFailuresDieAtOnce(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	rcv := newReceiver(t, http.StatusForbidden)
	c := f.channel(t, Spec{Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: Secret(rcv.URL)})
	first := f.alert(t)
	process(t, f.deliverer(http.DefaultClient))
	if got := f.delivery(t, first, c.ID); got.Status != StatusDead || got.Attempts != 1 || *got.LastError != FailureHTTPStatus {
		t.Errorf("403: %+v", got)
	}

	// The guard refuses the loopback address of the test server.
	if _, err := f.owner.Exec(t.Context(), `UPDATE alert_channels SET enabled = false WHERE id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}
	g := f.channel(t, Spec{Name: "internal", Type: TypeWebhook, Enabled: true, URL: Secret(rcv.URL + "/x")})
	second := f.alert(t)
	process(t, f.deliverer(ssrf.New(ssrf.Options{AllowHTTP: true}).Client()))
	if got := f.delivery(t, second, g.ID); got.Status != StatusDead || got.Attempts != 1 || *got.LastError != FailureBlocked ||
		got.LastStatusCode != nil {
		t.Errorf("blocked: %+v", got)
	}
	if rcv.count() != 1 {
		t.Errorf("requests = %d, want 1: the guard sent nothing", rcv.count())
	}
}

// A channel that was disabled or deleted after the alert was raised receives
// nothing; a test of a disabled channel is still sent, once.
func TestProcess_CancelsDeliveriesOfDisabledChannels(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	rcv := newReceiver(t, http.StatusBadGateway)
	c := f.channel(t, Spec{Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: Secret(rcv.URL)})
	gone := f.channel(t, Spec{Name: "gone", Type: TypeWebhook, Enabled: true, URL: Secret(rcv.URL)})
	alertID := f.alert(t)
	if _, err := f.owner.Exec(t.Context(), `UPDATE alert_channels SET enabled = false WHERE id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(t.Context(), `DELETE FROM alert_channels WHERE id = $1`, gone.ID); err != nil {
		t.Fatal(err)
	}
	test, err := RequestTest(t.Context(), f.console, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	d := f.deliverer(http.DefaultClient)
	for process(t, d) {
	}
	for _, id := range []string{c.ID, gone.ID} {
		if got := f.delivery(t, alertID, id); got.Status != StatusCanceled || got.Attempts != 0 {
			t.Errorf("delivery to %s: %+v", id, got)
		}
	}
	got, err := GetDelivery(t.Context(), f.owner, test.ID)
	if err != nil || got.Status != StatusDead || got.Attempts != 1 || *got.LastStatusCode != http.StatusBadGateway {
		t.Errorf("test: %+v, %v", got, err)
	}
	if rcv.count() != 1 {
		t.Errorf("requests = %d, want only the test", rcv.count())
	}
	var body struct{ Type string }
	if err := json.Unmarshal(rcv.bodies[0], &body); err != nil || body.Type != "test" {
		t.Errorf("test body = %s", rcv.bodies[0])
	}
}

// Two workers that look for a delivery at the same time never send it twice:
// the first claims it, and it is not due again until its backoff passed, also
// while the request runs.
func TestProcess_ConcurrentWorkersSendOnce(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	arrived := make(chan struct{})
	release := make(chan struct{})
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		close(arrived)
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := f.channel(t, Spec{Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: Secret(srv.URL)})
	alertID := f.alert(t)

	done := make(chan error, 1)
	go func() {
		_, err := f.deliverer(http.DefaultClient).Process(t.Context(), func() {})
		done <- err
	}()
	<-arrived
	if process(t, f.deliverer(http.DefaultClient)) {
		t.Error("a second worker took the delivery while it was sent")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := f.delivery(t, alertID, c.ID); got.Status != StatusDelivered || requests.Load() != 1 {
		t.Errorf("delivery %+v after %d requests", got, requests.Load())
	}

	// An alert reaches each channel once, also if its deliveries are
	// enqueued twice.
	if n, err := Enqueue(t.Context(), f.worker, alertID); err != nil || n != 0 {
		t.Errorf("Enqueue again = %d, %v; want 0", n, err)
	}
}

// A worker that stops while a request runs lets the request end and records
// it, so that the alert is not sent again.
func TestProcess_StopLetsTheRequestEnd(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		cancel()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := f.channel(t, Spec{Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: Secret(srv.URL)})
	alertID := f.alert(t)

	jobCtx, jobCancel := context.WithTimeout(ctx, 20*time.Second)
	defer jobCancel()
	if _, err := f.deliverer(http.DefaultClient).Process(jobCtx, func() {}); err != nil {
		t.Fatal(err)
	}
	if got := f.delivery(t, alertID, c.ID); got.Status != StatusDelivered {
		t.Errorf("delivery = %+v", got)
	}
}

// The URL and the header value of a channel never reach the log, also when the
// request fails with an error that names the URL.
func TestProcess_NeverLogsSecrets(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	rcv := newReceiver(t, http.StatusUnauthorized)
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	for i, u := range []string{rcv.URL, closed.URL} {
		f.channel(t, Spec{
			Name: "channel " + string(rune('a'+i)), Type: TypeWebhook, Enabled: true,
			URL: Secret(u + "/hooks/s3cr3t-path?token=s3cr3t-query"), Header: &Header{Name: "X-Token", Value: "s3cr3t-header"},
		})
	}
	f.alert(t)
	d := f.deliverer(http.DefaultClient)
	for process(t, d) {
	}
	logs := f.logs.String()
	if logs == "" || strings.Contains(logs, "s3cr3t") {
		t.Errorf("log = %s", logs)
	}
	if !strings.Contains(logs, `"failure":"network"`) || !strings.Contains(logs, `"status_code":401`) {
		t.Errorf("log lacks the classes of the failures: %s", logs)
	}
}

// Secrets sealed with an older key are encrypted again with the current one
// when they are used, so that the old key can be retired.
func TestProcess_EncryptsSecretsWithTheCurrentKey(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	entry1, entry2 := secretboxtest.Entry(t, 1), secretboxtest.Entry(t, 2)
	old, err := secretbox.ParseKeyring(entry1)
	if err != nil {
		t.Fatal(err)
	}
	f.keys = old
	rcv := newReceiver(t, http.StatusOK)
	c := f.channel(t, Spec{
		Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: Secret(rcv.URL),
		Header: &Header{Name: "X-Token", Value: "t0k3n"},
	})
	f.alert(t)

	rotated, err := secretbox.ParseKeyring(entry2 + "," + entry1)
	if err != nil {
		t.Fatal(err)
	}
	f.keys = rotated
	if err := CheckKeys(t.Context(), f.worker, rotated); err != nil {
		t.Errorf("CheckKeys with the old key listed: %v", err)
	}
	process(t, f.deliverer(http.DefaultClient))
	var urlKey, headerKey int
	if err := f.owner.QueryRow(t.Context(), `SELECT get_byte(url, 0), get_byte(header_value, 0) FROM alert_channel_secrets WHERE channel_id = $1`, c.ID).
		Scan(&urlKey, &headerKey); err != nil {
		t.Fatal(err)
	}
	if urlKey != 2 || headerKey != 2 || rcv.count() != 1 {
		t.Errorf("keys %d, %d after delivery, %d requests; want 2, 2, 1", urlKey, headerKey, rcv.count())
	}

	only2, err := secretbox.ParseKeyring(entry2)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckKeys(t.Context(), f.worker, only2); err != nil {
		t.Errorf("CheckKeys after the rotation: %v", err)
	}
	if err := CheckKeys(t.Context(), f.worker, old); err == nil || !strings.Contains(err.Error(), "key ID 2") {
		t.Errorf("CheckKeys without the current key = %v, want an error naming key 2", err)
	}
}

// A delivery whose secrets cannot be decrypted, for example after the key was
// removed, is dead without a request.
func TestProcess_UnreadableSecretsAreDead(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	rcv := newReceiver(t, http.StatusOK)
	c := f.channel(t, Spec{Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: Secret(rcv.URL)})
	alertID := f.alert(t)
	// An earlier attempt left a status code and a duration, which describe
	// no request of the last attempt.
	if _, err := f.owner.Exec(t.Context(), `UPDATE alert_deliveries SET attempts = 1, last_attempt_at = clock_timestamp(), last_status_code = 503, last_duration_ms = 120, last_error = 'http_status'`); err != nil {
		t.Fatal(err)
	}
	f.keys = secretboxtest.Keyring(t)

	process(t, f.deliverer(http.DefaultClient))
	got := f.delivery(t, alertID, c.ID)
	if got.Status != StatusDead || *got.LastError != FailureInvalidChannel || got.Attempts != 2 || got.LastStatusCode != nil ||
		got.LastDurationMs != nil || rcv.count() != 0 {
		t.Errorf("delivery %+v after %d requests", got, rcv.count())
	}
	if n := strings.Count(f.logs.String(), `"level":"ERROR"`); n != 1 || !strings.Contains(f.logs.String(), `"msg":"alerting: delivery dead"`) {
		t.Errorf("log = %s, want one error", f.logs)
	}
}

// Every status and failure class that the code knows is accepted by the
// schema, written with the worker's role as the deliverer writes them.
func TestSchema_AcceptsEveryStatusAndFailure(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	f.channel(t, Spec{Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: hookURL})
	alertID := f.alert(t)
	var id string
	if err := f.owner.QueryRow(t.Context(), `SELECT id FROM alert_deliveries WHERE alert_id = $1`, alertID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	for _, failure := range Failures {
		_, err := f.worker.Exec(t.Context(), `
UPDATE alert_deliveries SET attempts = 1, last_attempt_at = clock_timestamp(), last_error = $2 WHERE id = $1`, id, failure)
		if err != nil {
			t.Errorf("failure %s: %v", failure, err)
		}
	}
	for _, status := range Statuses {
		_, err := f.worker.Exec(t.Context(), `
UPDATE alert_deliveries SET status = $2, delivered_at = CASE WHEN $2 = 'delivered' THEN clock_timestamp() END WHERE id = $1`,
			id, status)
		if err != nil {
			t.Errorf("status %s: %v", status, err)
		}
	}
	if _, err := f.worker.Exec(t.Context(), `UPDATE alert_deliveries SET attempts = $2 WHERE id = $1`, id, MaxAttempts); err != nil {
		t.Errorf("attempts %d: %v", MaxAttempts, err)
	}
}

func TestRequestTest_OnePendingPerChannel(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	c := f.channel(t, Spec{Name: "SOAR", Type: TypeWebhook, Enabled: false, URL: hookURL})

	d, err := RequestTest(t.Context(), f.console, c.ID)
	if err != nil || d.AlertID != nil || d.ChannelID != c.ID || d.ChannelName != "SOAR" || d.Status != StatusPending {
		t.Fatalf("RequestTest = %+v, %v", d, err)
	}
	if _, err := RequestTest(t.Context(), f.console, c.ID); !errors.Is(err, ErrTestPending) {
		t.Errorf("second test: error = %v, want ErrTestPending", err)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if _, err := RequestTest(t.Context(), f.console, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("RequestTest(%s) = %v, want ErrNotFound", id, err)
		}
	}
	// Once the test is sent, another may be requested.
	if _, err := f.owner.Exec(t.Context(), `UPDATE alert_deliveries SET status = 'dead', attempts = 1, last_attempt_at = clock_timestamp() WHERE id = $1`, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := RequestTest(t.Context(), f.console, c.ID); err != nil {
		t.Errorf("test after the first was sent: %v", err)
	}
}

func TestRetry_OnlyDeadDeliveriesOfAlerts(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	rcv := newReceiver(t, http.StatusBadRequest)
	c := f.channel(t, Spec{Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: Secret(rcv.URL)})
	alertID := f.alert(t)
	pending := f.delivery(t, alertID, c.ID)
	if _, err := Retry(t.Context(), f.console, pending.ID); !errors.Is(err, ErrNotDead) {
		t.Errorf("retry a pending delivery: error = %v, want ErrNotDead", err)
	}

	process(t, f.deliverer(http.DefaultClient))
	got, err := Retry(t.Context(), f.console, pending.ID)
	if err != nil || got.Status != StatusPending || got.Attempts != 0 || got.LastAttemptAt != nil || got.LastError != nil {
		t.Fatalf("retry a dead delivery = %+v, %v", got, err)
	}
	rcv.status.Store(http.StatusOK)
	process(t, f.deliverer(http.DefaultClient))
	if got := f.delivery(t, alertID, c.ID); got.Status != StatusDelivered || got.Attempts != 1 {
		t.Errorf("after the retry: %+v", got)
	}

	test, err := RequestTest(t.Context(), f.console, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	rcv.status.Store(http.StatusBadRequest)
	process(t, f.deliverer(http.DefaultClient))
	if _, err := Retry(t.Context(), f.console, test.ID); !errors.Is(err, ErrNotDead) {
		t.Errorf("retry a dead test: error = %v, want ErrNotDead", err)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if _, err := Retry(t.Context(), f.console, id); !errors.Is(err, ErrDeliveryNotFound) {
			t.Errorf("Retry(%s) = %v, want ErrDeliveryNotFound", id, err)
		}
	}
}

func TestIncidentDeliveries(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	for _, name := range []string{"b", "a"} {
		f.channel(t, Spec{Name: name, Type: TypeWebhook, Enabled: true, URL: hookURL})
	}
	f.channel(t, Spec{Name: "disabled", Type: TypeWebhook, Enabled: false, URL: hookURL})
	alertID := f.alert(t)

	list, err := IncidentDeliveries(t.Context(), f.console, alertID)
	if err != nil || len(list) != 2 || list[0].ChannelName != "a" || list[1].ChannelName != "b" {
		t.Errorf("deliveries = %+v, %v; want those of the enabled channels a and b", list, err)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if _, err := IncidentDeliveries(t.Context(), f.console, id); !errors.Is(err, ErrIncidentNotFound) {
			t.Errorf("IncidentDeliveries(%s) = %v, want ErrIncidentNotFound", id, err)
		}
	}
}

// A worker skips a delivery that another worker holds, instead of waiting
// for it or taking it as well.
func TestProcess_SkipsADeliveryThatAnotherWorkerHolds(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	rcv := newReceiver(t, http.StatusOK)
	f.channel(t, Spec{Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: Secret(rcv.URL)})
	f.alert(t)

	tx, err := f.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := tx.Exec(t.Context(), `SELECT id FROM alert_deliveries FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	found, err := f.deliverer(http.DefaultClient).Process(ctx, func() {})
	if found || err != nil || rcv.count() != 0 {
		t.Errorf("Process while another worker holds the delivery = %v, %v, %d requests; want nothing", found, err, rcv.count())
	}
}

// The outcome of an attempt never overwrites a later one, for example if the
// delivery was claimed again meanwhile.
func TestRecord_KeepsALaterAttempt(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	c := f.channel(t, Spec{Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: hookURL})
	alertID := f.alert(t)
	d := f.deliverer(http.DefaultClient)

	a, found, err := d.claim(t.Context())
	if err != nil || !found {
		t.Fatalf("claim = %v, %v", found, err)
	}
	if _, err := f.owner.Exec(t.Context(), `UPDATE alert_deliveries SET attempts = 2 WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	code := http.StatusOK
	if err := d.record(t.Context(), a, outcome{delivered: true, statusCode: &code}); err != nil {
		t.Fatal(err)
	}
	if got := f.delivery(t, alertID, c.ID); got.Status != StatusPending || got.Attempts != 2 {
		t.Errorf("delivery = %+v, want the later attempt untouched", got)
	}
	if !strings.Contains(f.logs.String(), `"msg":"alerting: attempt not recorded"`) {
		t.Errorf("log = %s", f.logs)
	}
}

// The worker refuses to start if a header of a channel was encrypted with a
// key that it lacks, also when its URL was not.
func TestCheckKeys_CoversHeaders(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	c := f.channel(t, Spec{
		Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: hookURL,
		Header: &Header{Name: "X-Token", Value: "t0k3n"},
	})
	if err := CheckKeys(t.Context(), f.worker, f.keys); err != nil {
		t.Fatalf("CheckKeys = %v", err)
	}
	if _, err := f.owner.Exec(t.Context(), `UPDATE alert_channel_secrets SET header_value = set_byte(header_value, 0, 9) WHERE channel_id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := CheckKeys(t.Context(), f.worker, f.keys); err == nil || !strings.Contains(err.Error(), "key ID 9") {
		t.Errorf("CheckKeys = %v, want an error naming key 9", err)
	}
}

// The claim locks the secrets of the channel, so that encrypting them again
// never overwrites a replacement that an administrator makes meanwhile.
func TestClaim_LocksTheSecretsOfTheChannel(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	c := f.channel(t, Spec{Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: hookURL})
	d := f.deliverer(http.DefaultClient)

	tx, err := f.worker.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	if _, ok, err := d.loadChannel(t.Context(), tx, c.ID, false); err != nil || !ok {
		t.Fatalf("loadChannel = %v, %v", ok, err)
	}
	_, err = f.owner.Exec(t.Context(), `SELECT FROM alert_channel_secrets WHERE channel_id = $1 FOR UPDATE NOWAIT`, c.ID)
	if !isLockNotAvailable(err) {
		t.Errorf("lock of the secrets from another transaction: error = %v, want lock_not_available", err)
	}
}

func isLockNotAvailable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "55P03"
}

// A delivery that cannot be claimed, for example because the database rejects
// the claim, is postponed, so that the deliveries behind it are still taken.
func TestProcess_FailingClaimDoesNotHoldUpTheQueue(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	rcv := newReceiver(t, http.StatusOK)
	a := f.channel(t, Spec{Name: "a", Type: TypeWebhook, Enabled: true, URL: Secret(rcv.URL)})
	b := f.channel(t, Spec{Name: "b", Type: TypeWebhook, Enabled: true, URL: Secret(rcv.URL)})
	alertID := f.alert(t)
	if _, err := f.owner.Exec(t.Context(), `ALTER TABLE alert_deliveries ADD CONSTRAINT alert_deliveries_reject CHECK (attempts = 0) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	d := f.deliverer(http.DefaultClient)

	claimed := []string{}
	for range 2 {
		found, err := d.Process(t.Context(), func() {})
		if !found || err == nil {
			t.Fatalf("Process = %v, %v; want a failed claim", found, err)
		}
		var id string
		if err := f.owner.QueryRow(t.Context(), `SELECT id FROM alert_deliveries WHERE not_before > clock_timestamp() AND id <> ALL($1)`, claimed).Scan(&id); err != nil {
			t.Fatalf("no newly postponed delivery: %v", err)
		}
		claimed = append(claimed, id)
	}
	if found, err := d.Process(t.Context(), func() {}); found || err != nil {
		t.Errorf("Process with every delivery postponed = %v, %v; want nothing", found, err)
	}
	for _, id := range []string{a.ID, b.ID} {
		if got := f.delivery(t, alertID, id); got.Status != StatusPending || got.Attempts != 0 {
			t.Errorf("postponed delivery = %+v, want pending without a counted attempt", got)
		}
	}

	if _, err := f.owner.Exec(t.Context(), `ALTER TABLE alert_deliveries DROP CONSTRAINT alert_deliveries_reject`); err != nil {
		t.Fatal(err)
	}
	f.due(t)
	for process(t, d) {
	}
	if rcv.count() != 2 {
		t.Errorf("requests = %d, want both deliveries", rcv.count())
	}
}

// A secret that decrypts but cannot be encrypted again, for example because
// the database rejects the write, postpones the delivery instead of killing it.
func TestProcess_FailedResealPostponesTheDelivery(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	entry1, entry2 := secretboxtest.Entry(t, 1), secretboxtest.Entry(t, 2)
	var err error
	if f.keys, err = secretbox.ParseKeyring(entry1); err != nil {
		t.Fatal(err)
	}
	rcv := newReceiver(t, http.StatusOK)
	c := f.channel(t, Spec{Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: Secret(rcv.URL)})
	alertID := f.alert(t)
	if f.keys, err = secretbox.ParseKeyring(entry2 + "," + entry1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(t.Context(), `ALTER TABLE alert_channel_secrets ADD CONSTRAINT alert_channel_secrets_reject CHECK (get_byte(url, 0) = 1) NOT VALID`); err != nil {
		t.Fatal(err)
	}

	if found, err := f.deliverer(http.DefaultClient).Process(t.Context(), func() {}); !found || err == nil {
		t.Fatalf("Process = %v, %v; want a failed claim", found, err)
	}
	if got := f.delivery(t, alertID, c.ID); got.Status != StatusPending || got.Attempts != 0 || rcv.count() != 0 {
		t.Errorf("delivery %+v after %d requests, want it postponed", got, rcv.count())
	}
}

// A claim that the stop of the worker breaks off leaves the delivery due, so
// that the next worker sends it at once. The claim waits for the lock of the
// secrets, which another transaction holds, when the worker stops.
func TestProcess_StopDuringTheClaimLeavesTheDeliveryDue(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	c := f.channel(t, Spec{Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: hookURL})
	alertID := f.alert(t)
	before := f.delivery(t, alertID, c.ID).NotBefore

	tx, err := f.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := tx.Exec(t.Context(), `SELECT FROM alert_channel_secrets FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := f.deliverer(http.DefaultClient).Process(ctx, func() { t.Error("claimed while stopped") })
		done <- err
	}()
	// Wait until the claim waits for the lock.
	for {
		var waiting bool
		err := f.owner.QueryRow(t.Context(), `
SELECT EXISTS (SELECT FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		// A pause between the queries spares the database that other tests
		// share.
		<-time.After(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("Process that was stopped during the claim succeeded")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := f.delivery(t, alertID, c.ID); !got.NotBefore.Equal(before) || got.Attempts != 0 {
		t.Errorf("delivery = %+v, want it due as before", got)
	}
}

func TestProcess_DeliversToSlackAndTeams(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	slack := newReceiver(t, http.StatusOK)
	teams := newReceiver(t, http.StatusAccepted)
	s := f.channel(t, Spec{Name: "Slack", Type: TypeSlack, Enabled: true, URL: Secret(slack.URL + "/services/T0/B0/x")})
	tm := f.channel(t, Spec{Name: "Teams", Type: TypeTeams, Enabled: true, URL: Secret(teams.URL + "/workflows/x")})
	alertID := f.alert(t)
	d := f.deliverer(http.DefaultClient)
	for process(t, d) {
	}
	for _, c := range []Channel{s, tm} {
		if got := f.delivery(t, alertID, c.ID); got.Status != StatusDelivered {
			t.Errorf("delivery to %s = %+v", c.Name, got)
		}
	}
	if slack.count() != 1 || !strings.Contains(string(slack.bodies[0]), `"blocks"`) {
		t.Errorf("Slack received %d requests: %s", slack.count(), slack.bodies)
	}
	if teams.count() != 1 || !strings.Contains(string(teams.bodies[0]), `"AdaptiveCard"`) {
		t.Errorf("Teams received %d requests: %s", teams.count(), teams.bodies)
	}
}

// The alert of an incident of a scenario names the scenario as its resource,
// in every format, with the worker's role, and nothing of the scenario but its
// identifier.
func TestLoadAlert_NamesTheScenarioOfAnIncident(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)

	var scenarioID, incidentID string
	if err := f.owner.QueryRow(t.Context(), `INSERT INTO scenarios (name, notes) VALUES ('Finance share', 'fs01') RETURNING id`).Scan(&scenarioID); err != nil {
		t.Fatal(err)
	}
	err := f.owner.QueryRow(t.Context(), `
INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at, resource_name)
VALUES ('scenario', $1, 'low', clock_timestamp(), clock_timestamp(), 'Name') RETURNING id`, scenarioID).Scan(&incidentID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(t.Context(), `INSERT INTO alerts (incident_id, severity) VALUES ($1, 'low')`, incidentID); err != nil {
		t.Fatal(err)
	}

	tx, err := f.worker.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	m, err := loadAlert(t.Context(), tx, incidentID)
	if err != nil || m.resourceType != "scenario" || m.resourceID != scenarioID {
		t.Fatalf("loadAlert() = %+v, %v; want the scenario %s", m, err, scenarioID)
	}

	d := Delivery{ID: "33333333-3333-4333-8333-333333333333", AlertID: &incidentID}
	for _, typ := range []Type{TypeWebhook, TypeSlack, TypeTeams} {
		body, _, err := format(typ, m, d, "https://nyktus.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "scenario") || !strings.Contains(string(body), scenarioID) ||
			strings.Contains(string(body), "Finance") || strings.Contains(string(body), "fs01") {
			t.Errorf("%s: body %s, want the scenario by its identifier only", typ, body)
		}
	}
	mail := emailMessage(m, d, []string{"soc@example.com"}, "https://nyktus.example.com")
	if !strings.Contains(mail.Body, "scenario "+scenarioID) {
		t.Errorf("mail body %q does not name the scenario", mail.Body)
	}
}

// The alert of an incident of a honeypot that stands alone names the honeypot
// as its resource, in every format, with the worker's role, and nothing of it
// but its identifier: neither its name, its notes nor anything that the
// attacker typed.
func TestLoadAlert_NamesTheHoneypotOfAnIncident(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)

	var honeypotID, incidentID string
	if err := f.owner.QueryRow(t.Context(), `
INSERT INTO honeypots (service, name, notes, severity, secret_hash, secret_sealed)
VALUES ('ssh', 'Jump host', 'rack4', 'high', sha256('x'), sha256('x')) RETURNING id`).Scan(&honeypotID); err != nil {
		t.Fatal(err)
	}
	err := f.owner.QueryRow(t.Context(), `
INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at, resource_name)
VALUES ('honeypot', $1, 'high', clock_timestamp(), clock_timestamp(), 'Name') RETURNING id`, honeypotID).Scan(&incidentID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(t.Context(), `INSERT INTO alerts (incident_id, severity) VALUES ($1, 'high')`, incidentID); err != nil {
		t.Fatal(err)
	}

	tx, err := f.worker.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	m, err := loadAlert(t.Context(), tx, incidentID)
	if err != nil || m.resourceType != "honeypot" || m.resourceID != honeypotID {
		t.Fatalf("loadAlert() = %+v, %v; want the honeypot %s", m, err, honeypotID)
	}

	d := Delivery{ID: "33333333-3333-4333-8333-333333333333", AlertID: &incidentID}
	for _, typ := range []Type{TypeWebhook, TypeSlack, TypeTeams} {
		body, _, err := format(typ, m, d, "https://nyktus.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "honeypot") || !strings.Contains(string(body), honeypotID) ||
			strings.Contains(string(body), "Jump") || strings.Contains(string(body), "rack4") {
			t.Errorf("%s: body %s, want the honeypot by its identifier only", typ, body)
		}
	}
	mail := emailMessage(m, d, []string{"soc@example.com"}, "https://nyktus.example.com")
	if !strings.Contains(mail.Body, "honeypot "+honeypotID) {
		t.Errorf("mail body %q does not name the honeypot", mail.Body)
	}
}

// The body of a POST request to a honeytoken may hold personal data, such as
// account names and addresses. The event keeps it for the console; no alert
// carries it, in any format, and neither does the log of the worker, which
// reads the events.
func TestProcess_CarriesNothingOfTheBodyOfAPost(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	const marker = "alice@corp.example"

	var resourceID, incidentID string
	if err := f.owner.QueryRow(t.Context(), `SELECT gen_random_uuid()`).Scan(&resourceID); err != nil {
		t.Fatal(err)
	}
	err := f.owner.QueryRow(t.Context(), `
INSERT INTO incidents (resource_type, resource_id, severity, techniques, first_event_at, last_event_at, resource_name)
VALUES ('honeytoken', $1, 'high', '{T1078}', clock_timestamp(), clock_timestamp(), 'Name') RETURNING id`, resourceID).Scan(&incidentID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(t.Context(), `
INSERT INTO events (resource_type, resource_id, honeytoken_type, techniques, severity, occurred_at, recorded_at, channel,
	client_ip, method, body, incident_id, resource_name)
VALUES ('honeytoken', $1, 'web_url', '{T1078}', 'high', clock_timestamp(), clock_timestamp(), 'http', '192.0.2.7', 'POST',
	'{"TargetUserName":"`+marker+`"}', $2, 'Name')`, resourceID, incidentID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(t.Context(), `INSERT INTO alerts (incident_id, severity, techniques) VALUES ($1, 'high', '{T1078}')`, incidentID); err != nil {
		t.Fatal(err)
	}

	tx, err := f.worker.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	m, err := loadAlert(t.Context(), tx, incidentID)
	if err != nil {
		t.Fatal(err)
	}
	d := Delivery{ID: "33333333-3333-4333-8333-333333333333", AlertID: &incidentID}
	for _, typ := range []Type{TypeWebhook, TypeSlack, TypeTeams} {
		body, _, err := format(typ, m, d, "https://nyktus.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "alice") || strings.Contains(string(body), "TargetUserName") {
			t.Errorf("%s: body %s, want nothing of the body of the request", typ, body)
		}
	}
	mail := emailMessage(m, d, []string{"soc@example.com"}, "https://nyktus.example.com")
	if strings.Contains(mail.Body, "alice") || strings.Contains(mail.Body, "TargetUserName") {
		t.Errorf("mail body %q holds the body of the request", mail.Body)
	}

	rcv := newReceiver(t, http.StatusNoContent)
	f.channel(t, Spec{Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: Secret(rcv.URL + "/hook")})
	if _, err := Enqueue(t.Context(), f.worker, incidentID); err != nil {
		t.Fatal(err)
	}
	if !process(t, f.deliverer(http.DefaultClient)) || rcv.count() != 1 {
		t.Fatalf("delivered %d requests, want 1", rcv.count())
	}
	if strings.Contains(string(rcv.bodies[0]), "alice") || strings.Contains(f.logs.String(), "alice") {
		t.Errorf("body %s, log %s: want nothing of the body of the request", rcv.bodies[0], f.logs)
	}
}
