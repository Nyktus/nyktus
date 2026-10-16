// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package alerting

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"nyktus.org/nyktus/internal/platform/ssrf"
)

func TestBackoff_DoublesUpToAnHour(t *testing.T) {
	t.Parallel()

	want := []time.Duration{
		30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute,
		32 * time.Minute, time.Hour, time.Hour, time.Hour,
	}
	var total time.Duration
	for i, w := range want {
		if got := Backoff(i + 1); got != w {
			t.Errorf("Backoff(%d) = %v, want %v", i+1, got, w)
		}
		if i < MaxAttempts-1 {
			total += w
		}
	}
	// The last attempt comes about three hours after the first.
	if total < 3*time.Hour || total > 4*time.Hour {
		t.Errorf("time from the first to the last attempt = %v", total)
	}
	if got := Backoff(1000); got != MaxBackoff {
		t.Errorf("Backoff(1000) = %v, want %v", got, MaxBackoff)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	t.Parallel()

	wrap := func(err error) error {
		return fmt.Errorf("Post %q: %w", "https://hooks.example.com/secret", err)
	}
	// A status of 0 stands for an error without a response.
	tests := []struct {
		name      string
		status    int
		err       error
		delivered bool
		permanent bool
		failure   Failure
	}{
		{"200", 200, nil, true, false, ""},
		{"204", 204, nil, true, false, ""},
		{"redirect", 302, nil, false, true, FailureRedirect},
		{"bad request", 400, nil, false, true, FailureHTTPStatus},
		{"unauthorized", 401, nil, false, true, FailureHTTPStatus},
		{"not found", 404, nil, false, true, FailureHTTPStatus},
		{"request timeout", 408, nil, false, false, FailureHTTPStatus},
		{"too many requests", 429, nil, false, false, FailureHTTPStatus},
		{"server error", 500, nil, false, false, FailureHTTPStatus},
		{"unavailable", 503, nil, false, false, FailureHTTPStatus},
		{"blocked", 0, wrap(ssrf.ErrBlocked), false, true, FailureBlocked},
		{"invalid URL", 0, wrap(ssrf.ErrInvalidURL), false, true, FailureInvalidChannel},
		{"deadline", 0, wrap(context.DeadlineExceeded), false, false, FailureTimeout},
		{"network timeout", 0, wrap(timeoutError{}), false, false, FailureTimeout},
		{"refused", 0, wrap(&net.OpError{Op: "dial", Err: errors.New("connection refused")}), false, false, FailureNetwork},
		{"unknown authority", 0, wrap(x509.UnknownAuthorityError{}), false, false, FailureTLS},
		{"certificate verification", 0, wrap(&tls.CertificateVerificationError{Err: errors.New("expired")}), false, false, FailureTLS},
		{"wrong host", 0, wrap(x509.HostnameError{Host: "x"}), false, false, FailureTLS},
	}
	for _, tt := range tests {
		var resp *http.Response
		if tt.status != 0 {
			resp = &http.Response{StatusCode: tt.status, Header: http.Header{}, Body: http.NoBody}
		}
		o := classify(resp, tt.err)
		if o.delivered != tt.delivered || o.permanent != tt.permanent || (!o.delivered && o.failure != tt.failure) {
			t.Errorf("%s: outcome %+v, want delivered %t, permanent %t, failure %q", tt.name, o, tt.delivered, tt.permanent, tt.failure)
		}
		if tt.status != 0 && (o.statusCode == nil || *o.statusCode != tt.status) {
			t.Errorf("%s: status code %v, want %d", tt.name, o.statusCode, tt.status)
		}
	}
	for _, code := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		limited := &http.Response{StatusCode: code, Header: http.Header{"Retry-After": {"120"}}, Body: http.NoBody}
		if o := classify(limited, nil); o.retryAfter != 2*time.Minute {
			t.Errorf("%d with Retry-After: retryAfter = %v, want 2m", code, o.retryAfter)
		}
	}
}

func TestRetryAfter(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	tests := map[string]time.Duration{
		"":                              0,
		"90":                            90 * time.Second,
		"-5":                            0,
		"86400":                         MaxBackoff,
		"Thu, 15 Oct 2026 12:10:00 GMT": 10 * time.Minute,
		"Thu, 15 Oct 2026 11:00:00 GMT": 0,
		"Fri, 16 Oct 2026 12:00:00 GMT": MaxBackoff,
		"soon":                          0,
	}
	for v, want := range tests {
		if got := retryAfter(v, now); got != want {
			t.Errorf("retryAfter(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestNext(t *testing.T) {
	t.Parallel()

	transient := outcome{failure: FailureHTTPStatus}
	tests := []struct {
		name   string
		number int
		test   bool
		o      outcome
		status Status
		wait   time.Duration
	}{
		{"delivered", 1, false, outcome{delivered: true}, StatusDelivered, 0},
		{"first failure", 1, false, transient, StatusPending, 30 * time.Second},
		{"third failure", 3, false, transient, StatusPending, 2 * time.Minute},
		{"last failure", MaxAttempts, false, transient, StatusDead, 0},
		{"permanent failure", 1, false, outcome{permanent: true, failure: FailureBlocked}, StatusDead, 0},
		{"failed test", 1, true, transient, StatusDead, 0},
		{"delivered test", 1, true, outcome{delivered: true}, StatusDelivered, 0},
		{"receiver asks for longer", 1, false, outcome{failure: FailureHTTPStatus, retryAfter: 10 * time.Minute}, StatusPending, 10 * time.Minute},
		{"receiver asks for shorter", 4, false, outcome{failure: FailureHTTPStatus, retryAfter: time.Second}, StatusPending, 4 * time.Minute},
	}
	for _, tt := range tests {
		status, wait := next(tt.number, tt.test, tt.o)
		if status != tt.status || wait != tt.wait {
			t.Errorf("%s: next = %s, %v; want %s, %v", tt.name, status, wait, tt.status, tt.wait)
		}
	}
}

// The message of an alert holds the incident and nothing of the inventory or
// of the events, such as the client address.
func TestFormat_Webhook(t *testing.T) {
	t.Parallel()

	alertID := "11111111-1111-4111-8111-111111111111"
	m := message{
		incidentID: alertID, severity: "high", techniques: []string{"T1078"}, resourceType: "honeytoken",
		resourceID:   "22222222-2222-4222-8222-222222222222",
		openedAt:     time.Date(2026, 10, 15, 12, 0, 1, 0, time.FixedZone("CEST", 2*3600)),
		firstEventAt: time.Date(2026, 10, 15, 12, 0, 0, 0, time.FixedZone("CEST", 2*3600)),
	}
	d := Delivery{ID: "33333333-3333-4333-8333-333333333333", AlertID: &alertID}
	body, contentType, err := format(TypeWebhook, m, d, "https://nyktus.example.com")
	if err != nil || contentType != "application/json" {
		t.Fatalf("format = %v, %q", err, contentType)
	}
	want := `{"version":1,"type":"alert","delivery_id":"33333333-3333-4333-8333-333333333333",` +
		`"incident":{"id":"11111111-1111-4111-8111-111111111111",` +
		`"url":"https://nyktus.example.com/incidents/11111111-1111-4111-8111-111111111111",` +
		`"severity":"high","techniques":["T1078"],"resource_type":"honeytoken",` +
		`"resource_id":"22222222-2222-4222-8222-222222222222",` +
		`"opened_at":"2026-10-15T10:00:01Z","first_event_at":"2026-10-15T10:00:00Z"}}`
	if string(body) != want {
		t.Errorf("body =\n%s\nwant\n%s", body, want)
	}

	body, _, err = format(TypeWebhook, message{}, Delivery{ID: d.ID}, "https://nyktus.example.com")
	if err != nil || string(body) != `{"version":1,"type":"test","delivery_id":"33333333-3333-4333-8333-333333333333"}` {
		t.Errorf("test body = %s, %v", body, err)
	}

	var members map[string]any
	if err := json.Unmarshal(must(format(TypeWebhook, m, d, "https://c.example.com")), &members); err != nil {
		t.Fatal(err)
	}
	incident, _ := members["incident"].(map[string]any)
	if got := slices.Sorted(maps.Keys(incident)); !slices.Equal(got, []string{
		"first_event_at", "id", "opened_at", "resource_id", "resource_type", "severity", "techniques", "url",
	}) {
		t.Errorf("members of the incident = %v", got)
	}
}

func must(b []byte, _ string, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func chatFixture() (message, Delivery) {
	alertID := "11111111-1111-4111-8111-111111111111"
	m := message{
		incidentID: alertID, severity: "high", techniques: []string{"T1078", "T1213"}, resourceType: "honeytoken",
		resourceID: "22222222-2222-4222-8222-222222222222",
		openedAt:   time.Date(2026, 10, 15, 10, 0, 1, 0, time.UTC), firstEventAt: time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC),
	}
	return m, Delivery{ID: "33333333-3333-4333-8333-333333333333", AlertID: &alertID}
}

func TestFormat_Slack(t *testing.T) {
	t.Parallel()

	m, d := chatFixture()
	body, contentType, err := format(TypeSlack, m, d, "https://nyktus.example.com")
	if err != nil || contentType != "application/json" {
		t.Fatalf("format = %v, %q", err, contentType)
	}
	want := `{"blocks":[{"text":{"text":"Nyktus: incident opened","type":"plain_text"},"type":"header"},` +
		`{"fields":[{"text":"*Severity*\nhigh","type":"mrkdwn"},{"text":"*Techniques*\nT1078, T1213","type":"mrkdwn"},` +
		`{"text":"*Resource*\nhoneytoken 22222222-2222-4222-8222-222222222222","type":"mrkdwn"},` +
		`{"text":"*First event*\n2026-10-15T10:00:00Z","type":"mrkdwn"}],"type":"section"},` +
		`{"text":{"text":"\u003chttps://nyktus.example.com/incidents/11111111-1111-4111-8111-111111111111|Open the incident\u003e","type":"mrkdwn"},"type":"section"},` +
		`{"elements":[{"text":"Delivery 33333333-3333-4333-8333-333333333333","type":"mrkdwn"}],"type":"context"}],` +
		`"text":"Nyktus: incident opened: high"}`
	if string(body) != want {
		t.Errorf("body =\n%s\nwant\n%s", body, want)
	}

	body, _, err = format(TypeSlack, message{}, Delivery{ID: d.ID}, "https://nyktus.example.com")
	if err != nil || !strings.Contains(string(body), `"text":"Nyktus: test message"`) || strings.Contains(string(body), "incident") {
		t.Errorf("test body = %s, %v", body, err)
	}
}

func TestFormat_Teams(t *testing.T) {
	t.Parallel()

	m, d := chatFixture()
	body, contentType, err := format(TypeTeams, m, d, "https://nyktus.example.com")
	if err != nil || contentType != "application/json" {
		t.Fatalf("format = %v, %q", err, contentType)
	}
	want := `{"attachments":[{"content":{"actions":[{"title":"Open the incident","type":"Action.OpenUrl",` +
		`"url":"https://nyktus.example.com/incidents/11111111-1111-4111-8111-111111111111"}],` +
		`"body":[{"size":"Medium","text":"Nyktus: incident opened","type":"TextBlock","weight":"Bolder","wrap":true},` +
		`{"facts":[{"title":"Severity","value":"high"},{"title":"Techniques","value":"T1078, T1213"},` +
		`{"title":"Resource","value":"honeytoken 22222222-2222-4222-8222-222222222222"},` +
		`{"title":"First event","value":"2026-10-15T10:00:00Z"},{"title":"Delivery","value":"33333333-3333-4333-8333-333333333333"}],"type":"FactSet"}],` +
		`"type":"AdaptiveCard","version":"1.4"},"contentType":"application/vnd.microsoft.card.adaptive"}],"type":"message"}`
	if string(body) != want {
		t.Errorf("body =\n%s\nwant\n%s", body, want)
	}

	body, _, err = format(TypeTeams, message{}, Delivery{ID: d.ID}, "https://nyktus.example.com")
	if err != nil || !strings.Contains(string(body), `"text":"Nyktus: test message"`) || strings.Contains(string(body), "actions") {
		t.Errorf("test body = %s, %v", body, err)
	}
}

func TestSlackEscape(t *testing.T) {
	t.Parallel()

	if got := slackEscape("<!channel> & <https://x|y>"); got != "&lt;!channel&gt; &amp; &lt;https://x|y&gt;" {
		t.Errorf("slackEscape = %q", got)
	}
}

// Every type of channel has a format.
func TestFormat_CoversEveryType(t *testing.T) {
	t.Parallel()

	m, d := chatFixture()
	for _, typ := range Types {
		if _, _, err := format(typ, m, d, "https://nyktus.example.com"); err != nil {
			t.Errorf("format(%s) = %v", typ, err)
		}
	}
}
