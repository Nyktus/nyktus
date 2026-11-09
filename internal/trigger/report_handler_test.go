// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package trigger

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testSecret has the form of the secret of a honeypot.
var testSecret = strings.Repeat("sEcRe7-_", 5) + "abc"

func bearer(secret string) http.Header {
	return http.Header{"Authorization": {"Bearer " + secret}}
}

func TestHandler_TestSecretHasTheForm(t *testing.T) {
	t.Parallel()
	if !isSecret(testSecret) {
		t.Fatalf("test secret %q has not the form of a secret", testSecret)
	}
}

// A sensor learns nothing from the answer: whatever became of a report, a
// client receives the answer to any other POST, byte for byte, as in the
// outcomes of a honeytoken. The test uses a real server, because a recorder
// does not show what net/http adds or removes.
func TestTrigger_ReportsAreAnsweredLikeEveryOtherPost(t *testing.T) {
	t.Parallel()

	session := golden(t, "session_ssh.json")
	heartbeat := golden(t, "heartbeat.json")

	serverFor := func(r *fakeReporter) *httptest.Server {
		srv, _ := newReportingServer(t, &fakeRecorder{}, r)
		return srv
	}
	want := fetch(t, serverFor(&fakeReporter{}), http.MethodPost, "/", nil, nil)
	if want.status != http.StatusOK || len(want.body) != 0 {
		t.Fatalf("the answer to POST / is %d with %d bytes, want 200 without a body", want.status, len(want.body))
	}
	// It is the answer to a POST to a trigger value as well.
	if other := fetch(t, serverFor(&fakeReporter{}), http.MethodPost, "/"+value, strings.NewReader("{}"), nil); !other.equal(want) {
		t.Errorf("POST to a trigger value = %+v, want %+v as for a report", other, want)
	}

	for _, outcome := range []ReportOutcome{ReportUnknown, ReportDisabled, ReportRecorded, ReportLimited, ReportDuplicate, ReportInvalid} {
		srv := serverFor(&fakeReporter{result: ReportResult{Outcome: outcome, HoneypotID: "1", Service: "ssh"}})
		for name, body := range map[string][]byte{"session": session, "heartbeat": heartbeat} {
			got := fetch(t, srv, http.MethodPost, "/", bytes.NewReader(body), bearer(testSecret))
			if !got.equal(want) {
				t.Errorf("%s with outcome %s: response %+v, want %+v", name, outcome, got, want)
			}
		}
	}

	failing := serverFor(&fakeReporter{err: errors.New("database unavailable")})
	panicking := serverFor(&fakeReporter{panics: true})
	accepting := serverFor(&fakeReporter{result: ReportResult{Outcome: ReportRecorded, HoneypotID: "1", Service: "ssh"}})
	huge := bytes.Repeat([]byte(" "), maxBodyBytes+1)
	cases := map[string]response{
		"database failure on a session":   fetch(t, failing, http.MethodPost, "/", bytes.NewReader(session), bearer(testSecret)),
		"database failure on a heartbeat": fetch(t, failing, http.MethodPost, "/", bytes.NewReader(heartbeat), bearer(testSecret)),
		"panic on a session":              fetch(t, panicking, http.MethodPost, "/", bytes.NewReader(session), bearer(testSecret)),
		"panic on a heartbeat":            fetch(t, panicking, http.MethodPost, "/", bytes.NewReader(heartbeat), bearer(testSecret)),
		"no secret":                       fetch(t, accepting, http.MethodPost, "/", bytes.NewReader(session), nil),
		"secret of the wrong form":        fetch(t, accepting, http.MethodPost, "/", bytes.NewReader(session), bearer("short")),
		"unsupported version": fetch(t, accepting, http.MethodPost, "/",
			bytes.NewReader(mutated(t, "session_ssh.json", func(m map[string]any) { m["version"] = 3 })), bearer(testSecret)),
		"invalid report": fetch(t, accepting, http.MethodPost, "/", strings.NewReader("{"), bearer(testSecret)),
		"no body":        fetch(t, accepting, http.MethodPost, "/", nil, bearer(testSecret)),
	}
	for name, got := range cases {
		if !got.equal(want) {
			t.Errorf("%s: response %+v, want %+v", name, got, want)
		}
	}

	// A body beyond the limit is cut off by the server, which may close the
	// connection; the client still receives the same answer and nothing is
	// recorded.
	tooLarge := &fakeReporter{result: ReportResult{Outcome: ReportRecorded}}
	got := fetch(t, serverFor(tooLarge), http.MethodPost, "/", bytes.NewReader(huge), bearer(testSecret))
	if got.status != want.status || !bytes.Equal(got.body, want.body) || got.header.Get("Location") != want.header.Get("Location") {
		t.Errorf("body beyond the limit: response %+v, want %+v", got, want)
	}
	if s, h := tooLarge.reported(); s+h != 0 {
		t.Errorf("a body beyond the limit was recorded: %d sessions, %d heartbeats", s, h)
	}
}

func TestTrigger_ReportsReachTheReporterByKind(t *testing.T) {
	t.Parallel()

	rep := &fakeReporter{result: ReportResult{Outcome: ReportRecorded, HoneypotID: "7d2a", Service: "ssh"}}
	rec := &fakeRecorder{}
	srv, _ := newReportingServer(t, rec, rep)

	fetch(t, srv, http.MethodPost, "/", bytes.NewReader(golden(t, "session_ssh.json")), bearer(testSecret))
	fetch(t, srv, http.MethodPost, "/", bytes.NewReader(golden(t, "heartbeat.json")), bearer(testSecret))

	if len(rep.sessions) != 1 || len(rep.heartbeats) != 1 {
		t.Fatalf("reporter got %d sessions and %d heartbeats, want one of each", len(rep.sessions), len(rep.heartbeats))
	}
	if s := rep.sessions[0]; s.ID != "0123456789abcdef0123456789abcdef" || s.Port != 22 || len(s.Attempts) != 2 {
		t.Errorf("session = %+v", s)
	}
	if h := rep.heartbeats[0]; h.SensorVersion != "0.1.0-rc.1+build5" {
		t.Errorf("heartbeat = %+v", h)
	}
	for _, hash := range rep.hashes {
		if !bytes.Equal(hash, SecretHash(testSecret)) {
			t.Errorf("reporter got the hash %x, want that of the secret", hash)
		}
	}
	if n := len(rec.recorded()); n != 0 {
		t.Errorf("a report looked up %d trigger values", n)
	}
}

// What cannot be a report is not looked up: a request without the form of a
// secret, a version that is not known and a report of another form never reach
// the database.
func TestTrigger_RejectedReportsAreNotRecorded(t *testing.T) {
	t.Parallel()

	session := golden(t, "session_ssh.json")
	tests := []struct {
		name   string
		body   []byte
		header http.Header
		method string
		path   string
		reason string
	}{
		{"no secret", session, nil, http.MethodPost, "/", ""},
		{"secret of the wrong form", session, bearer("short"), http.MethodPost, "/", ""},
		{"basic authentication", session, http.Header{"Authorization": {"Basic " + testSecret}}, http.MethodPost, "/", ""},
		{"unsupported version", mutated(t, "session_ssh.json", func(m map[string]any) { m["version"] = 3 }), bearer(testSecret), http.MethodPost, "/", "unsupported_version"},
		{"no version", mutated(t, "session_ssh.json", func(m map[string]any) { delete(m, "version") }), bearer(testSecret), http.MethodPost, "/", "unsupported_version"},
		{"unknown member", mutated(t, "session_ssh.json", func(m map[string]any) { m["password"] = "x" }), bearer(testSecret), http.MethodPost, "/", "invalid_report"},
		{"not JSON", []byte("version 1"), bearer(testSecret), http.MethodPost, "/", "invalid_report"},
		{"body beyond the limit", bytes.Repeat([]byte(" "), maxBodyBytes+1), bearer(testSecret), http.MethodPost, "/", "invalid_report"},
		{"GET", session, bearer(testSecret), http.MethodGet, "/", ""},
		{"PUT", session, bearer(testSecret), http.MethodPut, "/", ""},
		{"another path", session, bearer(testSecret), http.MethodPost, "/report", ""},
		{"path of a trigger value", session, bearer(testSecret), http.MethodPost, "/" + value, ""},
	}
	for _, tt := range tests {
		rep := &fakeReporter{result: ReportResult{Outcome: ReportRecorded}}
		srv, log := newReportingServer(t, &fakeRecorder{}, rep)
		fetch(t, srv, tt.method, tt.path, bytes.NewReader(tt.body), tt.header)
		if s, h := rep.reported(); s+h != 0 {
			t.Errorf("%s: %d sessions and %d heartbeats were recorded, want none", tt.name, s, h)
		}
		if tt.reason == "" {
			if strings.Contains(log.String(), `"reason"`) {
				t.Errorf("%s: log names a reason: %s", tt.name, log)
			}
			continue
		}
		for _, want := range []string{`"outcome":"rejected"`, `"reason":"` + tt.reason + `"`} {
			if !strings.Contains(log.String(), want) {
				t.Errorf("%s: log does not contain %s: %s", tt.name, want, log)
			}
		}
	}
}

// The log names the honeypot, its service and the type of the event, and
// nothing that the sensor or the attacker chose, least of all the secret.
func TestTrigger_LogsNoSecretAndNoCapturedContent(t *testing.T) {
	t.Parallel()

	for _, outcome := range []ReportOutcome{ReportRecorded, ReportInvalid} {
		rep := &fakeReporter{result: ReportResult{Outcome: outcome, HoneypotID: "7d2a", Service: "ldap"}}
		srv, log := newReportingServer(t, &fakeRecorder{}, rep)
		fetch(t, srv, http.MethodPost, "/", bytes.NewReader(golden(t, "session_ldap.json")), bearer(testSecret))

		for _, secret := range []string{testSecret, "cn=admin", "dc=example", "objectClass", "198.51.100.23", "00112233445566778899aabbccddeeff"} {
			if strings.Contains(log.String(), secret) {
				t.Errorf("outcome %s: log contains %q: %s", outcome, secret, log)
			}
		}
		want := []string{`"msg":"trigger: request"`, `"report":"session"`, `"honeypot_id":"7d2a"`, `"service":"ldap"`, `"event_type":"directory_query"`}
		if outcome == ReportInvalid {
			want = append(want, `"outcome":"rejected"`, `"reason":"invalid_report"`)
		} else {
			want = append(want, `"outcome":"recorded"`)
		}
		for _, w := range want {
			if !strings.Contains(log.String(), w) {
				t.Errorf("outcome %s: log does not contain %s: %s", outcome, w, log)
			}
		}
	}
}

func TestTrigger_LogsFailedReports(t *testing.T) {
	t.Parallel()

	srv, log := newReportingServer(t, &fakeRecorder{}, &fakeReporter{err: errors.New("database unavailable")})
	fetch(t, srv, http.MethodPost, "/", bytes.NewReader(golden(t, "heartbeat.json")), bearer(testSecret))
	for _, want := range []string{`"msg":"trigger: recording failed"`, `"outcome":"failed"`, `"report":"heartbeat"`} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("log does not contain %s: %s", want, log)
		}
	}
	if strings.Contains(log.String(), testSecret) {
		t.Errorf("log contains the secret: %s", log)
	}
}

func TestTrigger_LogsReportsBeyondTheLimit(t *testing.T) {
	t.Parallel()

	var log bytes.Buffer
	h := New(Options{
		Logger:          slog.New(slog.NewJSONHandler(&log, nil)),
		Recorder:        &fakeRecorder{},
		Reporter:        &fakeReporter{result: ReportResult{Outcome: ReportLimited, HoneypotID: "7d2a", Service: "ssh"}},
		DefaultRedirect: defaultRedirect,
	})
	for range 3 {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(golden(t, "session_ssh.json")))
		req.Header.Set("Authorization", "Bearer "+testSecret)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	if strings.Contains(log.String(), "not recorded") {
		t.Fatalf("logged before the interval ended: %s", log.String())
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	h.Run(ctx)
	if !strings.Contains(log.String(), `"msg":"trigger: reports not recorded","honeypot_id":"7d2a","reports":3`) {
		t.Errorf("log = %s, want the three reports beyond the limit", log.String())
	}
	if strings.Contains(log.String(), "requests not recorded") {
		t.Errorf("log = %s, want no requests of honeytokens", log.String())
	}
}

// A sensor that closes the connection right after its report must not keep the
// report from being recorded, and a slow database must not keep it waiting.
func TestTrigger_ReportsAreRecordedWithTheirOwnDeadline(t *testing.T) {
	t.Parallel()

	var canceled error
	var hasDeadline bool
	rep := reporterFunc(func(ctx context.Context) {
		canceled = ctx.Err()
		_, hasDeadline = ctx.Deadline()
	})
	h := New(Options{Logger: slog.New(slog.DiscardHandler), Recorder: &fakeRecorder{}, Reporter: rep, DefaultRedirect: defaultRedirect})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewReader(golden(t, "heartbeat.json")))
	req.Header.Set("Authorization", "Bearer "+testSecret)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if canceled != nil || !hasDeadline {
		t.Errorf("report recorded with context error %v and deadline %v, want a live context with a deadline", canceled, hasDeadline)
	}
}

// reporterFunc runs f for every report.
type reporterFunc func(ctx context.Context)

func (f reporterFunc) RecordSession(ctx context.Context, _ []byte, _ Session) (ReportResult, error) {
	f(ctx)
	return ReportResult{Outcome: ReportRecorded}, nil
}

func (f reporterFunc) RecordHeartbeat(ctx context.Context, _ []byte, _ Heartbeat) (ReportResult, error) {
	f(ctx)
	return ReportResult{Outcome: ReportRecorded}, nil
}

// A tool call is what an attacker wrote, and neither its name nor its arguments
// reach the log.
func TestReport_LogHoldsNothingOfAToolCall(t *testing.T) {
	t.Parallel()

	rep := &fakeReporter{result: ReportResult{Outcome: ReportRecorded, HoneypotID: "7d2a", Service: "mcp"}}
	srv, log := newReportingServer(t, &fakeRecorder{}, rep)
	fetch(t, srv, http.MethodPost, "/", bytes.NewReader(golden(t, "session_mcp.json")), bearer(testSecret))

	for _, secret := range []string{"get_page", "1002", "vpn password", "ExampleAgent"} {
		if strings.Contains(log.String(), secret) {
			t.Errorf("log contains %q: %s", secret, log)
		}
	}
	if !strings.Contains(log.String(), `"event_type":"tool_call"`) {
		t.Errorf("log does not name the kind of event: %s", log)
	}
}
