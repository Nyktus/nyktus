// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"nyktus.org/nyktus/internal/platform/logging"
)

// logRecords decodes every JSON record in logs.
func logRecords(t *testing.T, logs *bytes.Buffer) []map[string]any {
	t.Helper()
	var records []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(logs.String()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode log record %q: %v", line, err)
		}
		records = append(records, record)
	}
	return records
}

// The router authenticates a request after the access log has received it. What
// the authenticating step adds to the log scope must still reach the access log,
// and the client address must be there as well.
func TestAccessLog_RecordsClientAddressAndLaterAttributes(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := logging.New(&logs, slog.LevelInfo)
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logging.AddToScope(r.Context(), slog.String("user_id", "u1"))
		w.WriteHeader(http.StatusNoContent)
	}), RequestID, ClientIP([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}), AccessLog(logger), Recover(logger))

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.2:4711"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	h.ServeHTTP(httptest.NewRecorder(), r)

	records := logRecords(t, &logs)
	if len(records) != 1 {
		t.Fatalf("records = %v, want one access log record", records)
	}
	if records[0]["client_ip"] != "203.0.113.9" || records[0]["user_id"] != "u1" {
		t.Errorf("access log record = %v, want client_ip 203.0.113.9 and user_id u1", records[0])
	}
}

func TestAccessLog_OmitsUnknownClientAddress(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := logging.New(&logs, slog.LevelInfo)
	h := Chain(http.NotFoundHandler(), RequestID, AccessLog(logger))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	if record := logRecords(t, &logs)[0]; record["client_ip"] != nil {
		t.Errorf("access log record = %v, want no client_ip without the ClientIP middleware", record)
	}
}

func TestRecover_RecordsLaterAttributes(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := logging.New(&logs, slog.LevelInfo)
	h := Chain(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		logging.AddToScope(r.Context(), slog.String("user_id", "u1"))
		panic("boom")
	}), RequestID, Recover(logger))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	if record := logRecords(t, &logs)[0]; record["msg"] != "http: handler panicked" || record["user_id"] != "u1" {
		t.Errorf("panic record = %v, want user_id u1", record)
	}
}

func TestDeadline_BoundsTheRequestContext(t *testing.T) {
	t.Parallel()

	var deadline time.Time
	var ok bool
	h := Deadline(10 * time.Second)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		deadline, ok = r.Context().Deadline()
	}))
	before := time.Now()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if !ok || deadline.Before(before.Add(10*time.Second)) || deadline.After(time.Now().Add(10*time.Second)) {
		t.Errorf("deadline = %v, %v; want 10s after the request started", deadline, ok)
	}
}

func TestDeadline_RejectsNonPositiveDuration(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("Deadline(0) did not panic")
		}
	}()
	Deadline(0)
}

func TestUnavailable_SuggestsRetry(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	Unavailable(w, r, discardLogger(), "test: op", errors.New("down"))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "5" {
		t.Errorf("response = %d, Retry-After %q; want 503 with Retry-After 5", w.Code, w.Header().Get("Retry-After"))
	}
}

func TestServerError_AnswersDeadlineWith503(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	ServerError(w, r, discardLogger(), "test: hash password", fmt.Errorf("wait for password hashing: %w", context.DeadlineExceeded))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Errorf("response = %d, Retry-After %q; want 503 with Retry-After", w.Code, w.Header().Get("Retry-After"))
	}
}
