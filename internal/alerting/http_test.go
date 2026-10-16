// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package alerting

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"nyktus.org/nyktus/internal/platform/ssrf"
)

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
