// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package alerting

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"nyktus.org/nyktus/internal/platform/ssrf"
)

// Sender sends a request. The client of the SSRF guard implements it.
type Sender interface {
	Do(req *http.Request) (*http.Response, error)
}

// httpTransport posts the message to the URL of a channel, formatted for its
// type, through the client of the SSRF guard.
type httpTransport struct {
	client     Sender
	consoleURL string
}

// send sends the message of a to its channel and classifies the result.
func (t *httpTransport) send(ctx context.Context, a attempt) outcome {
	body, contentType, err := format(a.ChannelType, a.message, a.Delivery, t.consoleURL)
	if err != nil {
		return outcome{permanent: true, failure: FailureInvalidChannel}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, string(a.channel.url), bytes.NewReader(body))
	if err != nil {
		return outcome{permanent: true, failure: FailureInvalidChannel}
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "Nyktus")
	if a.channel.headerName != nil {
		req.Header.Set(*a.channel.headerName, string(a.channel.headerValue))
	}
	start := time.Now()
	resp, err := t.client.Do(req)
	o := classify(resp, err)
	if resp != nil {
		// The body is read so that the connection can be reused, and never
		// kept: it is the business of the receiver.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	o.duration = time.Since(start)
	return o
}

// classify maps the result of a request to an outcome. Errors are classified,
// never kept: the error of a request names its URL, which is a secret.
func classify(resp *http.Response, err error) outcome {
	if err != nil {
		var (
			netErr  net.Error
			certErr *tls.CertificateVerificationError
			unknown x509.UnknownAuthorityError
			invalid x509.CertificateInvalidError
			host    x509.HostnameError
			record  tls.RecordHeaderError
		)
		switch {
		case errors.Is(err, ssrf.ErrBlocked):
			return outcome{permanent: true, failure: FailureBlocked}
		case errors.Is(err, ssrf.ErrInvalidURL):
			return outcome{permanent: true, failure: FailureInvalidChannel}
		case errors.As(err, &certErr), errors.As(err, &unknown), errors.As(err, &invalid), errors.As(err, &host),
			errors.As(err, &record):
			return outcome{failure: FailureTLS}
		case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
			return outcome{failure: FailureTimeout}
		default:
			return outcome{failure: FailureNetwork}
		}
	}
	code := resp.StatusCode
	o := outcome{statusCode: &code}
	switch {
	case code >= 200 && code < 300:
		o.delivered = true
	case code >= 300 && code < 400:
		o.permanent, o.failure = true, FailureRedirect
	case code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable:
		// Both may name how long the receiver wants to be left alone.
		o.failure, o.retryAfter = FailureHTTPStatus, retryAfter(resp.Header.Get("Retry-After"), time.Now())
	case code == http.StatusRequestTimeout || code >= 500:
		o.failure = FailureHTTPStatus
	default:
		o.permanent, o.failure = true, FailureHTTPStatus
	}
	return o
}

// retryAfter reads the wait that a receiver asks for, in seconds or as a date,
// bounded by MaxBackoff. It returns 0 if there is none.
func retryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil {
		return min(max(time.Duration(s)*time.Second, 0), MaxBackoff)
	}
	if t, err := http.ParseTime(v); err == nil {
		return min(max(t.Sub(now), 0), MaxBackoff)
	}
	return 0
}
