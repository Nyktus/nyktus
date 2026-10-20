// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package reporter sends the reports of the sensor to the trigger: sessions,
// which wait in a bounded queue, and heartbeats.
//
// The trigger answers every report alike, whether it was stored or not, so the
// sensor learns nothing from the answer and repeats a request only after a
// failure of the transport.
package reporter

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock"
	"nyktus.org/nyktus/sensor/internal/secret"
)

// Limits of the delivery.
const (
	// MaxRetries is how often a request is repeated after a failure of the
	// transport.
	MaxRetries = 3
	// RequestTimeout is how long one request may take.
	RequestTimeout = 10 * time.Second
	// maxResponseBody is how much of an answer the sensor reads. It ignores
	// the content, but a connection is reused only when the answer was read.
	maxResponseBody = 4 << 10
)

// defaultBackoff are the pauses before the repetitions, one for each.
var defaultBackoff = []time.Duration{time.Second, 3 * time.Second, 9 * time.Second}[:MaxRetries]

// NewHTTPClient returns the client that reports are sent with. It verifies the
// certificate of the trigger against the system's authorities, and against the
// file that SSL_CERT_FILE names where the system honors it, which is how an
// operator adds a private authority. It reads no proxy from the environment
// and does not follow a redirect: the trigger answers every report with one.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: RequestTimeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: RequestTimeout,
			MaxIdleConns:          4,
			IdleConnTimeout:       time.Minute,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// outcome says what became of a report.
type outcome int

const (
	// delivered means that the trigger answered. What it did with the report
	// is not known and not asked.
	delivered outcome = iota
	// expired means that the session is older than the server takes it.
	expired
	// failed means that the transport failed on every attempt.
	failed
	// canceled means that the sensor stopped first.
	canceled
)

// sender posts reports to the trigger.
type sender struct {
	url     string
	client  *http.Client
	clock   clock.Clock
	backoff []time.Duration
	logger  *slog.Logger
}

// deliver sends the report that build returns and repeats the request after a
// failure of the transport, up to MaxRetries times. build runs before every
// attempt, because the age of a session grows with every pause; it reports
// false for a report that must not be sent any more. For a report that failed
// it returns the error of the last attempt.
func (s *sender) deliver(ctx context.Context, sec secret.Secret, build func() ([]byte, bool)) (outcome, error) {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return canceled, err
		}
		body, ok := build()
		if !ok {
			return expired, nil
		}
		err := s.post(ctx, sec, body)
		if err == nil {
			return delivered, nil
		}
		if ctx.Err() != nil {
			return canceled, err
		}
		if errors.Is(err, errRequest) {
			return failed, err
		}
		s.logger.DebugContext(ctx, "sensor: report request failed", slog.Int("attempt", attempt+1), slog.Any("error", err))
		if attempt >= len(s.backoff) {
			return failed, err
		}
		if err := s.clock.Wait(ctx, s.backoff[attempt]); err != nil {
			return canceled, err
		}
	}
}

// errRequest is a request that cannot be built, which no repetition helps.
var errRequest = errors.New("build request")

// post sends one request. It returns an error only if the transport failed:
// any answer is a success, because the trigger answers alike whatever it did.
func (s *sender) post(ctx context.Context, sec secret.Secret, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return errRequest
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(sec))
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
	_ = resp.Body.Close()
	return nil
}
