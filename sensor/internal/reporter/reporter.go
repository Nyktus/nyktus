// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package reporter

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/session"
)

// Limits of the queue and of the heartbeat.
const (
	// QueueSize is the number of sessions that wait for delivery. A session
	// that finds the queue full is counted and dropped.
	QueueSize = 256
	// Senders is the number of sessions that are delivered at the same time.
	Senders = 4
	// HeartbeatInterval is the pause between the heartbeats of a honeypot.
	HeartbeatInterval = 5 * time.Minute
)

// Options configure a Reporter. Zero values mean the defaults above; tests set
// smaller ones.
type Options struct {
	// URL is where reports go.
	URL    string
	Client *http.Client
	Clock  clock.Clock
	Logger *slog.Logger
	// QueueSize, Senders and Backoff replace the defaults.
	QueueSize int
	Senders   int
	Backoff   []time.Duration
}

// Stats counts what happened to reports since the last call of TakeStats.
type Stats struct {
	// Sent counts sessions that the trigger answered.
	Sent int
	// Overflow counts sessions dropped because the queue was full.
	Overflow int
	// Expired counts sessions dropped because they were older than five
	// minutes when their turn came.
	Expired int
	// Failed counts sessions the transport failed for on every attempt.
	Failed int
	// Shutdown counts sessions dropped because the sensor stopped first.
	Shutdown int
}

// Reporter delivers the sessions of the sensor from a bounded queue.
type Reporter struct {
	sender    *sender
	clock     clock.Clock
	logger    *slog.Logger
	queue     chan *session.Session
	senders   int
	sendCtx   context.Context
	abort     context.CancelFunc
	wg        sync.WaitGroup
	startOnce sync.Once

	mu     sync.Mutex
	closed bool

	sent, overflow, expired, failed, shutdown atomic.Int64
}

// New returns a Reporter. It panics if a dependency is missing.
func New(o Options) *Reporter {
	if o.URL == "" || o.Clock == nil || o.Logger == nil {
		panic("reporter: missing url, clock or logger")
	}
	if o.Client == nil {
		o.Client = NewHTTPClient()
	}
	if o.QueueSize <= 0 {
		o.QueueSize = QueueSize
	}
	if o.Senders <= 0 {
		o.Senders = Senders
	}
	if o.Backoff == nil {
		o.Backoff = defaultBackoff
	}
	r := &Reporter{
		sender:  &sender{url: o.URL, client: o.Client, clock: o.Clock, backoff: o.Backoff, logger: o.Logger},
		clock:   o.Clock,
		logger:  o.Logger,
		queue:   make(chan *session.Session, o.QueueSize),
		senders: o.Senders,
	}
	// The senders outlive the cancellation of the process, so that Shutdown
	// can deliver what is queued; Shutdown ends them at its deadline.
	r.sendCtx, r.abort = context.WithCancel(context.Background())
	return r
}

// Start starts the senders. They run until Shutdown.
func (r *Reporter) Start() {
	r.startOnce.Do(func() {
		for range r.senders {
			r.wg.Go(func() {
				for s := range r.queue {
					r.send(s)
				}
			})
		}
	})
}

// Submit queues a finished session for delivery. It never blocks: a session
// that finds the queue full, or comes after Shutdown, is counted and dropped.
func (r *Reporter) Submit(s *session.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		r.shutdown.Add(1)
		return
	}
	select {
	case r.queue <- s:
	default:
		r.overflow.Add(1)
	}
}

// Shutdown stops taking sessions and delivers the queued ones until ctx is
// done. Whatever is still queued or in flight then is counted and dropped.
// It returns when no sender runs any more.
func (r *Reporter) Shutdown(ctx context.Context) {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		close(r.queue)
	}
	r.mu.Unlock()

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		r.abort()
		<-done
	}
	r.abort()
}

func (r *Reporter) send(s *session.Session) {
	build := func() ([]byte, bool) {
		rep, ok := s.Report(r.clock.Elapsed())
		if !ok {
			return nil, false
		}
		body, err := json.Marshal(rep)
		return body, err == nil
	}
	out, _ := r.sender.deliver(r.sendCtx, s.Honeypot().Secret, build)
	switch out {
	case delivered:
		r.sent.Add(1)
		r.logger.DebugContext(r.sendCtx, "sensor: session reported", s.Attr())
	case expired:
		r.expired.Add(1)
	case failed:
		r.failed.Add(1)
	case canceled:
		r.shutdown.Add(1)
	}
}

// RunHeartbeats tells the trigger that the honeypots run, once for each now
// and again for each every HeartbeatInterval, until ctx is done. Every honeypot
// has a loop of its own, so that a slow trigger delays only the heartbeat it is
// answering, not the ones after it. The heartbeats do not use the queue, which
// an attacker can fill: a honeypot under attack must not look offline.
func (r *Reporter) RunHeartbeats(ctx context.Context, sensorVersion string, honeypots []*session.Honeypot) {
	body, err := json.Marshal(report.NewHeartbeat(sensorVersion))
	if err != nil {
		panic("reporter: heartbeat does not serialize")
	}
	var wg sync.WaitGroup
	for _, hp := range honeypots {
		wg.Go(func() { r.heartbeats(ctx, hp, body) })
	}
	wg.Wait()
}

func (r *Reporter) heartbeats(ctx context.Context, hp *session.Honeypot, body []byte) {
	for {
		// A heartbeat comes once in five minutes whatever an attacker does, so
		// a failure is logged at once: it is how an operator learns that the
		// address or the certificate of the trigger is wrong.
		if out, err := r.sender.deliver(ctx, hp.Secret, func() ([]byte, bool) { return body, true }); out == failed {
			r.logger.WarnContext(ctx, "sensor: heartbeat not delivered", hp.Attr(), slog.Any("error", err))
		}
		if r.clock.Wait(ctx, HeartbeatInterval) != nil {
			return
		}
	}
}

// TakeStats returns the counts since the last call and resets them.
func (r *Reporter) TakeStats() Stats {
	return Stats{
		Sent:     int(r.sent.Swap(0)),
		Overflow: int(r.overflow.Swap(0)),
		Expired:  int(r.expired.Swap(0)),
		Failed:   int(r.failed.Swap(0)),
		Shutdown: int(r.shutdown.Swap(0)),
	}
}
