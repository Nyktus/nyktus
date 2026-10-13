// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package worker runs the jobs of the worker role, such as the jobs of events.
//
// Jobs wait in tables of PostgreSQL and are taken one at a time with
// SELECT ... FOR UPDATE SKIP LOCKED, so that several worker processes share the
// work without coordination. The worker looks for jobs at a fixed interval and
// right after it found one, so that a backlog drains without waiting. It
// listens on no port: it only connects out.
package worker

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Queue hands out jobs.
type Queue interface {
	// Process processes the next job that is due, if there is one. It calls
	// claimed once it holds the job, so that the worker can look for the next
	// job meanwhile. Canceling ctx must end the search for a job, but not a
	// job that was taken: the job runs to its end within the deadline of ctx,
	// so that a stopping worker completes its transaction. It returns false if
	// no job was due. An error means that the queue could not be reached or
	// the job could not be completed; the job then stays.
	Process(ctx context.Context, claimed func()) (bool, error)
}

// Options configures a Worker.
type Options struct {
	Logger *slog.Logger
	Queue  Queue
	// Concurrency bounds the jobs in progress at a time.
	Concurrency int
	// PollInterval is the wait after no job was due.
	PollInterval time.Duration
	// MaxBackoff bounds the wait after the queue failed. The wait doubles
	// from PollInterval with every failure in a row.
	MaxBackoff time.Duration
	// JobTimeout bounds a job, also when the worker is stopped while it runs.
	JobTimeout time.Duration
	// After returns a channel that receives once d has passed, time.After if
	// nil. Tests replace it.
	After func(d time.Duration) <-chan time.Time
}

// Worker runs jobs of a queue.
type Worker struct {
	logger       *slog.Logger
	queue        Queue
	concurrency  int
	pollInterval time.Duration
	maxBackoff   time.Duration
	jobTimeout   time.Duration
	after        func(time.Duration) <-chan time.Time
}

// New returns a Worker. It panics on missing or invalid options, which are
// programming errors.
func New(o Options) *Worker {
	switch {
	case o.Logger == nil || o.Queue == nil:
		panic("worker: nil logger or queue")
	case o.Concurrency < 1:
		panic("worker: concurrency below 1")
	case o.PollInterval <= 0 || o.MaxBackoff < o.PollInterval || o.JobTimeout <= 0:
		panic("worker: invalid intervals")
	}
	after := o.After
	if after == nil {
		after = time.After
	}
	return &Worker{
		logger: o.Logger, queue: o.Queue, concurrency: o.Concurrency,
		pollInterval: o.PollInterval, maxBackoff: o.MaxBackoff, jobTimeout: o.JobTimeout, after: after,
	}
}

// outcome is how an attempt to take a job ended.
type outcome struct {
	found   bool
	claimed bool
	err     error
}

// Run runs jobs until ctx is canceled. It then takes no new job and returns
// once the jobs in progress have ended.
func (w *Worker) Run(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()

	slots := make(chan struct{}, w.concurrency)
	// backoff is the wait after the next failure in a row.
	backoff := w.pollInterval
	for {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		// Both cases can be ready; a stopped worker takes no new job.
		if ctx.Err() != nil {
			<-slots
			return
		}

		claimed := make(chan struct{})
		ended := make(chan outcome, 1)
		wg.Go(func() {
			defer func() { <-slots }()
			ended <- w.attempt(ctx, claimed)
		})

		var wait time.Duration
		select {
		case <-claimed:
			// The job is in progress; the next one may be due as well.
			backoff = w.pollInterval
			continue
		case o := <-ended:
			switch {
			case o.err != nil && !o.claimed:
				wait = backoff
				backoff = min(backoff*2, w.maxBackoff)
			case o.found:
				backoff = w.pollInterval
				continue
			default:
				backoff = w.pollInterval
				wait = w.pollInterval
			}
		}
		if ctx.Err() != nil {
			return
		}
		select {
		case <-w.after(wait):
		case <-ctx.Done():
			return
		}
	}
}

// attempt takes and processes one job within the job timeout. A stop ends the
// search, and the queue lets a job that was taken run to its end within the
// timeout.
func (w *Worker) attempt(ctx context.Context, claimed chan<- struct{}) outcome {
	jobCtx, cancel := context.WithTimeout(ctx, w.jobTimeout)
	defer cancel()

	var o outcome
	var once sync.Once
	o.found, o.err = w.queue.Process(jobCtx, func() {
		once.Do(func() {
			o.claimed = true
			close(claimed)
		})
	})
	switch {
	case o.err == nil:
	case ctx.Err() != nil && !o.claimed:
		// The search ended with the worker, which is no failure.
		o.err = nil
	default:
		w.logger.ErrorContext(ctx, "worker: job failed", slog.Bool("claimed", o.claimed), slog.Any("error", o.err))
	}
	return o
}
