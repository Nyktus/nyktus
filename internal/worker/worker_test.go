// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// call is one call of Process on the fake queue. The test decides how it ends.
type call struct {
	ctx     context.Context
	claimed func()
	reply   chan result
}

type result struct {
	found bool
	err   error
}

// fakeQueue hands every call of Process to the test and counts the calls in
// progress.
type fakeQueue struct {
	calls chan call
	// stop ends every call that the test no longer answers.
	stop chan struct{}

	mu             sync.Mutex
	inFlight, most int
}

func newFakeQueue() *fakeQueue {
	return &fakeQueue{calls: make(chan call), stop: make(chan struct{})}
}

func (q *fakeQueue) Process(ctx context.Context, claimed func()) (bool, error) {
	q.mu.Lock()
	q.inFlight++
	q.most = max(q.most, q.inFlight)
	q.mu.Unlock()
	defer func() {
		q.mu.Lock()
		q.inFlight--
		q.mu.Unlock()
	}()

	c := call{ctx: ctx, claimed: claimed, reply: make(chan result)}
	select {
	case q.calls <- c:
	case <-q.stop:
		return false, nil
	}
	select {
	case r := <-c.reply:
		return r.found, r.err
	case <-q.stop:
		return false, nil
	}
}

// next returns the next call of Process.
func (q *fakeQueue) next(t *testing.T) call {
	t.Helper()
	select {
	case c := <-q.calls:
		return c
	case <-t.Context().Done():
		t.Fatal("no call of Process")
		return call{}
	}
}

// fakeClock hands every wait of the worker to the test.
type fakeClock struct {
	waits chan wait
}

type wait struct {
	d    time.Duration
	fire chan time.Time
}

func (c *fakeClock) after(d time.Duration) <-chan time.Time {
	w := wait{d: d, fire: make(chan time.Time, 1)}
	c.waits <- w
	return w.fire
}

// next returns the next wait of the worker and lets it pass.
func (c *fakeClock) next(t *testing.T) time.Duration {
	t.Helper()
	select {
	case w := <-c.waits:
		w.fire <- time.Time{}
		return w.d
	case <-t.Context().Done():
		t.Fatal("the worker did not wait")
		return 0
	}
}

type harness struct {
	queue  *fakeQueue
	clock  *fakeClock
	logMu  sync.Mutex
	log    bytes.Buffer
	cancel context.CancelFunc
	done   chan struct{}
}

// start runs a worker on fakes until the test ends or calls stop.
func start(t *testing.T, concurrency int) *harness {
	t.Helper()
	h := &harness{queue: newFakeQueue(), clock: &fakeClock{waits: make(chan wait)}, done: make(chan struct{})}
	w := New(Options{
		Logger:       slog.New(slog.NewJSONHandler(&lockedWriter{mu: &h.logMu, w: &h.log}, nil)),
		Queue:        h.queue,
		Concurrency:  concurrency,
		PollInterval: time.Second,
		MaxBackoff:   4 * time.Second,
		JobTimeout:   10 * time.Second,
		After:        h.clock.after,
	})
	ctx, cancel := context.WithCancel(t.Context())
	h.cancel = cancel
	go func() {
		defer close(h.done)
		w.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		close(h.queue.stop)
		// A wait that the test did not receive would block the worker.
		for {
			select {
			case <-h.done:
				return
			case <-h.clock.waits:
			}
		}
	})
	return h
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// After a job is claimed, the worker looks for the next one at once, up to its
// concurrency; it never runs more jobs at a time.
func TestRun_RunsJobsSideBySideUpToItsConcurrency(t *testing.T) {
	t.Parallel()
	h := start(t, 2)

	first := h.queue.next(t)
	first.claimed()
	second := h.queue.next(t)
	second.claimed()

	// Both slots are taken; the next attempt starts when a job ends.
	first.reply <- result{found: true}
	third := h.queue.next(t)
	third.reply <- result{}
	if d := h.clock.next(t); d != time.Second {
		t.Errorf("wait after no job was due = %v, want the poll interval", d)
	}
	second.reply <- result{found: true}

	h.queue.mu.Lock()
	defer h.queue.mu.Unlock()
	if h.queue.most > 2 {
		t.Errorf("%d jobs at a time, want at most 2", h.queue.most)
	}
}

// While every slot holds a job, the worker starts no further attempt. The
// bubble shows it without timing: once every goroutine is blocked, the number
// of calls in progress is final.
func TestRun_NeverExceedsItsConcurrency(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		q := newFakeQueue()
		w := New(Options{
			Logger: slog.New(slog.DiscardHandler), Queue: q, Concurrency: 2,
			PollInterval: time.Second, MaxBackoff: time.Second, JobTimeout: 10 * time.Second,
		})
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			w.Run(ctx)
		}()

		first := <-q.calls
		first.claimed()
		second := <-q.calls
		second.claimed()
		synctest.Wait()
		q.mu.Lock()
		inFlight := q.inFlight
		q.mu.Unlock()
		if inFlight != 2 {
			t.Errorf("%d calls in progress with two jobs claimed, want 2", inFlight)
		}

		first.reply <- result{found: true}
		third := <-q.calls
		synctest.Wait()
		q.mu.Lock()
		inFlight = q.inFlight
		q.mu.Unlock()
		if inFlight != 2 {
			t.Errorf("%d calls in progress after a job ended, want 2", inFlight)
		}

		cancel()
		third.reply <- result{}
		second.reply <- result{found: true}
		<-done
	})
}

// Without a due job, the worker waits the poll interval before it looks again.
func TestRun_WaitsThePollIntervalWhileIdle(t *testing.T) {
	t.Parallel()
	h := start(t, 1)

	for range 3 {
		h.queue.next(t).reply <- result{}
		if d := h.clock.next(t); d != time.Second {
			t.Errorf("wait = %v, want the poll interval", d)
		}
	}
}

// A job that ended without a claim, such as one that was processed in a way
// the queue does not report, does not make the worker wait.
func TestRun_LooksForTheNextJobAfterAJob(t *testing.T) {
	t.Parallel()
	h := start(t, 1)

	h.queue.next(t).reply <- result{found: true}
	h.queue.next(t).reply <- result{}
	if d := h.clock.next(t); d != time.Second {
		t.Errorf("wait = %v, want the poll interval", d)
	}
}

// While the queue cannot be reached, the worker waits longer after every
// failure, up to its maximum, logs each failure, and returns to the poll
// interval once the queue answers.
func TestRun_BacksOffWhileTheQueueFails(t *testing.T) {
	t.Parallel()
	h := start(t, 1)

	for _, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second} {
		h.queue.next(t).reply <- result{err: errors.New("connection refused")}
		if d := h.clock.next(t); d != want {
			t.Errorf("wait after a failure = %v, want %v", d, want)
		}
	}
	h.queue.next(t).reply <- result{}
	if d := h.clock.next(t); d != time.Second {
		t.Errorf("wait after the queue answered = %v, want the poll interval", d)
	}
	h.queue.next(t).reply <- result{err: errors.New("connection refused")}
	if d := h.clock.next(t); d != time.Second {
		t.Errorf("wait after a new failure = %v, want the poll interval", d)
	}

	if n := strings.Count(h.logged(), `"msg":"worker: job failed"`); n != 5 {
		t.Errorf("logged %d failures, want 5:\n%s", n, h.logged())
	}
}

// A job that fails after it was claimed is logged, and the worker looks for
// the next job at once: the queue answered.
func TestRun_LogsAJobThatFailedAfterItsClaim(t *testing.T) {
	t.Parallel()
	h := start(t, 1)

	c := h.queue.next(t)
	c.claimed()
	c.reply <- result{found: true, err: errors.New("commit failed")}
	h.queue.next(t).reply <- result{}
	if d := h.clock.next(t); d != time.Second {
		t.Errorf("wait = %v, want the poll interval", d)
	}
	if !strings.Contains(h.logged(), `"msg":"worker: job failed","claimed":true,"error":"commit failed"`) {
		t.Errorf("log = %s, want the failed job", h.logged())
	}
}

// A stopped worker takes no new job, but lets the job in progress end with a
// live context within its deadline, and returns only after it.
func TestRun_StopLetsTheJobInProgressEnd(t *testing.T) {
	t.Parallel()
	h := start(t, 2)

	c := h.queue.next(t)
	c.claimed()
	// The worker looks for the next job at once; that attempt finds none.
	h.queue.next(t).reply <- result{}
	h.cancel()

	select {
	case <-h.done:
		t.Fatal("Run returned while a job was in progress")
	case <-c.ctx.Done():
		t.Fatal("the job in progress was canceled")
	case <-h.clock.waits:
		// The worker started to wait before it saw the stop; it ends the wait.
	}
	if c.ctx.Err() != nil {
		t.Fatal("the job in progress was canceled")
	}
	deadline, ok := c.ctx.Deadline()
	if !ok || time.Until(deadline) > 10*time.Second {
		t.Errorf("job deadline = %v, %v; want at most the job timeout", deadline, ok)
	}
	c.reply <- result{found: true}
	<-h.done
}

func (h *harness) logged() string {
	h.logMu.Lock()
	defer h.logMu.Unlock()
	return h.log.String()
}

func TestNew_RejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	valid := Options{
		Logger: slog.New(slog.DiscardHandler), Queue: newFakeQueue(), Concurrency: 1,
		PollInterval: time.Second, MaxBackoff: time.Second, JobTimeout: time.Second,
	}
	for name, change := range map[string]func(*Options){
		"nil logger":         func(o *Options) { o.Logger = nil },
		"nil queue":          func(o *Options) { o.Queue = nil },
		"no concurrency":     func(o *Options) { o.Concurrency = 0 },
		"no poll interval":   func(o *Options) { o.PollInterval = 0 },
		"backoff below poll": func(o *Options) { o.MaxBackoff = time.Millisecond },
		"no job timeout":     func(o *Options) { o.JobTimeout = 0 },
	} {
		o := valid
		change(&o)
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: New() did not panic", name)
				}
			}()
			New(o)
		}()
	}
}
