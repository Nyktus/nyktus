// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package trigger

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/platform/request"
)

const (
	// maxBodyBytes limits the body of a request. The trigger never reads it,
	// but the limit holds for every reader the handler may gain.
	maxBodyBytes = 64 << 10
	// recordTimeout bounds the wait for the database. A request that takes
	// longer is answered as if its value were unknown.
	recordTimeout = 2 * time.Second
	// limitLogInterval is how often the requests that a honeytoken's limit of
	// events kept from being recorded are logged.
	limitLogInterval = time.Minute
)

// Lengths up to which the headers of a request are recorded, in bytes. They are
// enough to recognize a client, and keep a client from filling the database.
const (
	maxUserAgentBytes      = 512
	maxRefererBytes        = 1024
	maxAcceptLanguageBytes = 128
)

// imageSuffix marks a request for an image. The URL of a honeytoken of the type
// web_image ends with it, so that the trigger can answer every request for an
// image with an image without knowing the type of the honeytoken.
const imageSuffix = ".gif"

// pixel is a transparent GIF of one pixel, the answer to every request for an
// image.
var pixel = []byte{
	'G', 'I', 'F', '8', '9', 'a',
	0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, // 1x1, global color table of two colors
	0x00, 0x00, 0x00, 0xff, 0xff, 0xff, // black, white
	0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, // color 0 is transparent
	0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // image of 1x1 at 0,0
	0x02, 0x02, 0x44, 0x01, 0x00, // LZW: clear, color 0, end
	0x3b,
}

// Options configure the trigger.
type Options struct {
	Logger   *slog.Logger
	Recorder Recorder
	// DefaultRedirect is where every request goes that is not sent to the
	// redirect target of a honeytoken.
	DefaultRedirect string
	TrustedProxies  []netip.Prefix
}

// Handler answers the requests of the trigger.
type Handler struct {
	logger          *slog.Logger
	recorder        Recorder
	defaultRedirect string
	next            http.Handler
	limited         limitedRequests
}

// New returns the handler of the trigger. Run must run alongside it, so that
// requests beyond the limit of a honeytoken are logged.
func New(o Options) *Handler {
	if o.Logger == nil || o.Recorder == nil || o.DefaultRedirect == "" {
		panic("trigger: missing logger, recorder or default redirect")
	}
	h := &Handler{
		logger:          o.Logger,
		recorder:        o.Recorder,
		defaultRedirect: o.DefaultRedirect,
		limited:         limitedRequests{counts: map[string]int{}},
	}
	// The middleware of the console is not used: its request IDs, JSON errors
	// and redirects of unclean paths would each identify the trigger.
	h.next = httpx.ClientIP(o.TrustedProxies)(http.HandlerFunc(h.serve))
	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.next.ServeHTTP(w, r)
}

// Run logs the requests that the limit of events kept from being recorded, at
// most once per interval and honeytoken, until ctx is canceled.
func (h *Handler) Run(ctx context.Context) {
	ticker := time.NewTicker(limitLogInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.limited.flush(ctx, h.logger)
		case <-ctx.Done():
			h.limited.flush(context.WithoutCancel(ctx), h.logger)
			return
		}
	}
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	attrs := make([]slog.Attr, 0, 6)
	attrs = append(attrs, slog.String("method", r.Method))
	var res Result
	value, ok := triggerValue(r.URL.Path)
	switch {
	case !ok || (r.Method != http.MethodGet && r.Method != http.MethodHead):
		attrs = append(attrs, slog.String("outcome", "not_looked_up"))
	default:
		var err error
		res, err = h.record(r.Context(), Request{
			Value:          value,
			Method:         r.Method,
			ClientIP:       request.ClientIP(r.Context()),
			UserAgent:      untrusted(r.Header.Get("User-Agent"), maxUserAgentBytes),
			Referer:        untrusted(r.Header.Get("Referer"), maxRefererBytes),
			AcceptLanguage: untrusted(r.Header.Get("Accept-Language"), maxAcceptLanguageBytes),
		})
		if err != nil {
			// The client receives the answer to an unknown value, which is the
			// same as the answer to a known one.
			h.logger.ErrorContext(r.Context(), "trigger: recording failed", slog.Any("error", err))
			res = Result{}
			attrs = append(attrs, slog.String("outcome", "failed"))
		} else {
			attrs = append(attrs, slog.String("outcome", string(res.Outcome)))
		}
		if res.HoneytokenID != "" {
			attrs = append(attrs, slog.String("honeytoken_id", res.HoneytokenID))
		}
		if res.Outcome == OutcomeLimited {
			h.limited.add(res.HoneytokenID)
		}
	}

	status := http.StatusFound
	if strings.HasSuffix(r.URL.Path, imageSuffix) {
		status = http.StatusOK
		writeImage(w)
	} else {
		target := h.defaultRedirect
		if res.RedirectURL != "" {
			target = res.RedirectURL
		}
		writeRedirect(w, target)
	}

	// The path holds the trigger value, so it stays out of the log.
	attrs = append(attrs, slog.Int("status", status), slog.Duration("duration", time.Since(start)))
	if ip := request.ClientIP(r.Context()); ip.IsValid() {
		attrs = append(attrs, slog.String("client_ip", ip.String()))
	}
	h.logger.LogAttrs(r.Context(), slog.LevelInfo, "trigger: request", attrs...)
}

// errPanicked reports that the recorder panicked. The panic is logged where it
// is recovered, and the request is answered like any other.
var errPanicked = errors.New("recorder panicked")

func (h *Handler) record(ctx context.Context, req Request) (res Result, err error) {
	defer func() {
		if v := recover(); v != nil {
			h.logger.ErrorContext(ctx, "trigger: recorder panicked",
				slog.String("panic", fmt.Sprint(v)),
				slog.String("stack", string(debug.Stack())),
			)
			res, err = Result{}, errPanicked
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, recordTimeout)
	defer cancel()
	return h.recorder.Record(ctx, req)
}

// triggerValue extracts the trigger value from the path of a URL of a
// honeytoken, "/<value>" or "/<value>.gif". Other paths, such as "/" or
// "/robots.txt", hold no value and are answered without asking the database.
func triggerValue(path string) (string, bool) {
	value, ok := strings.CutPrefix(path, "/")
	value = strings.TrimSuffix(value, imageSuffix)
	return value, ok && isTriggerValue(value)
}

// triggerValueLength is the length of a trigger value: 128 bits in lowercase
// base32 without padding.
const triggerValueLength = 26

func isTriggerValue(s string) bool {
	if len(s) != triggerValueLength {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}

// untrusted prepares a header value for the database: invalid UTF-8 and
// control characters are replaced, so that a value cannot break the lines of a
// log or a report, and the value is cut to at most maxBytes without splitting a
// character.
func untrusted(s string, maxBytes int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return utf8.RuneError
		}
		return r
	}, strings.ToValidUTF8(s, string(utf8.RuneError)))
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// The responses set every header themselves. Content-Length is set explicitly,
// so that net/http neither adds a Content-Type of its own nor switches to
// chunked encoding, and Cache-Control keeps browsers and proxies from answering
// the next request from a cache, which would leave it unrecorded.

func writeImage(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "image/gif")
	h.Set("Content-Length", strconv.Itoa(len(pixel)))
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pixel)
}

// writeRedirect sends the client to target. http.Redirect is not used: its HTML
// body identifies the server as written in Go.
func writeRedirect(w http.ResponseWriter, target string) {
	h := w.Header()
	h.Set("Location", target)
	h.Set("Content-Length", "0")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)
}

// limitedRequests counts, per honeytoken, the requests that its limit of events
// kept from being recorded since they were last logged.
type limitedRequests struct {
	mu     sync.Mutex
	counts map[string]int
}

func (l *limitedRequests) add(honeytokenID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counts[honeytokenID]++
}

func (l *limitedRequests) flush(ctx context.Context, logger *slog.Logger) {
	l.mu.Lock()
	counts := l.counts
	l.counts = map[string]int{}
	l.mu.Unlock()
	for id, n := range counts {
		logger.WarnContext(ctx, "trigger: requests not recorded",
			slog.String("honeytoken_id", id), slog.Int("requests", n))
	}
}
