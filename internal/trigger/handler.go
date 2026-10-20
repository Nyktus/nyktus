// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package trigger

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/platform/request"
)

const (
	// maxBodyBytes limits the body of a request. Only the report of a sensor
	// is read, and the limit is the only bound on it; the limit holds for
	// every reader the handler may gain.
	maxBodyBytes = 64 << 10
	// recordTimeout bounds the wait for the database. A request that takes
	// longer is answered as if its value were unknown.
	recordTimeout = 2 * time.Second
	// limitLogInterval is how often the requests that the limit of events of a
	// honeytoken or honeypot kept from being recorded are logged.
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
	// Reporter records the reports of sensors.
	Reporter Reporter
	// DefaultRedirect is where every request goes that is not sent to the
	// redirect target of a honeytoken.
	DefaultRedirect string
	TrustedProxies  []netip.Prefix
}

// Handler answers the requests of the trigger.
type Handler struct {
	logger          *slog.Logger
	recorder        Recorder
	reporter        Reporter
	defaultRedirect string
	next            http.Handler
	limited         limitedRequests
	limitedReports  limitedRequests
}

// New returns the handler of the trigger. Run must run alongside it, so that
// requests beyond the limit of a honeytoken or honeypot are logged.
func New(o Options) *Handler {
	if o.Logger == nil || o.Recorder == nil || o.Reporter == nil || o.DefaultRedirect == "" {
		panic("trigger: missing logger, recorder, reporter or default redirect")
	}
	h := &Handler{
		logger:          o.Logger,
		recorder:        o.Recorder,
		reporter:        o.Reporter,
		defaultRedirect: o.DefaultRedirect,
		limited: limitedRequests{counts: map[string]int{}, warn: func(ctx context.Context, l *slog.Logger, id string, n int) {
			l.WarnContext(ctx, "trigger: requests not recorded", slog.String("honeytoken_id", id), slog.Int("requests", n))
		}},
		limitedReports: limitedRequests{counts: map[string]int{}, warn: func(ctx context.Context, l *slog.Logger, id string, n int) {
			l.WarnContext(ctx, "trigger: reports not recorded", slog.String("honeypot_id", id), slog.Int("reports", n))
		}},
	}
	// The middleware of the console is not used: its request IDs, JSON errors
	// and redirects of unclean paths would each identify the trigger.
	h.next = httpx.ClientIP(o.TrustedProxies)(http.HandlerFunc(h.serve))
	return h
}

// ServeHTTP implements http.Handler. A panic is answered with the default
// response, so that it looks like every other answer; net/http would abort the
// connection instead.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	aw := &answerWriter{ResponseWriter: w}
	defer h.recoverPanic(aw, r)
	h.next.ServeHTTP(aw, r)
}

// recoverPanic must be deferred directly, because recover only stops a panic
// when it is called by the deferred function itself.
func (h *Handler) recoverPanic(w *answerWriter, r *http.Request) {
	v := recover()
	if v == nil {
		return
	}
	if v == http.ErrAbortHandler { //nolint:errorlint // recover returns the panic value itself, never a wrapped error.
		panic(v)
	}
	h.logger.ErrorContext(r.Context(), "trigger: handler panicked",
		slog.String("panic", fmt.Sprint(v)),
		slog.String("stack", string(debug.Stack())),
	)
	if w.answered {
		// A truncated answer must not look complete.
		panic(http.ErrAbortHandler)
	}
	h.answer(w, r.URL.Path, "")
}

// answerWriter remembers whether the answer has started.
type answerWriter struct {
	http.ResponseWriter
	answered bool
}

func (w *answerWriter) WriteHeader(status int) {
	w.answered = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *answerWriter) Write(b []byte) (int, error) {
	w.answered = true
	return w.ResponseWriter.Write(b)
}

// Run logs the requests and reports that the limit of events kept from being
// recorded, at most once per interval and honeytoken or honeypot, until ctx is
// canceled.
func (h *Handler) Run(ctx context.Context) {
	ticker := time.NewTicker(limitLogInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.limited.flush(ctx, h.logger)
			h.limitedReports.flush(ctx, h.logger)
		case <-ctx.Done():
			h.limited.flush(context.WithoutCancel(ctx), h.logger)
			h.limitedReports.flush(context.WithoutCancel(ctx), h.logger)
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
	// Paths are compared in lower case: a URL can be written in upper case on
	// its way, for example in the alphanumeric mode of a QR code.
	path := strings.ToLower(r.URL.Path)
	value, ok := triggerValue(path)
	switch {
	case r.Method == http.MethodPost && path == reportPath:
		// A sensor reports here. The answer is the one that every other POST
		// receives, whatever became of the report.
		attrs = h.report(r, attrs)
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

	status := h.answer(w, path, res.RedirectURL)

	// The path holds the trigger value, so it stays out of the log.
	attrs = append(attrs, slog.Int("status", status), slog.Duration("duration", time.Since(start)))
	if ip := request.ClientIP(r.Context()); ip.IsValid() {
		attrs = append(attrs, slog.String("client_ip", ip.String()))
	}
	h.logger.LogAttrs(r.Context(), slog.LevelInfo, "trigger: request", attrs...)
}

// answer writes the answer for the form of path: the image for a path that ends
// with ".gif", otherwise a redirect to redirectURL or the default target. It
// returns the status code.
func (h *Handler) answer(w http.ResponseWriter, path, redirectURL string) int {
	if strings.HasSuffix(strings.ToLower(path), imageSuffix) {
		writeImage(w)
		return http.StatusOK
	}
	if redirectURL == "" {
		redirectURL = h.defaultRedirect
	}
	writeRedirect(w, redirectURL)
	return http.StatusFound
}

func (h *Handler) record(ctx context.Context, req Request) (Result, error) {
	ctx, cancel := recordingContext(ctx)
	defer cancel()
	return h.recorder.Record(ctx, req)
}

// recordingContext returns the context of a recording. A client that closes
// the connection right after its request must not cancel the recording, or it
// could request a honeytoken without leaving an event.
func recordingContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
}

// reportPath is where sensors send their reports.
const reportPath = "/"

// report records the report of a sensor, if the request carries the form of
// one, and returns the attributes of the log. It writes no response. The log
// names the honeypot, its service and the type of the event, never the secret
// or anything that the sensor chose.
func (h *Handler) report(r *http.Request, attrs []slog.Attr) []slog.Attr {
	secret, ok := bearerSecret(r.Header.Get("Authorization"))
	if !ok {
		return append(attrs, slog.String("outcome", "not_looked_up"))
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return append(attrs, slog.String("outcome", "rejected"), slog.String("reason", "invalid_report"))
	}
	rep, err := DecodeReport(body)
	switch {
	case errors.Is(err, ErrUnsupportedVersion):
		return append(attrs, slog.String("outcome", "rejected"), slog.String("reason", "unsupported_version"))
	case err != nil:
		return append(attrs, slog.String("outcome", "rejected"), slog.String("reason", "invalid_report"))
	}
	attrs = append(attrs, slog.String("report", rep.Kind()))

	ctx, cancel := recordingContext(r.Context())
	defer cancel()
	var res ReportResult
	hash := SecretHash(secret)
	if rep.Session != nil {
		res, err = h.reporter.RecordSession(ctx, hash, *rep.Session)
		attrs = append(attrs, slog.String("event_type", string(rep.Session.EventType())))
	} else {
		res, err = h.reporter.RecordHeartbeat(ctx, hash, *rep.Heartbeat)
	}
	if err != nil {
		h.logger.ErrorContext(r.Context(), "trigger: recording failed", slog.Any("error", err))
		return append(attrs, slog.String("outcome", "failed"))
	}
	if res.Outcome == ReportInvalid {
		attrs = append(attrs, slog.String("outcome", "rejected"), slog.String("reason", "invalid_report"))
	} else {
		attrs = append(attrs, slog.String("outcome", string(res.Outcome)))
	}
	if res.HoneypotID != "" {
		attrs = append(attrs, slog.String("honeypot_id", res.HoneypotID), slog.String("service", res.Service))
	}
	if res.Outcome == ReportLimited {
		h.limitedReports.add(res.HoneypotID)
	}
	return attrs
}

// bearerSecret returns the secret of an Authorization header of the form
// "Bearer <secret>", if the value has the form of a secret.
func bearerSecret(header string) (string, bool) {
	const scheme = "Bearer "
	if len(header) != len(scheme)+secretLength || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}
	secret := header[len(scheme):]
	return secret, isSecret(secret)
}

// triggerValue extracts the trigger value from the lowercase path of a URL of a
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

// untrusted prepares a header value for the database: invalid UTF-8 and every
// character that is not printable are replaced, so that a value cannot break
// the lines of a log or a report, and the value is cut to at most maxBytes
// without splitting a character. Beside control characters this covers line
// separators and format characters, which can reorder or hide text: an
// override of the writing direction makes a Referer read as another address.
// Spaces other than U+0020 are replaced as well, because a run of wide spaces
// can push the rest of a value out of sight. The checks of the events table
// refuse the control characters, separators and common format characters, in
// case a compromised trigger skips this; only this function replaces the
// rest, such as other spaces, rare format characters and code points that
// Go does not know.
func untrusted(s string, maxBytes int) string {
	s = strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
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

// limitedRequests counts, per honeytoken or honeypot, the requests or reports
// that its limit of events kept from being recorded since they were last
// logged.
type limitedRequests struct {
	mu     sync.Mutex
	counts map[string]int
	// warn logs the count of one identifier.
	warn func(ctx context.Context, logger *slog.Logger, id string, n int)
}

func (l *limitedRequests) add(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counts[id]++
}

func (l *limitedRequests) flush(ctx context.Context, logger *slog.Logger) {
	l.mu.Lock()
	counts := l.counts
	l.counts = map[string]int{}
	l.mu.Unlock()
	for id, n := range counts {
		l.warn(ctx, logger, id, n)
	}
}
