// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package trigger

import (
	"bytes"
	"context"
	"errors"
	"image/gif"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

const (
	defaultRedirect = "https://www.example.com/"
	value           = "q3xwz7a2kfm4ub6tyc5nre2lpa"
)

// fakeRecorder answers with the result configured for a value, and records the
// requests it receives.
type fakeRecorder struct {
	mu       sync.Mutex
	results  map[string]Result
	err      error
	panics   bool
	requests []Request
}

func (f *fakeRecorder) Record(ctx context.Context, r Request) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r)
	if f.panics {
		panic("recorder failed")
	}
	if f.err != nil {
		return Result{}, f.err
	}
	if _, ok := ctx.Deadline(); !ok {
		return Result{}, errors.New("no deadline")
	}
	if res, ok := f.results[r.Value]; ok {
		return res, nil
	}
	return Result{Outcome: OutcomeUnknown}, nil
}

func (f *fakeRecorder) recorded() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

// response is what a client receives, without the Date header, which differs
// between any two responses.
type response struct {
	status int
	header http.Header
	body   []byte
}

func newServer(t *testing.T, rec Recorder, trusted ...netip.Prefix) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	var log bytes.Buffer
	h := New(Options{
		Logger:          slog.New(slog.NewJSONHandler(&log, nil)),
		Recorder:        rec,
		DefaultRedirect: defaultRedirect,
		TrustedProxies:  trusted,
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, &log
}

func fetch(t *testing.T, srv *httptest.Server, method, path string, body io.Reader, header http.Header) response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	maps.Copy(req.Header, header)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	res.Header.Del("Date")
	return response{status: res.StatusCode, header: res.Header, body: b}
}

func (r response) equal(o response) bool {
	return r.status == o.status && bytes.Equal(r.body, o.body) && maps.EqualFunc(r.header, o.header, slices.Equal)
}

// Trigger responses must not tell an observer anything about a value: valid,
// unknown, disabled, limited and failing requests, and requests of a value of
// another type, receive the same status, headers and body. The test uses a real
// server, because a recorder does not show what net/http adds or removes.
func TestTrigger_IdenticalResponsesForEveryOutcome(t *testing.T) {
	t.Parallel()

	results := map[string]Result{
		"recordedaaaaaaaaaaaaaaaaaa": {Outcome: OutcomeRecorded, HoneytokenID: "1"},
		"disabledaaaaaaaaaaaaaaaaaa": {Outcome: OutcomeDisabled, HoneytokenID: "2"},
		"limitedaaaaaaaaaaaaaaaaaaa": {Outcome: OutcomeLimited, HoneytokenID: "3"},
	}
	ok, _ := newServer(t, &fakeRecorder{results: results})
	failing, _ := newServer(t, &fakeRecorder{err: errors.New("database unavailable")})
	panicking, _ := newServer(t, &fakeRecorder{panics: true})

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, suffix := range []string{"", ".gif"} {
			want := fetch(t, ok, method, "/"+value+suffix, nil, nil)
			cases := map[string]response{
				"recorded":         fetch(t, ok, method, "/recordedaaaaaaaaaaaaaaaaaa"+suffix, nil, nil),
				"disabled":         fetch(t, ok, method, "/disabledaaaaaaaaaaaaaaaaaa"+suffix, nil, nil),
				"limited":          fetch(t, ok, method, "/limitedaaaaaaaaaaaaaaaaaaa"+suffix, nil, nil),
				"database failure": fetch(t, failing, method, "/"+value+suffix, nil, nil),
				"panic":            fetch(t, panicking, method, "/"+value+suffix, nil, nil),
				"no value":         fetch(t, ok, method, "/robots"+suffix, nil, nil),
			}
			for name, got := range cases {
				if !got.equal(want) {
					t.Errorf("%s %q, %s: response %+v, want %+v as for an unknown value", method, suffix, name, got, want)
				}
			}
		}
	}
}

// A panic anywhere in the handler is answered like every other request, not
// with an aborted connection.
func TestTrigger_PanicIsAnsweredWithTheDefaultResponse(t *testing.T) {
	t.Parallel()

	ok, _ := newServer(t, &fakeRecorder{})
	want := fetch(t, ok, http.MethodGet, "/"+value, nil, nil)
	wantImage := fetch(t, ok, http.MethodGet, "/"+value+".gif", nil, nil)

	var log bytes.Buffer
	h := New(Options{Logger: slog.New(slog.NewJSONHandler(&log, nil)), Recorder: &fakeRecorder{}, DefaultRedirect: defaultRedirect})
	h.next = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("handler failed") })
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	if got := fetch(t, srv, http.MethodGet, "/"+value, nil, nil); !got.equal(want) {
		t.Errorf("response after a panic = %+v, want %+v", got, want)
	}
	if got := fetch(t, srv, http.MethodGet, "/"+value+".gif", nil, nil); !got.equal(wantImage) {
		t.Errorf("image after a panic = %+v, want %+v", got, wantImage)
	}
	if !strings.Contains(log.String(), `"msg":"trigger: handler panicked"`) {
		t.Errorf("log = %s, want the panic", log.String())
	}
}

// The only difference the trigger may show is the redirect target that the
// operator configured for a honeytoken, and only in the Location header.
func TestTrigger_ConfiguredRedirectChangesOnlyTheLocation(t *testing.T) {
	t.Parallel()

	const target = "https://wiki.example.com/finance"
	srv, _ := newServer(t, &fakeRecorder{results: map[string]Result{
		value: {Outcome: OutcomeRecorded, HoneytokenID: "1", RedirectURL: target},
	}})

	got := fetch(t, srv, http.MethodGet, "/"+value, nil, nil)
	want := fetch(t, srv, http.MethodGet, "/aaaaaaaaaaaaaaaaaaaaaaaaaa", nil, nil)
	if loc := got.header.Get("Location"); loc != target {
		t.Errorf("Location = %q, want %q", loc, target)
	}
	got.header.Set("Location", defaultRedirect)
	if !got.equal(want) {
		t.Errorf("response with a configured target %+v differs from %+v beyond the Location", got, want)
	}

	// An image never redirects, whatever the honeytoken.
	if img, want := fetch(t, srv, http.MethodGet, "/"+value+".gif", nil, nil), fetch(t, srv, http.MethodGet, "/x.gif", nil, nil); !img.equal(want) {
		t.Errorf("image of a honeytoken with a redirect %+v, want %+v", img, want)
	}
}

func TestTrigger_ResponsesCarryNoFingerprint(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t, &fakeRecorder{})
	redirect := fetch(t, srv, http.MethodGet, "/"+value, nil, nil)
	if redirect.status != http.StatusFound || len(redirect.body) != 0 {
		t.Errorf("redirect = %d %q, want 302 without a body", redirect.status, redirect.body)
	}
	if got, want := slices.Sorted(maps.Keys(redirect.header)), []string{"Cache-Control", "Content-Length", "Location"}; !slices.Equal(got, want) {
		t.Errorf("redirect headers = %v, want %v", got, want)
	}
	if redirect.header.Get("Location") != defaultRedirect || redirect.header.Get("Cache-Control") != "no-store" {
		t.Errorf("redirect headers = %v", redirect.header)
	}

	image := fetch(t, srv, http.MethodGet, "/"+value+".gif", nil, nil)
	if image.status != http.StatusOK || !bytes.Equal(image.body, pixel) {
		t.Errorf("image = %d %q, want 200 with the pixel", image.status, image.body)
	}
	if got, want := slices.Sorted(maps.Keys(image.header)), []string{"Cache-Control", "Content-Length", "Content-Type"}; !slices.Equal(got, want) {
		t.Errorf("image headers = %v, want %v", got, want)
	}
	if image.header.Get("Content-Type") != "image/gif" || image.header.Get("Cache-Control") != "no-store" {
		t.Errorf("image headers = %v", image.header)
	}

	for _, r := range []response{redirect, image} {
		for _, name := range []string{"Server", "X-Powered-By", "X-Request-Id"} {
			if v := r.header.Get(name); v != "" {
				t.Errorf("%s = %q, want no such header", name, v)
			}
		}
	}
}

func TestPixel_IsATransparentImageOfOnePixel(t *testing.T) {
	t.Parallel()

	img, err := gif.Decode(bytes.NewReader(pixel))
	if err != nil {
		t.Fatalf("decode pixel: %v", err)
	}
	if b := img.Bounds(); b.Dx() != 1 || b.Dy() != 1 {
		t.Errorf("bounds = %v, want 1x1", b)
	}
	if _, _, _, a := img.At(0, 0).RGBA(); a != 0 {
		t.Errorf("alpha = %d, want transparent", a)
	}
}

// Paths without a trigger value, unclean paths and methods other than GET and
// HEAD are answered like an unknown value, without asking the database.
func TestTrigger_AnswersEverythingElseWithoutLookingItUp(t *testing.T) {
	t.Parallel()

	rec := &fakeRecorder{}
	srv, _ := newServer(t, rec)
	want := fetch(t, srv, http.MethodGet, "/aaaaaaaaaaaaaaaaaaaaaaaaaa", nil, nil)
	wantImage := fetch(t, srv, http.MethodGet, "/aaaaaaaaaaaaaaaaaaaaaaaaaa.gif", nil, nil)
	before := len(rec.recorded())

	for _, path := range []string{
		"/", "/robots.txt", "/favicon.ico", "/" + value + "/", "/" + value + "a",
		"/" + value + "?x=1&token=" + value, "//" + value, "/./" + value, "/a/../" + value, "/" + value + ".png",
	} {
		if got := fetch(t, srv, http.MethodGet, path, nil, nil); !got.equal(want) {
			t.Errorf("GET %s = %+v, want %+v", path, got, want)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions, "PROPFIND"} {
		if got := fetch(t, srv, method, "/"+value, strings.NewReader("{}"), nil); !got.equal(want) {
			t.Errorf("%s = %+v, want %+v", method, got, want)
		}
		if got := fetch(t, srv, method, "/"+value+".gif", nil, nil); !got.equal(wantImage) {
			t.Errorf("%s image = %+v, want %+v", method, got, wantImage)
		}
	}

	// A query does not hide the value: the path alone counts.
	if got := rec.recorded()[before:]; len(got) != 1 || got[0].Value != value {
		t.Errorf("looked up %+v, want only the request with a query", got)
	}
}

// Request bodies on the trigger are limited to 64 KiB. The trigger never reads
// them, so a larger body changes nothing.
func TestTrigger_LargeBodyChangesNothing(t *testing.T) {
	t.Parallel()

	rec := &fakeRecorder{}
	srv, _ := newServer(t, rec)
	want := fetch(t, srv, http.MethodPost, "/"+value, nil, nil)
	got := fetch(t, srv, http.MethodPost, "/"+value, bytes.NewReader(make([]byte, 1<<20)), nil)
	if !got.equal(want) {
		t.Errorf("POST with 1 MiB = %+v, want %+v", got, want)
	}
	if len(rec.recorded()) != 0 {
		t.Error("a POST was recorded")
	}
}

type recorderFunc func(context.Context, Request) (Result, error)

func (f recorderFunc) Record(ctx context.Context, r Request) (Result, error) { return f(ctx, r) }

func TestTrigger_RecordsTheRequest(t *testing.T) {
	t.Parallel()

	rec := &fakeRecorder{}
	srv, _ := newServer(t, rec, netip.MustParsePrefix("127.0.0.0/8"))
	header := http.Header{
		"User-Agent":      {"curl/8.0\t\xffx"},
		"Referer":         {"https://intranet.example.com/finance"},
		"Accept-Language": {"de-DE,de;q=0.9"},
		"X-Forwarded-For": {"198.51.100.7"},
		"Cookie":          {"session=1"},
	}
	fetch(t, srv, http.MethodGet, "/"+value+".gif", nil, header)
	fetch(t, srv, http.MethodHead, "/"+value, nil, nil)

	got := rec.recorded()
	want := []Request{
		{
			Value: value, Method: http.MethodGet, ClientIP: netip.MustParseAddr("198.51.100.7"),
			UserAgent: "curl/8.0\uFFFD\uFFFDx", Referer: "https://intranet.example.com/finance", AcceptLanguage: "de-DE,de;q=0.9",
		},
		{Value: value, Method: http.MethodHead, ClientIP: netip.MustParseAddr("127.0.0.1"), UserAgent: "Go-http-client/1.1"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("recorded %+v, want %+v", got, want)
	}
}

// A URL can be written in upper case on its way, for example in the
// alphanumeric mode of a QR code. Its requests still count.
func TestTrigger_ReadsURLsInAnyCase(t *testing.T) {
	t.Parallel()

	rec := &fakeRecorder{}
	srv, _ := newServer(t, rec)
	if got, want := fetch(t, srv, http.MethodGet, "/"+strings.ToUpper(value), nil, nil), fetch(t, srv, http.MethodGet, "/x", nil, nil); !got.equal(want) {
		t.Errorf("upper case URL = %+v, want %+v", got, want)
	}
	if got, want := fetch(t, srv, http.MethodGet, "/"+strings.ToUpper(value)+".GIF", nil, nil), fetch(t, srv, http.MethodGet, "/x.gif", nil, nil); !got.equal(want) {
		t.Errorf("upper case image = %+v, want %+v", got, want)
	}
	if got := rec.recorded(); len(got) != 2 || got[0].Value != value || got[1].Value != value {
		t.Errorf("looked up %+v, want the value in lower case twice", got)
	}
}

// A client that closes the connection right after its request must not keep
// it from being recorded.
func TestTrigger_RecordingOutlivesTheClient(t *testing.T) {
	t.Parallel()

	var canceled error
	h := New(Options{Logger: slog.New(slog.DiscardHandler), Recorder: recorderFunc(func(ctx context.Context, _ Request) (Result, error) {
		canceled = ctx.Err()
		return Result{Outcome: OutcomeRecorded}, nil
	}), DefaultRedirect: defaultRedirect})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(ctx, http.MethodGet, "/"+value, nil))
	if canceled != nil {
		t.Errorf("recording ran with a canceled context: %v", canceled)
	}
}

func TestUntrusted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, in string
		maxBytes int
		want     string
	}{
		{name: "plain", in: "Mozilla/5.0", maxBytes: 512, want: "Mozilla/5.0"},
		{name: "control characters", in: "a\x00b\tc\nd\x7fe", maxBytes: 512, want: "a\uFFFDb\uFFFDc\uFFFDd\uFFFDe"},
		{name: "invalid UTF-8", in: "a\xff\xfeb", maxBytes: 512, want: "a\uFFFDb"},
		{name: "cut", in: strings.Repeat("a", 600), maxBytes: 512, want: strings.Repeat("a", 512)},
		{name: "cut before a character", in: "a\u00e4", maxBytes: 2, want: "a"},
		{name: "replacement grows the value", in: strings.Repeat("\x01", 200), maxBytes: 512, want: strings.Repeat("\uFFFD", 170)},
	}
	for _, tt := range tests {
		if got := untrusted(tt.in, tt.maxBytes); got != tt.want {
			t.Errorf("%s: untrusted(%q) = %q, want %q", tt.name, tt.in, got, tt.want)
		}
		if got := untrusted(tt.in, tt.maxBytes); len(got) > tt.maxBytes || !utf8.ValidString(got) {
			t.Errorf("%s: untrusted(%q) = %q, longer than %d bytes or invalid", tt.name, tt.in, got, tt.maxBytes)
		}
	}
}

// The log names the honeytoken by its identifier, never the requested value,
// which would let whoever reads the log trigger the honeytoken.
func TestTrigger_LogsNoTriggerValue(t *testing.T) {
	t.Parallel()

	srv, log := newServer(t, &fakeRecorder{results: map[string]Result{value: {Outcome: OutcomeRecorded, HoneytokenID: "4f1c"}}})
	fetch(t, srv, http.MethodGet, "/"+value+"?q="+value, nil, nil)
	if strings.Contains(log.String(), value[:10]) {
		t.Errorf("log contains the trigger value: %s", log)
	}
	for _, want := range []string{`"msg":"trigger: request"`, `"outcome":"recorded"`, `"honeytoken_id":"4f1c"`, `"status":302`} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("log does not contain %s: %s", want, log)
		}
	}
}

func TestTrigger_LogsRequestsBeyondTheLimit(t *testing.T) {
	t.Parallel()

	var log bytes.Buffer
	h := New(Options{
		Logger:          slog.New(slog.NewJSONHandler(&log, nil)),
		Recorder:        &fakeRecorder{results: map[string]Result{value: {Outcome: OutcomeLimited, HoneytokenID: "4f1c"}}},
		DefaultRedirect: defaultRedirect,
	})
	for range 3 {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/"+value, nil))
	}
	if strings.Contains(log.String(), "not recorded") {
		t.Fatalf("logged before the interval ended: %s", log.String())
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	h.Run(ctx)
	if !strings.Contains(log.String(), `"msg":"trigger: requests not recorded","honeytoken_id":"4f1c","requests":3`) {
		t.Errorf("log = %s, want the three requests beyond the limit", log.String())
	}
	log.Reset()
	h.limited.flush(t.Context(), h.logger)
	if log.Len() != 0 {
		t.Errorf("logged the same requests twice: %s", log.String())
	}
}

// A recorder that takes too long must not keep the client waiting: the request
// is answered after the timeout like any other.
func TestTrigger_RecordingHasADeadline(t *testing.T) {
	t.Parallel()

	var remaining time.Duration
	h := New(Options{Logger: slog.New(slog.DiscardHandler), Recorder: recorderFunc(func(ctx context.Context, _ Request) (Result, error) {
		if deadline, ok := ctx.Deadline(); ok {
			remaining = time.Until(deadline)
		}
		return Result{}, ctx.Err()
	}), DefaultRedirect: defaultRedirect})
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/"+value, nil))
	if remaining <= 0 || remaining > recordTimeout {
		t.Errorf("time left for recording = %v, want at most %v", remaining, recordTimeout)
	}
}

func TestTriggerValue(t *testing.T) {
	t.Parallel()

	for path, want := range map[string]bool{
		"/" + value:                   true,
		"/" + value + ".gif":          true,
		"/" + value + ".gif.gif":      false,
		"/" + strings.ToUpper(value):  false,
		"/" + value[:25]:              false,
		"/" + value[:25] + "1":        false,
		"/" + value[:25] + "8":        false,
		value:                         false,
		"/" + value + "/":             false,
		"/":                           false,
		"/x/" + value:                 false,
		"/" + value[:24] + "\u00e4":   false,
		"/" + strings.Repeat("a", 26): true,
	} {
		if _, ok := triggerValue(path); ok != want {
			t.Errorf("triggerValue(%q) = %v, want %v", path, ok, want)
		}
	}
}
