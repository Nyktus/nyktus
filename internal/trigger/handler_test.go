// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package trigger

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"image/gif"
	"io"
	"log/slog"
	"maps"
	"net"
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
	return newReportingServer(t, rec, &fakeReporter{}, trusted...)
}

func newReportingServer(t *testing.T, rec Recorder, rep Reporter, trusted ...netip.Prefix) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	var log bytes.Buffer
	h := New(Options{
		Logger:          slog.New(slog.NewJSONHandler(&log, nil)),
		Recorder:        rec,
		Reporter:        rep,
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
	h := New(Options{Logger: slog.New(slog.NewJSONHandler(&log, nil)), Recorder: &fakeRecorder{}, Reporter: &fakeReporter{}, DefaultRedirect: defaultRedirect})
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

// Paths without a trigger value, unclean paths and methods other than GET,
// HEAD and POST are answered like an unknown value, without asking the
// database.
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
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions, "PROPFIND"} {
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

// Request bodies on the trigger are limited to 64 KiB, and only the start of
// the body of a POST is read: a larger body changes neither the answer nor what
// is recorded.
func TestTrigger_LargeBodyChangesNothing(t *testing.T) {
	t.Parallel()

	rec := &fakeRecorder{}
	srv, _ := newServer(t, rec)
	want := fetch(t, srv, http.MethodPost, "/"+value, nil, nil)
	got := fetch(t, srv, http.MethodPost, "/"+value, bytes.NewReader(bytes.Repeat([]byte("a"), 1<<20)), nil)
	if !got.equal(want) {
		t.Errorf("POST with 1 MiB = %+v, want %+v", got, want)
	}
	requests := rec.recorded()
	if len(requests) != 2 || requests[0].Body != "" || requests[1].Body != strings.Repeat("a", maxBodyExcerptBytes) {
		t.Errorf("recorded %d requests, want the empty body and an excerpt of %d bytes", len(requests), maxBodyExcerptBytes)
	}
}

// Every POST is answered with the same status and no body, whatever its path
// and whatever became of it: a log shipper or a webhook repeats a request that
// it does not see succeed, and an answer that differed for a value that is
// unknown, disabled or limited would tell an observer which values are live.
// The test uses a real server, because a recorder does not show what net/http
// adds or removes.
func TestTrigger_IdenticalResponsesToEveryPost(t *testing.T) {
	t.Parallel()

	results := map[string]Result{
		"recordedaaaaaaaaaaaaaaaaaa": {Outcome: OutcomeRecorded, HoneytokenID: "1", RedirectURL: "https://wiki.example.com/finance"},
		"disabledaaaaaaaaaaaaaaaaaa": {Outcome: OutcomeDisabled, HoneytokenID: "2"},
		"limitedaaaaaaaaaaaaaaaaaaa": {Outcome: OutcomeLimited, HoneytokenID: "3"},
	}
	ok, _ := newServer(t, &fakeRecorder{results: results})
	failing, _ := newServer(t, &fakeRecorder{err: errors.New("database unavailable")})
	panicking, _ := newServer(t, &fakeRecorder{panics: true})

	bodies := map[string][]byte{
		"empty":          nil,
		"json":           []byte(`{"TargetUserName":"svc-backup","IpAddress":"203.0.113.9"}`),
		"not text":       {0xff, 0xfe, 0x00, 0x1b, '[', 0xe2, 0x80, 0xae, '\n'},
		"beyond 4 KiB":   bytes.Repeat([]byte("x"), 2*maxBodyExcerptBytes),
		"beyond 64 KiB":  bytes.Repeat([]byte("x"), maxBodyBytes+1),
		"far beyond 64K": bytes.Repeat([]byte("x"), 1<<20),
	}
	for name, body := range bodies {
		for _, suffix := range []string{"", ".gif"} {
			want := fetch(t, ok, http.MethodPost, "/"+value+suffix, bytes.NewReader(body), nil)
			if want.status != http.StatusOK || len(want.body) != 0 || want.header.Get("Location") != "" || want.header.Get("Content-Type") != "" {
				t.Fatalf("POST answer = %+v, want 200 without a body, a Location or a Content-Type", want)
			}
			cases := map[string]response{
				"recorded with a redirect": fetch(t, ok, http.MethodPost, "/recordedaaaaaaaaaaaaaaaaaa"+suffix, bytes.NewReader(body), nil),
				"disabled":                 fetch(t, ok, http.MethodPost, "/disabledaaaaaaaaaaaaaaaaaa"+suffix, bytes.NewReader(body), nil),
				"limited":                  fetch(t, ok, http.MethodPost, "/limitedaaaaaaaaaaaaaaaaaaa"+suffix, bytes.NewReader(body), nil),
				"database failure":         fetch(t, failing, http.MethodPost, "/"+value+suffix, bytes.NewReader(body), nil),
				"panic":                    fetch(t, panicking, http.MethodPost, "/"+value+suffix, bytes.NewReader(body), nil),
				"no value":                 fetch(t, ok, http.MethodPost, "/robots"+suffix, bytes.NewReader(body), nil),
				"root":                     fetch(t, ok, http.MethodPost, "/", bytes.NewReader(body), nil),
				"root with a bearer":       fetch(t, ok, http.MethodPost, "/", bytes.NewReader(body), bearer(testSecret)),
			}
			for caseName, got := range cases {
				if !got.equal(want) {
					t.Errorf("body %s, %q, %s: response %+v, want %+v", name, suffix, caseName, got, want)
				}
			}
		}
	}
}

// The answer to a POST is the same after a panic in the handler.
func TestTrigger_PanicOnAPostIsAnsweredLikeEveryOtherPost(t *testing.T) {
	t.Parallel()

	ok, _ := newServer(t, &fakeRecorder{})
	want := fetch(t, ok, http.MethodPost, "/"+value, nil, nil)

	var log bytes.Buffer
	h := New(Options{Logger: slog.New(slog.NewJSONHandler(&log, nil)), Recorder: &fakeRecorder{}, Reporter: &fakeReporter{}, DefaultRedirect: defaultRedirect})
	h.next = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("handler failed") })
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	for _, path := range []string{"/" + value, "/" + value + ".gif", "/"} {
		if got := fetch(t, srv, http.MethodPost, path, nil, nil); !got.equal(want) {
			t.Errorf("POST %s after a panic = %+v, want %+v", path, got, want)
		}
	}
}

// Only a POST has a body that is recorded, and it is recorded as untrusted
// text: line breaks and tabs become spaces, every other character that is not
// printable is replaced, and the excerpt ends at a character, not inside one.
func TestTrigger_PostRecordsTheBodyAsCleanedExcerpt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string
	}{
		{"empty", "", ""},
		{"text", `{"user":"alice"}`, `{"user":"alice"}`},
		{"line breaks and tabs", "a\r\nb\tc\nd", "a  b c d"},
		{"control characters", "a\x00b\x1bc\x7fd", "a\uFFFDb\uFFFDc\uFFFDd"},
		{"override of the writing direction", "a\u202Eb\u2028c", "a\uFFFDb\uFFFDc"},
		{"invalid UTF-8", "a\xffb", "a\uFFFDb"},
		// A run of invalid bytes becomes one replacement character, as in a header.
		{"a run of invalid UTF-8", "a\xff\xfe\xfdb", "a\uFFFDb"},
		{"exactly the limit", strings.Repeat("a", maxBodyExcerptBytes), strings.Repeat("a", maxBodyExcerptBytes)},
		{"beyond the limit", strings.Repeat("a", maxBodyExcerptBytes+1), strings.Repeat("a", maxBodyExcerptBytes)},
		// Two bytes each: 2048 characters fit exactly, a character that crosses the limit is cut as a whole.
		{"characters of two bytes", strings.Repeat("\u00E9", 3000), strings.Repeat("\u00E9", maxBodyExcerptBytes/2)},
		{"a character that crosses the limit", strings.Repeat("a", maxBodyExcerptBytes-1) + "\u00E9", strings.Repeat("a", maxBodyExcerptBytes-1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := &fakeRecorder{}
			srv, _ := newServer(t, rec)
			fetch(t, srv, http.MethodPost, "/"+value, strings.NewReader(tt.body), nil)
			got := rec.recorded()
			if len(got) != 1 || got[0].Method != http.MethodPost || got[0].Body != tt.want {
				t.Errorf("recorded %+v, want one POST with the body %q", got, tt.want)
			}
			if !utf8.ValidString(got[0].Body) || len(got[0].Body) > maxBodyExcerptBytes {
				t.Errorf("body of %d bytes, want valid UTF-8 of at most %d", len(got[0].Body), maxBodyExcerptBytes)
			}
		})
	}
}

// The webhooks of the cloud deceptions report the caller only in the body. The
// EventBridge input transformer of the guides yields a short JSON object that
// is kept whole. The alert of Azure Monitor in the common schema (built in the
// order of the sample in its documentation) is longer than the excerpt, and the
// dimensions with the address of the caller must lie within it, before the long
// links that the alert carries after them.
func TestTrigger_PostKeepsTheCallerOfACloudWebhook(t *testing.T) {
	t.Parallel()

	eventBridge := `{"eventName":"GetSecretValue","sourceIPAddress":"203.0.113.10","userAgent":"aws-cli/2.17.0 md/awscrt#0.20.11 ua/2.0 os/linux#6.1 md/arch#x86_64 lang/python#3.12.4 md/pyimpl#CPython cfg/retry-mode#standard md/installer#exe md/prompt#off md/command#secretsmanager.get-secret-value","userArn":"arn:aws:sts::123456789012:assumed-role/ops/jane","userType":"AssumedRole","accountId":"123456789012","region":"eu-central-1","time":"2026-01-01T10:00:00Z"}`
	link := "https://portal.azure.com#@00000000-0000-0000-0000-000000000000/blade/Microsoft_Azure_Monitoring_Logs/LogsBlade/source/Alerts.EmailLinks/scope/" + strings.Repeat("%7B%22resources%22", 30)
	azure := `{"schemaId":"azureMonitorCommonAlertSchema","data":{"essentials":{` +
		`"alertId":"/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.AlertsManagement/alerts/00000000-0000-0000-0000-000000000000",` +
		`"alertRule":"audit-notify-rule","severity":"Sev1","signalType":"Log","monitorCondition":"Fired","monitoringService":"Log Alerts V2",` +
		`"alertTargetIDs":["/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/rg-orders/providers/microsoft.operationalinsights/workspaces/audit-notify-logs"],` +
		`"configurationItems":[],"originAlertId":"00000000-0000-0000-0000-000000000000","firedDateTime":"2026-01-01T10:05:00.1234567Z","description":"","essentialsVersion":"1.0","alertContextVersion":"1.0",` +
		`"alertRuleID":"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-orders/providers/microsoft.insights/scheduledqueryrules/audit-notify-rule"},` +
		`"alertContext":{"properties":null,"conditionType":"LogQueryCriteria","condition":{"windowSize":"PT10M","allOf":[{` +
		`"searchQuery":"AzureDiagnostics | where ResourceProvider == 'MICROSOFT.KEYVAULT' and OperationName == 'SecretGet' and requestUri_s has '/secrets/orders-db-password/'",` +
		`"metricMeasureColumn":null,"targetResourceTypes":"['Microsoft.OperationalInsights/workspaces']","operator":"GreaterThan","threshold":"0","timeAggregation":"Count",` +
		`"dimensions":[{"name":"CallerIPAddress","value":"203.0.113.10"},{"name":"clientInfo_s","value":"azsdk-python-keyvault-secrets/4.8.0 Python/3.12.4 (Linux)"},{"name":"ResultSignature","value":"OK"}],` +
		`"metricValue":1.0,"failingPeriods":{"numberOfEvaluationPeriods":1,"minFailingPeriodsToAlert":1},` +
		`"linkToSearchResultsUI":"` + link + `","linkToFilteredSearchResultsUI":"` + link + `",` +
		`"linkToSearchResultsAPI":"` + link + `","linkToFilteredSearchResultsAPI":"` + link + `"}],` +
		`"windowStartTime":"2026-01-01T09:55:00Z","windowEndTime":"2026-01-01T10:05:00Z"}}}}`
	if len(azure) <= maxBodyExcerptBytes {
		t.Fatalf("the sample alert has %d bytes, want more than the excerpt of %d", len(azure), maxBodyExcerptBytes)
	}

	tests := []struct {
		name string
		body string
		want []string
	}{
		{"EventBridge", eventBridge, []string{`"sourceIPAddress":"203.0.113.10"`, `"userArn":"arn:aws:sts::123456789012:assumed-role/ops/jane"`}},
		{"Azure Monitor", azure, []string{`{"name":"CallerIPAddress","value":"203.0.113.10"}`, `{"name":"ResultSignature","value":"OK"}`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := &fakeRecorder{}
			srv, _ := newServer(t, rec)
			fetch(t, srv, http.MethodPost, "/"+value, strings.NewReader(tt.body), http.Header{"Content-Type": {"application/json"}})
			got := rec.recorded()
			if len(got) != 1 || got[0].Method != http.MethodPost {
				t.Fatalf("recorded %+v, want one POST", got)
			}
			if !strings.HasPrefix(tt.body, got[0].Body) {
				t.Errorf("recorded body is no prefix of the sent body")
			}
			for _, w := range tt.want {
				if !strings.Contains(got[0].Body, w) {
					t.Errorf("recorded body lacks %s", w)
				}
			}
		})
	}
}

// A GET or HEAD request is recorded without the body that it may carry, and
// the other methods are not recorded.
func TestTrigger_OnlyAPostRecordsABody(t *testing.T) {
	t.Parallel()

	rec := &fakeRecorder{}
	srv, _ := newServer(t, rec)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		fetch(t, srv, method, "/"+value, strings.NewReader("secret=1"), nil)
	}
	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		fetch(t, srv, method, "/"+value, strings.NewReader("secret=1"), nil)
	}
	got := rec.recorded()
	if len(got) != 2 || got[0].Method != http.MethodGet || got[1].Method != http.MethodHead || got[0].Body != "" || got[1].Body != "" {
		t.Errorf("recorded %+v, want a GET and a HEAD without a body", got)
	}
}

// The body of a request that breaks off is recorded as far as it arrived: the
// request happened all the same, and the answer does not depend on it.
func TestTrigger_PostRecordsABodyThatBreaksOff(t *testing.T) {
	t.Parallel()

	rec := &fakeRecorder{}
	srv, _ := newServer(t, rec)
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(t.Context(), "tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "POST /"+value+" HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nuser=alice"); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// The server answers once it has recorded, or closes; either way it ends the connection.
	_, _ = io.Copy(io.Discard, conn)
	got := rec.recorded()
	if len(got) != 1 || got[0].Body != "user=alice" {
		t.Errorf("recorded %+v, want one POST with the body that arrived", got)
	}
}

// net/http answers Expect: 100-continue with an interim response only when the
// handler reads the body. Every POST is read, so that the answer to one with a
// value cannot be told from the answer to one without.
func TestTrigger_PostIsReadWhateverItsPath(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t, &fakeRecorder{})
	firstLine := func(path string) string {
		t.Helper()
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(t.Context(), "tcp", strings.TrimPrefix(srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.WriteString(conn, "POST "+path+" HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return line
	}
	want := firstLine("/" + value)
	if !strings.Contains(want, "100") {
		t.Fatalf("first line for a value = %q, want the interim response", want)
	}
	for _, path := range []string{"/", "/robots.txt", "/" + value + ".gif", "/" + value + "/"} {
		if got := firstLine(path); got != want {
			t.Errorf("first line for %s = %q, want %q", path, got, want)
		}
	}
}

// The body may hold personal data, so it never reaches the log, which names
// the request by its outcome only.
func TestTrigger_LogsNoBody(t *testing.T) {
	t.Parallel()

	const marker = "alice@example.com"
	for name, rec := range map[string]*fakeRecorder{
		"recorded": {results: map[string]Result{value: {Outcome: OutcomeRecorded, HoneytokenID: "1"}}},
		"limited":  {results: map[string]Result{value: {Outcome: OutcomeLimited, HoneytokenID: "1"}}},
		"failing":  {err: errors.New("database unavailable")},
		"panics":   {panics: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv, log := newServer(t, rec)
			fetch(t, srv, http.MethodPost, "/"+value, strings.NewReader(`{"user":"`+marker+`"}`), nil)
			if strings.Contains(log.String(), marker) || strings.Contains(log.String(), "alice") {
				t.Errorf("log = %s, want no part of the body", log.String())
			}
		})
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
	h := New(Options{Logger: slog.New(slog.DiscardHandler), Reporter: &fakeReporter{}, Recorder: recorderFunc(func(ctx context.Context, _ Request) (Result, error) {
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

	// Written as code points, so that no invisible character sits in the source.
	ch := func(cps ...rune) string { return string(cps) }
	bad := string(utf8.RuneError)

	tests := []struct {
		name, in string
		maxBytes int
		want     string
	}{
		{name: "plain", in: "Mozilla/5.0", maxBytes: 512, want: "Mozilla/5.0"},
		{name: "control characters", in: "a\x00b\tc\nd\x7fe", maxBytes: 512, want: "a\uFFFDb\uFFFDc\uFFFDd\uFFFDe"},
		{name: "C1 control character", in: "a" + ch(0x85) + "b", maxBytes: 512, want: "a" + bad + "b"},
		{name: "line and paragraph separators", in: "a" + ch(0x2028, 0x2029) + "b", maxBytes: 512, want: "a" + bad + bad + "b"},
		{name: "override of the writing direction", in: "https://" + ch(0x202e) + "moc.elpmaxe", maxBytes: 512, want: "https://" + bad + "moc.elpmaxe"},
		{name: "isolates of the writing direction", in: ch(0x2066, 0x2069), maxBytes: 512, want: bad + bad},
		{name: "invisible characters", in: "a" + ch(0xad, 0x200b, 0xfeff) + "b", maxBytes: 512, want: "a" + bad + bad + bad + "b"},
		{name: "spaces other than the ordinary one", in: "a" + ch(0xa0, 0x2003, 0x3000) + "b", maxBytes: 512, want: "a" + bad + bad + bad + "b"},
		{name: "printable text of other scripts stays", in: "Mozilla " + ch(0x4e2d, 0x6587) + " " + ch(0xe4, 0x1f600), maxBytes: 512, want: "Mozilla " + ch(0x4e2d, 0x6587) + " " + ch(0xe4, 0x1f600)},
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
		Reporter:        &fakeReporter{},
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
	h := New(Options{Logger: slog.New(slog.DiscardHandler), Reporter: &fakeReporter{}, Recorder: recorderFunc(func(ctx context.Context, _ Request) (Result, error) {
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

// Only the start of a body is read, so that a client cannot make the trigger
// read and clean more than it records; the characters that cross the end are
// read to the end of the character.
func TestReadBodyExcerpt_ReadsNoMoreThanItNeeds(t *testing.T) {
	t.Parallel()

	src := &countingReader{r: strings.NewReader(strings.Repeat("a", 1<<20))}
	if got := readBodyExcerpt(src); len(got) != maxBodyExcerptBytes {
		t.Errorf("excerpt of %d bytes, want %d", len(got), maxBodyExcerptBytes)
	}
	if src.n > maxBodyExcerptBytes+utf8.UTFMax {
		t.Errorf("read %d bytes, want at most %d", src.n, maxBodyExcerptBytes+utf8.UTFMax)
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// A client that sends the start of a body and then stalls does not hold the
// recording back until the read timeout of the server: the body is read within
// a short time, and what arrived is recorded while the connection is still
// open.
func TestTrigger_PostStallingBodyIsRecordedAfterAShortWait(t *testing.T) {
	t.Parallel()

	rec := &fakeRecorder{}
	var log bytes.Buffer
	h := New(Options{Logger: slog.New(slog.NewJSONHandler(&log, nil)), Recorder: rec, Reporter: &fakeReporter{}, DefaultRedirect: defaultRedirect})
	h.bodyTimeout = 50 * time.Millisecond
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(t.Context(), "tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "POST /"+value+" HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nuser="); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(rec.recorded()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the request was not recorded while its body stalled")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := rec.recorded(); len(got) != 1 || got[0].Body != "user=" {
		t.Errorf("recorded %+v, want one POST with the body that arrived", got)
	}
}

// A POST is never read beyond the start of its body, except the report of a
// sensor, which carries the form of a secret: a client without the form of one
// cannot make the trigger buffer 64 KiB.
func TestTrigger_PostIsReadOnlyAsFarAsItsExcerpt(t *testing.T) {
	t.Parallel()

	h := New(Options{Logger: slog.New(slog.DiscardHandler), Recorder: &fakeRecorder{}, Reporter: &fakeReporter{}, DefaultRedirect: defaultRedirect})
	for _, path := range []string{"/", "/" + value, "/robots.txt"} {
		body := &countingReader{r: strings.NewReader(strings.Repeat("a", 1<<20))}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, body)
		h.ServeHTTP(httptest.NewRecorder(), req)
		if limit := maxBodyExcerptBytes + utf8.UTFMax + 1; body.n > limit {
			t.Errorf("POST %s: read %d bytes, want at most %d", path, body.n, limit)
		}
	}
}
