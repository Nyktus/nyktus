// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package trigger

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// A request is recorded for the value of a honeytoken wherever it stands, and a
// client receives the answer to every other request of its form.
func TestTrigger_RecordsTheValueWhereverItStands(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		method string
		path   string
		header http.Header
	}{
		"later path segment":      {http.MethodGet, "/v2/" + value + "/status", nil},
		"query":                   {http.MethodGet, "/status?api_key=" + value, nil},
		"query, HEAD":             {http.MethodHead, "/status?api_key=" + value, nil},
		"bearer token":            {http.MethodGet, "/status", http.Header{"Authorization": {"Bearer " + value}}},
		"api key header":          {http.MethodGet, "/status", http.Header{"X-Api-Key": {value}}},
		"cookie":                  {http.MethodGet, "/status", http.Header{"Cookie": {"sid=" + value}}},
		"url credentials":         {http.MethodGet, "/status", http.Header{"Authorization": {"Basic " + basicOf("svc:"+value)}}},
		"POST to the root":        {http.MethodPost, "/", http.Header{"X-Api-Key": {value}}},
		"POST, query":             {http.MethodPost, "/ingest?key=" + value, nil},
		"POST to the root, query": {http.MethodPost, "/?key=" + value, nil},
	} {
		rec := &fakeRecorder{}
		srv, _ := newServer(t, rec)
		fetch(t, srv, tt.method, tt.path, strings.NewReader("x"), tt.header)
		got := rec.recorded()
		if len(got) != 1 || !slices.Equal(got[0].Values, []string{value}) || got[0].Method != tt.method {
			t.Errorf("%s: recorded %+v, want one request of %s for the value", name, got, tt.method)
		}
	}
}

// Whatever carries the value, the answer depends on the form of the request
// only: a valid, unknown, disabled or limited value, a failing database and a
// panic receive the same answer, also if the value stands in a query or a
// header, and an answer does not differ from that to a request without any value.
func TestTrigger_IdenticalResponsesWhateverCarriesTheValue(t *testing.T) {
	t.Parallel()

	results := map[string]Result{
		"recordedaaaaaaaaaaaaaaaaaa": {Outcome: OutcomeRecorded, HoneytokenID: "1"},
		"disabledaaaaaaaaaaaaaaaaaa": {Outcome: OutcomeDisabled, HoneytokenID: "2"},
		"limitedaaaaaaaaaaaaaaaaaaa": {Outcome: OutcomeLimited, HoneytokenID: "3"},
	}
	ok, _ := newServer(t, &fakeRecorder{results: results})
	failing, _ := newServer(t, &fakeRecorder{err: errors.New("database unavailable")})
	panicking, _ := newServer(t, &fakeRecorder{panics: true})

	carriers := map[string]func(v, suffix string) (string, http.Header){
		"path":   func(v, s string) (string, http.Header) { return "/a/" + v + s, nil },
		"query":  func(v, s string) (string, http.Header) { return "/a" + s + "?key=" + v, nil },
		"header": func(v, s string) (string, http.Header) { return "/a" + s, http.Header{"X-Api-Key": {v}} },
		"basic": func(v, s string) (string, http.Header) {
			return "/a" + s, http.Header{"Authorization": {"Basic " + basicOf("u:"+v)}}
		},
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		for _, suffix := range []string{"", ".gif"} {
			for carrier, at := range carriers {
				p, h := at("recordedaaaaaaaaaaaaaaaaaa", suffix)
				want := fetch(t, ok, method, p, nil, h)
				p, h = "/a"+suffix, nil
				if got := fetch(t, ok, method, p, nil, h); !got.equal(want) {
					t.Errorf("%s %q via %s: request without a value = %+v, want %+v", method, suffix, carrier, got, want)
				}
				for _, c := range []struct {
					name  string
					srv   *httptest.Server
					value string
				}{
					{"unknown", ok, value},
					{"disabled", ok, "disabledaaaaaaaaaaaaaaaaaa"},
					{"limited", ok, "limitedaaaaaaaaaaaaaaaaaaa"},
					{"failing", failing, value},
					{"panic", panicking, value},
				} {
					p, h := at(c.value, suffix)
					if got := fetch(t, c.srv, method, p, nil, h); !got.equal(want) {
						t.Errorf("%s %q via %s, %s: response %+v, want %+v", method, suffix, carrier, c.name, got, want)
					}
				}
			}
		}
	}
}

// The redirect target of a honeytoken applies wherever its value stands, and is
// the only thing that differs.
func TestTrigger_ConfiguredRedirectAppliesWhereverTheValueStands(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t, &fakeRecorder{results: map[string]Result{
		value: {Outcome: OutcomeRecorded, HoneytokenID: "1", RedirectURL: "https://example.org/docs"},
	}})
	for name, got := range map[string]response{
		"query":  fetch(t, srv, http.MethodGet, "/x?k="+value, nil, nil),
		"header": fetch(t, srv, http.MethodGet, "/x", nil, http.Header{"X-Api-Key": {value}}),
	} {
		if got.status != http.StatusFound || got.header.Get("Location") != "https://example.org/docs" {
			t.Errorf("%s: %+v, want a redirect to the target of the honeytoken", name, got)
		}
	}
}

// A request with several values is handed over in one call, in the order of the
// path, the query and the headers, and the recorder decides which of them counts:
// the first that belongs to a honeytoken, also a disabled one.
func TestTrigger_HandsOverAllValuesInOneCallInTheirOrder(t *testing.T) {
	t.Parallel()

	rec := &fakeRecorder{results: map[string]Result{
		second: {Outcome: OutcomeDisabled, HoneytokenID: "2"},
		third:  {Outcome: OutcomeRecorded, HoneytokenID: "3"},
	}}
	srv, log := newServer(t, rec)
	fetch(t, srv, http.MethodGet, "/"+value+"?a="+second, nil, http.Header{"X-Api-Key": {third}})

	got := rec.recorded()
	if len(got) != 1 || !slices.Equal(got[0].Values, []string{value, second, third}) {
		t.Errorf("recorded %+v, want one call with the values in order", got)
	}
	if !strings.Contains(log.String(), `"honeytoken_id":"2"`) || strings.Contains(log.String(), `"honeytoken_id":"3"`) {
		t.Errorf("log does not name only the honeytoken of the first known value: %s", log)
	}
}

func TestTrigger_HandsOverAtMostAFewValues(t *testing.T) {
	t.Parallel()

	var many []string
	for i := range 2 * maxCandidates {
		many = append(many, strings.Repeat(string(rune('a'+i)), triggerValueLength))
	}
	rec := &fakeRecorder{}
	srv, _ := newServer(t, rec)
	fetch(t, srv, http.MethodGet, "/"+strings.Join(many, "/"), nil, nil)
	if got := rec.recorded(); len(got) != 1 || !slices.Equal(got[0].Values, many[:maxCandidates]) {
		t.Errorf("recorded %+v, want one call with the first %d values", got, maxCandidates)
	}
}

// The report of a sensor is no request of a honeytoken, whatever else the
// request carries, and a POST to the same path without the form of a secret is.
func TestTrigger_ReportOfASensorLooksUpNoValue(t *testing.T) {
	t.Parallel()

	rec := &fakeRecorder{}
	rep := &fakeReporter{result: ReportResult{Outcome: ReportRecorded}}
	srv, _ := newReportingServer(t, rec, rep)
	header := bearer(testSecret)
	header.Set("X-Api-Key", value)
	fetch(t, srv, http.MethodPost, "/?k="+value, strings.NewReader(string(golden(t, "heartbeat.json"))), header)
	if got := rec.recorded(); len(got) != 0 {
		t.Errorf("looked up %+v for the report of a sensor, want nothing", got)
	}
	if s, h := rep.reported(); s+h != 1 {
		t.Errorf("reported %d sessions and %d heartbeats, want one report", s, h)
	}
}

// The value of a honeytoken stays out of the log wherever it stands.
func TestTrigger_LogsNoValueFromQueryOrHeaders(t *testing.T) {
	t.Parallel()

	srv, log := newServer(t, &fakeRecorder{results: map[string]Result{value: {Outcome: OutcomeRecorded, HoneytokenID: "4f1c"}}})
	for _, header := range []http.Header{
		{"X-Api-Key": {value}},
		{"Authorization": {"Basic " + basicOf("svc:"+value)}},
		{"Cookie": {"sid=" + value}},
	} {
		fetch(t, srv, http.MethodGet, "/x?token="+value, nil, header)
	}
	if strings.Contains(log.String(), value[:10]) || strings.Contains(log.String(), "c3Zj") {
		t.Errorf("log contains the trigger value or credentials: %s", log)
	}
	if strings.Count(log.String(), `"outcome":"recorded"`) != 3 {
		t.Errorf("log does not name three recorded requests: %s", log)
	}
}

// A path that net/http does not clean, and any ending, still carries the value:
// the request is recorded once.
func TestTrigger_RecordsTheValueInOddPaths(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"/" + value + "/", "//" + value, "/./" + value, "/a/../" + value, "/" + value + ".png", "/" + value + "/x.gif",
		"/x?token=" + value, "/x?token=" + strings.ToUpper(value),
	} {
		rec := &fakeRecorder{}
		srv, _ := newServer(t, rec)
		fetch(t, srv, http.MethodGet, path, nil, nil)
		if got := rec.recorded(); len(got) != 1 || !slices.Equal(got[0].Values, []string{value}) {
			t.Errorf("GET %s: looked up %+v, want the value once", path, got)
		}
	}
}
