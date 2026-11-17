// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package trigger

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

const (
	second = "mfrggzdfmztwq2lknnwg23tpoa"
	third  = "nbswy3dpeb3w64tmmqqq2yljna"
	fourth = "orsxg5bamrzgs3tfebqwy2lvna"
	fifth  = "pjxxezlsn5zgkzlsmvzxe5ddna"
)

func basicOf(credentials string) string {
	return base64.StdEncoding.EncodeToString([]byte(credentials))
}

func newRequest(t *testing.T, target string, header http.Header) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	for k, v := range header {
		r.Header[k] = v
	}
	return r
}

// The value of a honeytoken is found wherever it stands, so that what carries
// it can look like what it pretends to be.
func TestCandidates_FindsTheValueInEveryPlace(t *testing.T) {
	t.Parallel()

	encoded := "%" + "71" + value[1:] // percent-encoded first letter
	for name, r := range map[string]*http.Request{
		"first path segment":       newRequest(t, "/"+value, nil),
		"image":                    newRequest(t, "/"+value+".gif", nil),
		"other extension":          newRequest(t, "/"+value+".png", nil),
		"later path segment":       newRequest(t, "/api/v1/"+value+"/items", nil),
		"prefix after a delimiter": newRequest(t, "/key_"+value, nil),
		"empty segments":           newRequest(t, "//"+value, nil),
		"upper case":               newRequest(t, "/"+strings.ToUpper(value), nil),
		"query value":              newRequest(t, "/?token="+value, nil),
		"query without a name":     newRequest(t, "/?"+value, nil),
		"query name":               newRequest(t, "/?"+value+"=1", nil),
		"query percent-encoded":    newRequest(t, "/?token="+encoded, nil),
		"query after another":      newRequest(t, "/?a=1&b=2;c="+value, nil),
		"bearer token":             newRequest(t, "/", http.Header{"Authorization": {"Bearer " + value}}),
		"api key":                  newRequest(t, "/", http.Header{"X-Api-Key": {value}}),
		"prefixed api key":         newRequest(t, "/", http.Header{"X-Api-Key": {"sk-live-" + value}}),
		"cookie":                   newRequest(t, "/", http.Header{"Cookie": {"a=b; sid=" + value + "; c=d"}}),
		"basic credentials":        newRequest(t, "/", http.Header{"Authorization": {"Basic " + basicOf("svc:"+value)}}),
		"basic user name":          newRequest(t, "/", http.Header{"Authorization": {"basic " + basicOf(value+":x")}}),
		"basic unpadded":           newRequest(t, "/", http.Header{"Authorization": {"Basic " + strings.TrimRight(basicOf("svc:"+value+"!"), "=")}}),
		"basic in upper case":      newRequest(t, "/", http.Header{"Authorization": {"Basic " + basicOf("svc:"+strings.ToUpper(value))}}),
		"any other header":         newRequest(t, "/", http.Header{"X-Something": {"a " + value + " b"}}),
		"a second header value":    newRequest(t, "/", http.Header{"X-Something": {"nothing", value}}),
	} {
		if got := candidates(r); !slices.Equal(got, []string{value}) {
			t.Errorf("%s: candidates = %q, want [%q]", name, got, value)
		}
	}
}

func TestCandidates_IgnoresWhatIsNoValue(t *testing.T) {
	t.Parallel()

	kelvin := strings.Replace(value, "k", "K", 1)
	if kelvin == value {
		t.Fatal("test value has no k to replace")
	}
	for name, r := range map[string]*http.Request{
		"no value":               newRequest(t, "/robots.txt?a=b", http.Header{"X-Api-Key": {"abc"}}),
		"one character short":    newRequest(t, "/"+value[:25], nil),
		"one character more":     newRequest(t, "/"+value+"a", nil),
		"in a longer run":        newRequest(t, "/a"+value, nil),
		"a longer run in query":  newRequest(t, "/?k="+value+value, nil),
		"digit outside alphabet": newRequest(t, "/"+value[:25]+"1", nil),
		"digit 8":                newRequest(t, "/?x="+value[:25]+"8", nil),
		"a letter of a script":   newRequest(t, "/"+kelvin, nil),
		"basic that is no text":  newRequest(t, "/", http.Header{"Authorization": {"Basic !!!"}}),
		"basic without scheme":   newRequest(t, "/", http.Header{"Authorization": {"Basic"}}),
		"basic too long":         newRequest(t, "/", http.Header{"Authorization": {"Basic " + basicOf(strings.Repeat("x", maxBasicBytes)+":"+value)}}),
		"other scheme decoded":   newRequest(t, "/", http.Header{"Authorization": {"Bearer " + basicOf("svc:"+value)}}),
		"encoded into the value": newRequest(t, "/?k=%2f"+value[:25], nil),
	} {
		if got := candidates(r); len(got) != 0 {
			t.Errorf("%s: candidates = %q, want none", name, got)
		}
	}
}

// Which honeytoken a request with several values is recorded for must not
// depend on the order of a map.
func TestCandidates_OrderIsPathQueryThenHeadersByName(t *testing.T) {
	t.Parallel()

	r := newRequest(t, "/"+value+"/?a="+second, http.Header{
		"X-B": {fourth},
		"X-A": {third, value},
	})
	want := []string{value, second, third, fourth}
	for range 20 {
		if got := candidates(r); !slices.Equal(got, want) {
			t.Fatalf("candidates = %q, want %q", got, want)
		}
	}
}

// A request that carries many strings of the form of a value leads to a few
// lookups, not one per string.
func TestCandidates_AreBounded(t *testing.T) {
	t.Parallel()

	r := newRequest(t, "/"+value+"/"+second+"/"+third+"/"+fourth+"/"+fifth+"?a="+strings.Repeat(value+"&", 100), nil)
	got := candidates(r)
	if want := []string{value, second, third, fourth}; maxCandidates != 4 || !slices.Equal(got, want) {
		t.Errorf("candidates = %q, want the first %d: %q", got, maxCandidates, want)
	}
}
