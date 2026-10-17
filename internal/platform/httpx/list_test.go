// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testID = "00000000-0000-4000-8000-000000000000"

func TestDecodeListQuery_AcceptsLimitAndCursor(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 10, 10, 12, 0, 0, 123456000, time.UTC)
	cursor := EncodeCursor(Cursor{Time: at, ID: testID})
	for query, want := range map[string]ListQuery{
		"":                         {Limit: 50},
		"limit=1":                  {Limit: 1},
		"limit=200":                {Limit: 200},
		"cursor=" + cursor:         {Limit: 50, After: &Cursor{Time: at, ID: testID}},
		"limit=7&cursor=" + cursor: {Limit: 7, After: &Cursor{Time: at, ID: testID}},
	} {
		rec := httptest.NewRecorder()
		got, ok := DecodeListQuery(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/items?"+query, nil), 50, 200)
		if !ok {
			t.Errorf("DecodeListQuery(%q) rejected: %s", query, rec.Body)
			continue
		}
		if got.Limit != want.Limit || (got.After == nil) != (want.After == nil) ||
			(got.After != nil && (!got.After.Time.Equal(want.After.Time) || got.After.ID != want.After.ID)) {
			t.Errorf("DecodeListQuery(%q) = %+v, want %+v", query, got, want)
		}
	}
}

func TestDecodeListQuery_RejectsInvalidQueries(t *testing.T) {
	t.Parallel()

	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for _, query := range []string{
		"limit=0",
		"limit=201",
		"limit=ten",
		"limit=+50",
		"limit=0050",
		"limit=-0",
		"limit=99999999999999999999",
		"limit=1&limit=2",
		"offset=10",
		"limit=1;cursor=x",
		"cursor=%%%",
		"cursor=" + b64("2026-10-10T12:00:00Z"),
		"cursor=" + b64("yesterday|"+testID),
		"cursor=" + b64("2026-10-10T12:00:00Z|' OR 1=1 --"),
		"cursor=" + b64("2026-10-10T12:00:00Z|"+testID) + "%3D",
	} {
		rec := httptest.NewRecorder()
		if _, ok := DecodeListQuery(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/items?"+query, nil), 50, 200); ok {
			t.Errorf("DecodeListQuery(%q) accepted", query)
			continue
		}
		var body struct {
			Error struct{ Code string } `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusBadRequest || body.Error.Code != CodeInvalidRequest {
			t.Errorf("DecodeListQuery(%q): status %d, body %s; want 400 invalid_request", query, rec.Code, rec.Body)
		}
	}
}

// The client chooses the parameter names, so an error does not repeat them.
func TestDecodeListQuery_DoesNotRepeatParameterNames(t *testing.T) {
	t.Parallel()

	name := strings.Repeat("n", 1000)
	rec := httptest.NewRecorder()
	DecodeListQuery(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/items?"+name+"=1", nil), 50, 200)
	if strings.Contains(rec.Body.String(), name) {
		t.Error("the error repeats the unknown parameter name")
	}
}

// A list accepts the filter parameters it names, once each, and still rejects
// every other parameter.
func TestDecodeListQuery_AcceptsDeclaredFilters(t *testing.T) {
	t.Parallel()

	decode := func(query string, filters ...string) (ListQuery, *httptest.ResponseRecorder, bool) {
		rec := httptest.NewRecorder()
		q, ok := DecodeListQuery(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/items?"+query, nil), 50, 200, filters...)
		return q, rec, ok
	}

	q, rec, ok := decode("type=web_url&limit=5&enabled=", "type", "enabled")
	if !ok || q.Limit != 5 || len(q.Filters) != 2 || q.Filters["type"] != "web_url" || q.Filters["enabled"] != "" {
		t.Errorf("decode() = %+v, %v (%s)", q, ok, rec.Body)
	}
	if q, _, ok := decode("limit=5", "type"); !ok || q.Filters != nil {
		t.Errorf("decode() without filters = %+v, %v; want no filters", q, ok)
	}
	for _, query := range []string{"type=a&type=b", "state=x", "type=a"} {
		filters := []string{"type", "enabled"}
		if query == "type=a" {
			filters = nil
		}
		if _, rec, ok := decode(query, filters...); ok || rec.Code != http.StatusBadRequest {
			t.Errorf("decode(%q, %v) accepted", query, filters)
		}
	}
	if _, rec, _ := decode("state=x", "type", "enabled"); !strings.Contains(rec.Body.String(), "use limit, cursor, type and enabled") {
		t.Errorf("error %s does not name the parameters of the list", rec.Body)
	}
}

// A request accepts the parameters it names, once each, and rejects every
// other one with an error that names what it accepts.
func TestDecodeQuery(t *testing.T) {
	t.Parallel()

	decode := func(query string, names ...string) (map[string]string, *httptest.ResponseRecorder, bool) {
		rec := httptest.NewRecorder()
		values, ok := DecodeQuery(rec, httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/items/1?"+query, nil), names...)
		return values, rec, ok
	}

	if values, rec, ok := decode("a=1&b=", "a", "b", "c"); !ok || len(values) != 2 || values["a"] != "1" || values["b"] != "" {
		t.Errorf("decode() = %v, %v (%s)", values, ok, rec.Body)
	}
	if values, rec, ok := decode("", "a"); !ok || len(values) != 0 {
		t.Errorf("decode() without parameters = %v, %v (%s)", values, ok, rec.Body)
	}
	for _, tt := range []struct {
		query, message string
		names          []string
	}{
		{"a=1&a=2", "query parameters must be given once", []string{"a"}},
		{"%%%", "query string is invalid", []string{"a"}},
		{"a=1;b=2", "query string is invalid", []string{"a", "b"}},
		{"x=1", "unknown query parameter; this request accepts none", nil},
		{"x=1", "unknown query parameter; use a\"", []string{"a"}},
		{"x=1", "unknown query parameter; use a, b and c\"", []string{"a", "b", "c"}},
	} {
		_, rec, ok := decode(tt.query, tt.names...)
		if ok || rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tt.message) {
			t.Errorf("decode(%q, %v): %v, status %d, body %s; want 400 with %q", tt.query, tt.names, ok, rec.Code, rec.Body, tt.message)
		}
	}
}
