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
