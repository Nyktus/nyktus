// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOptional_DistinguishesAbsentFromPresentAndRejectsNull(t *testing.T) {
	t.Parallel()

	type request struct {
		Name    Optional[string] `json:"name"`
		Enabled Optional[bool]   `json:"enabled"`
	}
	decode := func(body string) (request, int) {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		var req request
		if !DecodeJSON(w, r, &req, MaxBodyBytes) {
			return req, w.Code
		}
		return req, http.StatusOK
	}

	req, status := decode(`{"enabled": false}`)
	if status != http.StatusOK || req.Name.Set || req.Name.Ptr() != nil || !req.Enabled.Set || req.Enabled.Value || *req.Enabled.Ptr() {
		t.Errorf("decode({enabled: false}) = %+v, %d", req, status)
	}
	if req, status := decode(`{"name": ""}`); status != http.StatusOK || !req.Name.Set || *req.Name.Ptr() != "" {
		t.Errorf(`decode({name: ""}) = %+v, %d`, req, status)
	}
	for _, body := range []string{`{"name": null}`, `{"enabled": null}`, `{"enabled": "yes"}`} {
		if _, status := decode(body); status != http.StatusBadRequest {
			t.Errorf("decode(%s) status = %d, want 400", body, status)
		}
	}
}

func TestNullable_DistinguishesAbsentNullAndValue(t *testing.T) {
	t.Parallel()

	type request struct {
		Target Nullable[string]   `json:"target"`
		Tags   Nullable[[]string] `json:"tags"`
	}
	decode := func(body string) (request, int) {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		var req request
		if !DecodeJSON(w, r, &req, MaxBodyBytes) {
			return req, w.Code
		}
		return req, http.StatusOK
	}

	if req, status := decode(`{}`); status != http.StatusOK || req.Target.Set || req.Tags.Set {
		t.Errorf("decode({}) = %+v, %d; want nothing set", req, status)
	}
	if req, status := decode(`{"target": null}`); status != http.StatusOK || !req.Target.Set || !req.Target.Null {
		t.Errorf("decode({target: null}) = %+v, %d; want set to null", req, status)
	}
	if req, status := decode(`{"target": "", "tags": []}`); status != http.StatusOK || !req.Target.Set || req.Target.Null ||
		req.Target.Value != "" || !req.Tags.Set || req.Tags.Null || req.Tags.Value == nil {
		t.Errorf(`decode({target: "", tags: []}) = %+v, %d; want both set to empty values`, req, status)
	}
	if _, status := decode(`{"tags": "a"}`); status != http.StatusBadRequest {
		t.Errorf("decode({tags: a}) status = %d, want 400", status)
	}
}
