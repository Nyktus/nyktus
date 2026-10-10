// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nyktus.org/nyktus/internal/platform/logging"
	"nyktus.org/nyktus/internal/platform/request"
)

func TestDecodeJSON(t *testing.T) {
	t.Parallel()

	const jsonType = "application/json"
	type payload struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	tests := []struct {
		name        string
		contentType string
		body        string
		maxBytes    int64
		wantOK      bool
		wantStatus  int
		wantCode    string
		wantMessage string
	}{
		{name: "valid", contentType: "application/json; charset=utf-8", body: `{"name":"a","count":1}`, wantOK: true},
		{name: "wrong content type", contentType: "text/plain", body: `{}`, wantStatus: http.StatusUnsupportedMediaType, wantCode: CodeUnsupportedMedia},
		{name: "missing content type", body: `{}`, wantStatus: http.StatusUnsupportedMediaType, wantCode: CodeUnsupportedMedia},
		{name: "empty body", contentType: jsonType, body: ``, wantStatus: http.StatusBadRequest, wantMessage: "request body is empty"},
		{name: "syntax error", contentType: jsonType, body: `{"name":`, wantStatus: http.StatusBadRequest, wantMessage: "request body is not valid JSON"},
		{name: "unknown field", contentType: jsonType, body: `{"admin":true}`, wantStatus: http.StatusBadRequest, wantMessage: `unknown field "admin"`},
		{name: "wrong type", contentType: jsonType, body: `{"count":"x"}`, wantStatus: http.StatusBadRequest, wantMessage: `field "count" has an invalid type`},
		{name: "trailing object", contentType: jsonType, body: `{"name":"a"}{"admin":true}`, wantStatus: http.StatusBadRequest, wantMessage: "request body must contain a single JSON value"},
		{name: "trailing garbage", contentType: jsonType, body: `{"name":"a"} x`, wantStatus: http.StatusBadRequest, wantMessage: "request body must contain a single JSON value"},
		{name: "too large", contentType: jsonType, body: `{"name":"` + strings.Repeat("a", 64) + `"}`, maxBytes: 32, wantStatus: http.StatusRequestEntityTooLarge, wantCode: CodeBodyTooLarge},
		{name: "too large after value", contentType: jsonType, body: `{"name":"a"}` + strings.Repeat(" ", 64), maxBytes: 32, wantStatus: http.StatusRequestEntityTooLarge, wantCode: CodeBodyTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			maxBytes := tt.maxBytes
			if maxBytes == 0 {
				maxBytes = MaxBodyBytes
			}

			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(tt.body))
			if tt.contentType != "" {
				r.Header.Set("Content-Type", tt.contentType)
			}
			w := httptest.NewRecorder()

			var dst payload
			ok := DecodeJSON(w, r, &dst, maxBytes)
			if ok != tt.wantOK {
				t.Fatalf("DecodeJSON() = %v, want %v (body %s)", ok, tt.wantOK, w.Body.String())
			}
			if tt.wantOK {
				return
			}

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			got := decodeErrorResponse(t, w)
			wantCode := tt.wantCode
			if wantCode == "" {
				wantCode = CodeInvalidRequest
			}
			if got.Error.Code != wantCode {
				t.Errorf("code = %q, want %q", got.Error.Code, wantCode)
			}
			if tt.wantMessage != "" && got.Error.Message != tt.wantMessage {
				t.Errorf("message = %q, want %q", got.Error.Message, tt.wantMessage)
			}
			if strings.Contains(got.Error.Message, "Go struct") || strings.Contains(got.Error.Message, "httpx.") {
				t.Errorf("message leaks implementation details: %q", got.Error.Message)
			}
		})
	}
}

func TestServerError_LogsDetailsAndHidesThem(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := logging.New(&logs, slog.LevelInfo)
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ServerError(w, r, logger, "test: query failed", errors.New("connection to 10.0.0.5 refused"))
	}))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if strings.Contains(w.Body.String(), "10.0.0.5") {
		t.Errorf("response leaks the internal error: %s", w.Body.String())
	}
	got := decodeErrorResponse(t, w)
	if got.Error.RequestID == "" || got.Error.RequestID != w.Header().Get("X-Request-ID") {
		t.Errorf("request_id = %q, header = %q", got.Error.RequestID, w.Header().Get("X-Request-ID"))
	}
	if !strings.Contains(logs.String(), "10.0.0.5") || !strings.Contains(logs.String(), got.Error.RequestID) {
		t.Errorf("log lacks error or request ID: %s", logs.String())
	}
}

func TestRequestID_IgnoresClientValueAndIsUnique(t *testing.T) {
	t.Parallel()

	var seen []string
	h := RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = append(seen, request.ID(r.Context()))
	}))

	for range 2 {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		r.Header.Set("X-Request-ID", "forged")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if got := w.Header().Get("X-Request-ID"); got == "forged" || got == "" {
			t.Errorf("X-Request-ID = %q, want a server-generated value", got)
		}
	}
	if len(seen) != 2 || seen[0] == seen[1] || seen[0] == "forged" {
		t.Errorf("request IDs = %v, want two distinct server-generated values", seen)
	}
}

func TestAccessLog_LogsRoutePatternInsteadOfPath(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := logging.New(&logs, slog.LevelInfo)
	rt := NewRouter(discardLogger(), nil)
	rt.Handle(http.MethodGet, "/items/{id}", Public, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	h := Chain(rt, RequestID, AccessLog(logger), Recover(logger))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/items/secret-value", nil))

	var record map[string]any
	if err := json.Unmarshal(logs.Bytes(), &record); err != nil {
		t.Fatalf("decode log record %q: %v", logs.String(), err)
	}
	if record["route"] != "GET /items/{id}" {
		t.Errorf("route = %v, want the pattern", record["route"])
	}
	if record["status"] != float64(http.StatusTeapot) {
		t.Errorf("status = %v, want %d", record["status"], http.StatusTeapot)
	}
	if record["request_id"] == nil {
		t.Error("access log record lacks request_id")
	}
	if strings.Contains(logs.String(), "secret-value") {
		t.Errorf("access log contains the raw path: %s", logs.String())
	}
}

func TestRecover_TurnsPanicInto500(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := logging.New(&logs, slog.LevelInfo)
	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}), RequestID, Recover(logger))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if got := decodeErrorResponse(t, w); got.Error.Code != CodeInternal || got.Error.RequestID == "" {
		t.Errorf("error response = %+v", got)
	}
	if !strings.Contains(logs.String(), "boom") || !strings.Contains(logs.String(), "stack") {
		t.Errorf("log lacks panic value or stack: %s", logs.String())
	}
}

func TestRecover_PassesAbortHandlerOn(t *testing.T) {
	t.Parallel()

	h := Recover(discardLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	defer func() {
		if v := recover(); v != http.ErrAbortHandler { //nolint:errorlint // recover returns the panic value itself, never a wrapped error.
			t.Errorf("recovered %v, want http.ErrAbortHandler", v)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
}

func TestRecover_AbortsResponseThatHasStarted(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	h := Recover(logging.New(&logs, slog.LevelInfo))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[`))
		panic("boom")
	}))
	defer func() {
		if v := recover(); v != http.ErrAbortHandler { //nolint:errorlint // recover returns the panic value itself, never a wrapped error.
			t.Errorf("recovered %v, want http.ErrAbortHandler", v)
		}
		if !strings.Contains(logs.String(), "boom") {
			t.Errorf("log lacks the original panic: %s", logs.String())
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
}

func TestRouter_RejectsRouteWithoutAccessDeclaration(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("Handle() accepted a route without access declaration")
		}
	}()
	NewRouter(discardLogger(), nil).Handle(http.MethodGet, "/", Access{}, http.NotFoundHandler())
}

func TestRouter_RecordsRoutesAndDispatchesByMethod(t *testing.T) {
	t.Parallel()

	rt := NewRouter(discardLogger(), nil)
	rt.Handle(http.MethodGet, "/a", Public, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	if routes := rt.Routes(); len(routes) != 1 || routes[0] != (Route{Method: http.MethodGet, Path: "/a", Access: Public}) {
		t.Errorf("Routes() = %+v", routes)
	}

	w := httptest.NewRecorder()
	rt.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/a", nil))
	if w.Code != http.StatusNoContent {
		t.Errorf("GET /a status = %d, want 204", w.Code)
	}
}

func TestRouter_AnswersUnmatchedRequestsWithJSONNotFound(t *testing.T) {
	t.Parallel()

	rt := NewRouter(discardLogger(), nil)
	rt.Handle(http.MethodGet, "/a", Public, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, req := range []struct{ method, path string }{
		{http.MethodGet, "/unknown"},
		{http.MethodGet, "/"},
		{http.MethodPost, "/a"},
	} {
		w := httptest.NewRecorder()
		rt.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), req.method, req.path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s status = %d, want 404", req.method, req.path, w.Code)
		}
		if got := decodeErrorResponse(t, w); got.Error.Code != CodeNotFound {
			t.Errorf("%s %s code = %q, want %q", req.method, req.path, got.Error.Code, CodeNotFound)
		}
		if allow := w.Header().Get("Allow"); allow != "" {
			t.Errorf("%s %s Allow = %q, want no Allow header", req.method, req.path, allow)
		}
	}
}

func TestServe_ShutsDownWhenContextIsCancelled(t *testing.T) {
	t.Parallel()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), discardLogger())

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, srv, ln) }()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not return after cancellation")
	}
}

func TestServe_ClosesConnectionsAfterShutdownTimeout(t *testing.T) {
	t.Parallel()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	started, handlerDone := make(chan struct{}), make(chan struct{})
	srv := NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		close(started)
		<-r.Context().Done()
	}), discardLogger())

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, srv, ln, 50*time.Millisecond) }()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	go func() {
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-started

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("serve() error = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve() did not return after the shutdown timeout")
	}
	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection of the blocked handler was not closed")
	}
}

func TestWriteJSON_ResponsesAreNotCachedOrSniffed(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	for header, want := range map[string]string{
		"Content-Type":           "application/json",
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := w.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

func decodeErrorResponse(t *testing.T, w *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error response %q: %v", w.Body.String(), err)
	}
	return resp
}
