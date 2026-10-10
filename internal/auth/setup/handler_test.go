// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/auth/password"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/user"
)

// validToken stands in for a setup token in handler tests.
var validToken = strings.Repeat("A", 43)

// fakeService records the calls of the handler.
type fakeService struct {
	closed      bool
	openErr     error
	validErr    error
	completeErr error
	completed   []Admin
	validated   int
}

func (f *fakeService) Open(context.Context) (bool, error) { return !f.closed, f.openErr }

func (f *fakeService) Valid(_ context.Context, token string) (bool, error) {
	f.validated++
	return token == validToken, f.validErr
}

func (f *fakeService) Complete(_ context.Context, token string, admin Admin) (user.User, error) {
	if token != validToken {
		return user.User{}, ErrInvalidToken
	}
	if f.completeErr != nil {
		return user.User{}, f.completeErr
	}
	f.completed = append(f.completed, admin)
	return user.User{
		ID: "00000000-0000-4000-8000-000000000001", Email: admin.Email, DisplayName: admin.DisplayName,
		Role: user.RoleAdmin, Status: user.StatusActive, PasswordHash: admin.PasswordHash,
	}, nil
}

// fakeHasher validates like password.Hasher but does not hash, and counts calls.
type fakeHasher struct{ calls int }

func (f *fakeHasher) Hash(_ context.Context, pw string) (string, error) {
	f.calls++
	if len([]rune(pw)) < password.MinLength {
		return "", password.ErrTooShort
	}
	return "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA", nil
}

// body returns a valid setup request with the given changes.
func body(changes map[string]any) string {
	fields := map[string]any{
		"token":        validToken,
		"email":        "Admin@Example.com",
		"display_name": "Ada Admin",
		"password":     "correct horse battery",
	}
	for k, v := range changes {
		if v == nil {
			delete(fields, k)
		} else {
			fields[k] = v
		}
	}
	b, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// serve passes a request through a router with the setup route, as the console
// registers it.
func serve(t *testing.T, svc *fakeService, hasher *fakeHasher, path, contentType, reqBody string) *httptest.ResponseRecorder {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	rt := httpx.NewRouter(logger, nil)
	rt.Handle(http.MethodPost, "/api/v1/setup", httpx.Public, NewHandler(logger, svc, hasher))

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(reqBody))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, r)
	return w
}

func errorMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp httpx.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error response %q: %v", w.Body.String(), err)
	}
	return resp.Error.Message
}

func TestHandler_CreatesAdministrator(t *testing.T) {
	t.Parallel()

	svc, hasher := &fakeService{}, &fakeHasher{}
	w := serve(t, svc, hasher, "/api/v1/setup", "application/json", body(nil))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	want := map[string]any{
		"id": "00000000-0000-4000-8000-000000000001", "email": "admin@example.com",
		"display_name": "Ada Admin", "role": "admin", "status": "active",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("response = %v, want %v", got, want)
	}
	if len(svc.completed) != 1 || svc.completed[0].Email != "admin@example.com" || !strings.HasPrefix(svc.completed[0].PasswordHash, "$argon2id$") {
		t.Errorf("Complete() calls = %+v, want one with the normalized address and the hash", svc.completed)
	}
}

func TestHandler_ClosedSetupAnswersEveryRequestAsUnknownRoute(t *testing.T) {
	t.Parallel()

	unknown := serve(t, &fakeService{}, &fakeHasher{}, "/api/v1/unknown", "application/json", body(nil))
	requests := map[string]struct{ contentType, body string }{
		"valid":                  {"application/json", body(nil)},
		"malformed body":         {"application/json", "{"},
		"unknown field":          {"application/json", body(map[string]any{"role": "admin"})},
		"wrong content type":     {"text/plain", body(nil)},
		"invalid token":          {"application/json", body(map[string]any{"token": "guess"})},
		"invalid field in token": {"application/json", body(map[string]any{"email": "not an address"})},
	}
	for name, req := range requests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			svc, hasher := &fakeService{closed: true}, &fakeHasher{}
			w := serve(t, svc, hasher, "/api/v1/setup", req.contentType, req.body)
			if w.Code != unknown.Code || w.Body.String() != unknown.Body.String() || fmt.Sprint(w.Header()) != fmt.Sprint(unknown.Header()) {
				t.Errorf("response = %d %v %s, want the response of an unknown route: %d %v %s",
					w.Code, w.Header(), w.Body, unknown.Code, unknown.Header(), unknown.Body)
			}
			if svc.validated != 0 || hasher.calls != 0 || len(svc.completed) != 0 {
				t.Errorf("closed setup looked up %d tokens, hashed %d passwords, completed %d times; want none",
					svc.validated, hasher.calls, len(svc.completed))
			}
		})
	}
}

// Without a valid token, the endpoint must not reveal its validation rules nor
// hash a password.
func TestHandler_InvalidTokenAnswersAsUnknownRouteBeforeValidation(t *testing.T) {
	t.Parallel()

	unknown := serve(t, &fakeService{}, &fakeHasher{}, "/api/v1/unknown", "application/json", body(nil))
	for name, changes := range map[string]map[string]any{
		"wrong token":                  {"token": "guess"},
		"missing token":                {"token": nil},
		"wrong token and invalid data": {"token": "guess", "email": "x", "display_name": "", "password": "short"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			svc, hasher := &fakeService{}, &fakeHasher{}
			w := serve(t, svc, hasher, "/api/v1/setup", "application/json", body(changes))
			if w.Code != unknown.Code || w.Body.String() != unknown.Body.String() {
				t.Errorf("response = %d %s, want the response of an unknown route", w.Code, w.Body)
			}
			if hasher.calls != 0 || len(svc.completed) != 0 {
				t.Errorf("hashed %d passwords, completed %d times; want none", hasher.calls, len(svc.completed))
			}
		})
	}
}

func TestHandler_RejectsInvalidFieldsWithValidToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		changes map[string]any
		message string
		hashed  bool
	}{
		{name: "missing email", changes: map[string]any{"email": nil}, message: "email must be"},
		{name: "address with display name", changes: map[string]any{"email": "Ada <ada@example.com>"}, message: "email must be"},
		{name: "empty display name", changes: map[string]any{"display_name": ""}, message: "display_name must have 1 to 100"},
		{name: "display name with surrounding space", changes: map[string]any{"display_name": " Ada"}, message: "display_name must have"},
		{name: "display name with bidirectional override", changes: map[string]any{"display_name": "Ada\u202eAdmin"}, message: "display_name must have"},
		{name: "display name too long", changes: map[string]any{"display_name": strings.Repeat("a", 101)}, message: "display_name must have"},
		{name: "short password", changes: map[string]any{"password": "too short"}, message: "password must have at least 12", hashed: true},
		{name: "wrong type", changes: map[string]any{"password": 123456789012}, message: `field "password" has an invalid type`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc, hasher := &fakeService{}, &fakeHasher{}
			w := serve(t, svc, hasher, "/api/v1/setup", "application/json", body(tt.changes))
			if w.Code != http.StatusBadRequest || !strings.Contains(errorMessage(t, w), tt.message) {
				t.Errorf("response = %d %s, want 400 with %q", w.Code, w.Body, tt.message)
			}
			if len(svc.completed) != 0 {
				t.Error("an invalid request completed the setup")
			}
			if !tt.hashed && hasher.calls != 0 {
				t.Errorf("hashed %d passwords before the other fields were valid", hasher.calls)
			}
		})
	}
}

func TestHandler_RejectsOversizedBody(t *testing.T) {
	t.Parallel()

	w := serve(t, &fakeService{}, &fakeHasher{}, "/api/v1/setup", "application/json",
		body(map[string]any{"display_name": strings.Repeat("a", maxBodyBytes)}))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", w.Code)
	}
}

// Between the check of the token and its use, a concurrent request can complete
// the setup or the token can expire.
func TestHandler_LostRaceAnswersAsUnknownRoute(t *testing.T) {
	t.Parallel()

	for _, err := range []error{ErrClosed, ErrInvalidToken} {
		t.Run(err.Error(), func(t *testing.T) {
			t.Parallel()

			w := serve(t, &fakeService{completeErr: err}, &fakeHasher{}, "/api/v1/setup", "application/json", body(nil))
			if w.Code != http.StatusNotFound || errorMessage(t, w) != "not found" {
				t.Errorf("response = %d %s, want 404", w.Code, w.Body)
			}
		})
	}
}

func TestHandler_RejectsAddressInUse(t *testing.T) {
	t.Parallel()

	svc := &fakeService{completeErr: fmt.Errorf("complete setup: %w", user.ErrEmailTaken)}
	w := serve(t, svc, &fakeHasher{}, "/api/v1/setup", "application/json", body(nil))
	if w.Code != http.StatusBadRequest || errorMessage(t, w) != "email is already in use" {
		t.Errorf("response = %d %s, want 400", w.Code, w.Body)
	}
}

func TestHandler_HidesServiceErrors(t *testing.T) {
	t.Parallel()

	failure := errors.New("connection refused by 10.1.2.3")
	for name, svc := range map[string]*fakeService{
		"open":     {openErr: failure},
		"valid":    {validErr: failure},
		"complete": {completeErr: failure},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			w := serve(t, svc, &fakeHasher{}, "/api/v1/setup", "application/json", body(nil))
			if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "10.1.2.3") {
				t.Errorf("response = %d %s, want a generic 500", w.Code, w.Body)
			}
		})
	}
}

func TestRequest_LogValueHidesSecrets(t *testing.T) {
	t.Parallel()

	var logged bytes.Buffer
	req := request{Token: validToken, Email: "ada@example.com", DisplayName: "Ada", Password: "correct horse battery"}
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("test", slog.Any("request", req))
	for _, secret := range []string{validToken, "ada@example.com", "correct horse"} {
		if strings.Contains(logged.String(), secret) {
			t.Errorf("log leaks %q: %s", secret, logged.String())
		}
	}
}

func TestNewHandler_RejectsMissingDependencies(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("NewHandler() without a service did not panic")
		}
	}()
	NewHandler(slog.New(slog.DiscardHandler), nil, &fakeHasher{})
}
