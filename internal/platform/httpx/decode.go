// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

// MaxBodyBytes is the default limit for request bodies.
const MaxBodyBytes = 1 << 20

var errTrailingData = errors.New("trailing data after JSON value")

// DecodeJSON decodes the JSON request body into dst. It rejects other content types,
// bodies larger than maxBytes, unknown fields and trailing data. On failure it writes
// the error response and returns false; the handler must then return.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) bool {
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		WriteError(w, r, http.StatusUnsupportedMediaType, CodeUnsupportedMedia, "request body must be application/json")
		return false
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		writeDecodeError(w, r, err)
		return false
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		var tooLarge *http.MaxBytesError
		if !errors.As(err, &tooLarge) {
			err = errTrailingData
		}
		writeDecodeError(w, r, err)
		return false
	}
	return true
}

// writeDecodeError maps decoder errors to client messages without Go type names or
// other implementation details.
func writeDecodeError(w http.ResponseWriter, r *http.Request, err error) {
	var (
		syntaxErr *json.SyntaxError
		typeErr   *json.UnmarshalTypeError
		tooLarge  *http.MaxBytesError
	)
	status, code, message := http.StatusBadRequest, CodeInvalidRequest, "request body is invalid"

	switch {
	case errors.As(err, &tooLarge):
		status, code = http.StatusRequestEntityTooLarge, CodeBodyTooLarge
		message = fmt.Sprintf("request body exceeds %d bytes", tooLarge.Limit)
	case errors.Is(err, errTrailingData):
		message = "request body must contain a single JSON value"
	case errors.Is(err, io.EOF):
		message = "request body is empty"
	case errors.As(err, &syntaxErr), errors.Is(err, io.ErrUnexpectedEOF):
		message = "request body is not valid JSON"
	case errors.As(err, &typeErr) && typeErr.Field != "":
		message = fmt.Sprintf("field %q has an invalid type", typeErr.Field)
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		message = strings.TrimPrefix(err.Error(), "json: ")
	}
	WriteError(w, r, status, code, message)
}
