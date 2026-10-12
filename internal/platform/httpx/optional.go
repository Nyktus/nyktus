// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"encoding/json"
	"errors"
)

// Optional is a member of a request body that may be left out but, if present,
// must not be null. A null would otherwise be indistinguishable from an absent
// member and silently change nothing. DecodeJSON rejects a null with 400.
type Optional[T any] struct {
	// Set reports whether the member was present.
	Set   bool
	Value T
}

var errNull = errors.New("null is not allowed")

// UnmarshalJSON implements json.Unmarshaler.
func (o *Optional[T]) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return errNull
	}
	o.Set = true
	return json.Unmarshal(b, &o.Value)
}

// Ptr returns a pointer to the value, or nil if the member was left out.
func (o Optional[T]) Ptr() *T {
	if !o.Set {
		return nil
	}
	return &o.Value
}
