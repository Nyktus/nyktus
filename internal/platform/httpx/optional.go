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

// Nullable is a member of a request body that may be left out, or be null to
// remove a value, such as an optional field of a resource in a change.
type Nullable[T any] struct {
	// Set reports whether the member was present, also as null.
	Set bool
	// Null reports whether the member was null.
	Null  bool
	Value T
}

// UnmarshalJSON implements json.Unmarshaler.
//
// A member that appears more than once counts with its last value, as for
// every other member, so every call starts afresh.
func (n *Nullable[T]) UnmarshalJSON(b []byte) error {
	*n = Nullable[T]{Set: true}
	if string(b) == "null" {
		n.Null = true
		return nil
	}
	return json.Unmarshal(b, &n.Value)
}
