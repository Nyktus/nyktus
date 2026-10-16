// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestViolation_ReturnsTheConstraintOfTheCode(t *testing.T) {
	t.Parallel()

	check := fmt.Errorf("insert: %w", &pgconn.PgError{Code: CheckViolation, ConstraintName: "things_name_check"})
	tests := []struct {
		name string
		err  error
		code string
		want string
	}{
		{"wrapped violation", check, CheckViolation, "things_name_check"},
		{"other code", check, UniqueViolation, ""},
		{"other error", errors.New("connection reset"), CheckViolation, ""},
		{"no error", nil, CheckViolation, ""},
	}
	for _, tt := range tests {
		if got := Violation(tt.err, tt.code); got != tt.want {
			t.Errorf("%s: Violation = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestNotFound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"no rows", fmt.Errorf("get: %w", pgx.ErrNoRows), true},
		{"not a UUID", fmt.Errorf("get: %w", &pgconn.PgError{Code: invalidTextRepresentation}), true},
		{"other database error", &pgconn.PgError{Code: CheckViolation}, false},
		{"other error", errors.New("connection reset"), false},
		{"no error", nil, false},
	}
	for _, tt := range tests {
		if got := NotFound(tt.err); got != tt.want {
			t.Errorf("%s: NotFound = %t, want %t", tt.name, got, tt.want)
		}
	}
}
