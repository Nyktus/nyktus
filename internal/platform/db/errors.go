// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// SQLSTATE codes of constraint violations that stores map to errors of their
// own.
const (
	// CheckViolation is raised by a CHECK constraint and by triggers that
	// reject a row in its place.
	CheckViolation  = "23514"
	UniqueViolation = "23505"
	// ForeignKeyViolation is raised when a row refers to a row that does not exist.
	ForeignKeyViolation = "23503"
)

// invalidTextRepresentation is raised for an identifier that is not a UUID.
const invalidTextRepresentation = "22P02"

// Violation returns the name of the constraint that err violated with the
// SQLSTATE code, also when err is wrapped, and "" otherwise. Stores map
// violations by code and constraint name, never by the message.
func Violation(err error, code string) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == code {
		return pgErr.ConstraintName
	}
	return ""
}

// NotFound reports whether err means that no row has the identifier that a
// statement looked for: no row matched, or the identifier is not a UUID and
// therefore cannot belong to one.
func NotFound(err error) bool {
	var pgErr *pgconn.PgError
	return errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == invalidTextRepresentation)
}
