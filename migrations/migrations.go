// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package migrations embeds the PostgreSQL schema migrations applied by
// "nyktus migrate".
package migrations

import "embed"

// FS contains the migration files.
//
//go:embed *.sql
var FS embed.FS
