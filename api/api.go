// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package api embeds the OpenAPI specification of the console API, so that every
// package loads the contract the same way, independent of its directory.
package api

import (
	"bytes"
	_ "embed"
)

//go:embed openapi.yaml
var openAPI []byte

// OpenAPI returns a copy of the specification in YAML.
func OpenAPI() []byte { return bytes.Clone(openAPI) }
