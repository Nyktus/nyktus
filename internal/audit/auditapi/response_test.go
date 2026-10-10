// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package auditapi

import (
	"encoding/json"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/audit"
)

// The specification requires changed_fields as an array. The store returns what
// the database driver decodes, which must not turn into null.
func TestNewEntryResponse_ChangedFieldsWithoutValuesIsAnEmptyArray(t *testing.T) {
	t.Parallel()

	b, err := json.Marshal(newEntryResponse(audit.StoredEntry{}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"changed_fields":[]`) {
		t.Errorf("response = %s, want changed_fields as an empty array", b)
	}
}
