// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package attack

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

var techniqueID = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)

// The embedded list is generated, but the code relies on its form: one entry
// per identifier, in order, every sub-technique under an active parent, and a
// name and tactics for each.
func TestEmbeddedList_IsConsistent(t *testing.T) {
	t.Parallel()

	var l list
	if err := json.Unmarshal(data, &l); err != nil {
		t.Fatalf("parse embedded list: %v", err)
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(l.Version) || l.Version != version {
		t.Errorf("version = %q, want a version such as 19.2", l.Version)
	}
	// ATT&CK Enterprise has had several hundred techniques for years. A short
	// list means that the generator dropped some.
	if len(l.Techniques) < 500 || len(techniques) != len(l.Techniques) {
		t.Errorf("%d techniques, %d distinct; want at least 500, all distinct", len(l.Techniques), len(techniques))
	}
	for i, tech := range l.Techniques {
		if !techniqueID.MatchString(tech.ID) {
			t.Errorf("identifier %q is malformed", tech.ID)
		}
		if i > 0 && l.Techniques[i-1].ID >= tech.ID {
			t.Errorf("%s follows %s; want ascending identifiers", tech.ID, l.Techniques[i-1].ID)
		}
		if strings.TrimSpace(tech.Name) != tech.Name || tech.Name == "" || len(tech.Tactics) == 0 {
			t.Errorf("%s: name %q, tactics %v; want both", tech.ID, tech.Name, tech.Tactics)
		}
		if parentID, _, sub := strings.Cut(tech.ID, "."); sub {
			parent, ok := techniques[parentID]
			if !ok || !strings.HasPrefix(tech.Name, parent.Name+": ") {
				t.Errorf("%s %q: want a sub-technique of an active parent %s, named after it", tech.ID, tech.Name, parentID)
			}
		}
	}
}

func TestLookup(t *testing.T) {
	t.Parallel()

	got, ok := Lookup("T1003.001")
	if !ok || got.Name != "OS Credential Dumping: LSASS Memory" || len(got.Tactics) != 1 || got.Tactics[0] != "Credential Access" {
		t.Errorf("Lookup(T1003.001) = %+v, %v", got, ok)
	}
	if _, ok := Lookup("T1003"); !ok {
		t.Error("Lookup(T1003) found no technique")
	}
	// Revoked (T1086, now T1059.001) and deprecated (T1064) techniques are not
	// offered, nor are malformed or unknown identifiers.
	for _, id := range []string{"T1086", "T1064", "T9999", "T1003.999", "t1003", "T1003.1", "", " T1003"} {
		if _, ok := Lookup(id); ok {
			t.Errorf("Lookup(%q) found a technique", id)
		}
	}

	got.Tactics[0] = "changed"
	if again, _ := Lookup("T1003.001"); again.Tactics[0] != "Credential Access" {
		t.Error("changing a returned technique changed the list")
	}
}
