// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package engage

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var activityID = regexp.MustCompile(`^EAC[0-9]{4}$`)

// The approaches of engagement activities, in the order of the matrix.
var approaches = []string{"Collect", "Detect", "Prevent", "Direct", "Disrupt", "Reassure", "Motivate"}

// The embedded list is generated, but the code relies on its form: one entry
// per identifier, in order, and a name and known approaches for each.
func TestEmbeddedList_IsConsistent(t *testing.T) {
	t.Parallel()

	var l list
	if err := json.Unmarshal(data, &l); err != nil {
		t.Fatalf("parse embedded list: %v", err)
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(l.Version) || l.Version != Version() {
		t.Errorf("version = %q, want a version such as 1.0", l.Version)
	}
	// Engage 1.0 has 23 engagement activities. A shorter list means that the
	// generator dropped some.
	if len(l.Activities) < 23 || len(activities) != len(l.Activities) {
		t.Errorf("%d activities, %d distinct; want at least 23, all distinct", len(l.Activities), len(activities))
	}
	for i, a := range l.Activities {
		if !activityID.MatchString(a.ID) {
			t.Errorf("identifier %q is malformed", a.ID)
		}
		if i > 0 && l.Activities[i-1].ID >= a.ID {
			t.Errorf("%s follows %s; want ascending identifiers", a.ID, l.Activities[i-1].ID)
		}
		if strings.TrimSpace(a.Name) != a.Name || a.Name == "" || len(a.Approaches) == 0 {
			t.Errorf("%s: name %q, approaches %v; want both", a.ID, a.Name, a.Approaches)
		}
		last := -1
		for _, approach := range a.Approaches {
			at := slices.Index(approaches, approach)
			if at <= last {
				t.Errorf("%s: approaches %v; want known approaches in the order of the matrix", a.ID, a.Approaches)
			}
			last = at
		}
	}
}

func TestLookup(t *testing.T) {
	t.Parallel()

	got, ok := Lookup("EAC0005")
	if !ok || got.Name != "Lures" || !slices.Equal(got.Approaches, []string{"Detect", "Direct", "Disrupt"}) {
		t.Errorf("Lookup(EAC0005) = %+v, %v", got, ok)
	}
	// Strategic activities are not offered, nor are malformed or unknown
	// identifiers.
	for _, id := range []string{"SAC0001", "EAC9999", "eac0005", "EAC005", "", " EAC0005", "EAP0001"} {
		if _, ok := Lookup(id); ok {
			t.Errorf("Lookup(%q) found an activity", id)
		}
	}

	got.Approaches[0] = "changed"
	if again, _ := Lookup("EAC0005"); again.Approaches[0] != "Detect" {
		t.Error("changing a returned activity changed the list")
	}
}
