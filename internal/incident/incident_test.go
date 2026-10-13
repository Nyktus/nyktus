// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package incident

import (
	"slices"
	"testing"

	"nyktus.org/nyktus/internal/honeytoken"
)

// Every type of honeytoken has a severity, so that no event waits for a
// decision that was never made.
func TestEventSeverity_CoversEveryHoneytokenType(t *testing.T) {
	t.Parallel()

	for _, typ := range honeytoken.Types {
		s := string(typ)
		got, err := eventSeverity(ResourceHoneytoken, &s)
		if err != nil || !slices.Contains(Severities, got) || got == SeverityInfo {
			t.Errorf("eventSeverity(%s) = %q, %v; want a severity above info", typ, got, err)
		}
	}
	if len(honeytokenSeverity) != len(honeytoken.Types) {
		t.Errorf("severities for %d types, want %d", len(honeytokenSeverity), len(honeytoken.Types))
	}
}

func TestEventSeverity_RejectsUnknownEvents(t *testing.T) {
	t.Parallel()

	unknown := "qr_code"
	if _, err := eventSeverity(ResourceHoneytoken, &unknown); err == nil {
		t.Error("eventSeverity() accepted an unknown honeytoken type")
	}
	if _, err := eventSeverity(ResourceHoneytoken, nil); err == nil {
		t.Error("eventSeverity() accepted a honeytoken event without type")
	}
	webURL := string(honeytoken.TypeWebURL)
	if _, err := eventSeverity("honeypot", &webURL); err == nil {
		t.Error("eventSeverity() accepted an unknown resource type")
	}
}

func TestHigher(t *testing.T) {
	t.Parallel()

	for i, a := range Severities {
		for j, b := range Severities {
			want := a
			if j > i {
				want = b
			}
			if got := higher(a, b); got != want {
				t.Errorf("higher(%s, %s) = %s, want %s", a, b, got, want)
			}
		}
	}
}

func TestUnion(t *testing.T) {
	t.Parallel()

	if got := union(nil, nil); got == nil || len(got) != 0 {
		t.Errorf("union(nil, nil) = %#v, want an empty slice", got)
	}
	if got := union([]string{"T1", "T2"}, []string{"T2", "T3", "T1"}); !slices.Equal(got, []string{"T1", "T2", "T3"}) {
		t.Errorf("union() = %v, want T1 T2 T3", got)
	}
}
