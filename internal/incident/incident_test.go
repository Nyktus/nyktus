// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package incident

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/honeytoken"
)

// Every type of honeytoken has a severity, so that no event waits for a
// decision that was never made.
func TestEventSeverity_CoversEveryHoneytokenType(t *testing.T) {
	t.Parallel()

	for _, typ := range honeytoken.Types {
		s := string(typ)
		got, err := eventSeverity(honeytoken.ResourceType, &s)
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
	if _, err := eventSeverity(honeytoken.ResourceType, &unknown); err == nil {
		t.Error("eventSeverity() accepted an unknown honeytoken type")
	}
	if _, err := eventSeverity(honeytoken.ResourceType, nil); err == nil {
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

// The triage validates every field before it writes, so that a rejected value
// never reaches the database, which would check it again.
func TestChange_Validate(t *testing.T) {
	t.Parallel()

	status := func(s Status) *Status { return &s }
	severity := func(s Severity) *Severity { return &s }
	text := func(s string) *string { return &s }
	for _, tt := range []struct {
		name   string
		change Change
		want   error
	}{
		{"every status", Change{Status: status(StatusClosed)}, nil},
		{"unknown status", Change{Status: status("resolved")}, ErrInvalidStatus},
		{"notes over lines", Change{Notes: text("a\r\n\tb\u00a0c")}, nil},
		{"longest notes", Change{Notes: text(strings.Repeat("\u00e4", MaxNotesLength))}, nil},
		{"notes too long", Change{Notes: text(strings.Repeat("a", MaxNotesLength+1))}, ErrInvalidNotes},
		{"control character in notes", Change{Notes: text("a\x07")}, ErrInvalidNotes},
		{"format character in notes", Change{Notes: text("a\u202eb")}, ErrInvalidNotes},
		{"invalid UTF-8 in notes", Change{Notes: text("a\xff")}, ErrInvalidNotes},
		{"info as override", Change{SetSeverityOverride: true, SeverityOverride: severity(SeverityInfo)}, nil},
		{"unknown override", Change{SetSeverityOverride: true, SeverityOverride: severity("urgent")}, ErrInvalidSeverity},
		{"removed override", Change{SetSeverityOverride: true}, nil},
		{"techniques", Change{SetTechniquesOverride: true, TechniquesOverride: []string{"T1078", "T1003.001"}}, nil},
		{"no techniques", Change{SetTechniquesOverride: true, TechniquesOverride: []string{}}, nil},
		{"unknown technique", Change{SetTechniquesOverride: true, TechniquesOverride: []string{"T9999"}}, ErrInvalidTechniques},
		{"repeated technique", Change{SetTechniquesOverride: true, TechniquesOverride: []string{"T1078", "T1078"}}, ErrInvalidTechniques},
	} {
		if err := tt.change.validate(); !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
			t.Errorf("%s: validate() = %v, want %v", tt.name, err, tt.want)
		}
	}
}

// The triage moves the status only forward and reports exactly the fields
// whose values change.
func TestApply(t *testing.T) {
	t.Parallel()

	status := func(s Status) *Status { return &s }
	severity := func(s Severity) *Severity { return &s }
	base := Incident{Status: StatusAcknowledged, Notes: "n", SeverityOverride: severity(SeverityHigh), TechniquesOverride: []string{"T1078"}}
	for _, tt := range []struct {
		name    string
		change  Change
		changed []string
		err     error
	}{
		{"same status", Change{Status: status(StatusAcknowledged)}, nil, nil},
		{"forward", Change{Status: status(StatusClosed)}, []string{FieldStatus}, nil},
		{"back", Change{Status: status(StatusOpen)}, nil, ErrStatusBackward},
		{"same notes", Change{Notes: new("n")}, nil, nil},
		{"same override", Change{SetSeverityOverride: true, SeverityOverride: severity(SeverityHigh)}, nil, nil},
		{"removed override", Change{SetSeverityOverride: true}, []string{FieldSeverityOverride}, nil},
		{"same techniques", Change{SetTechniquesOverride: true, TechniquesOverride: []string{"T1078"}}, nil, nil},
		{"other techniques", Change{SetTechniquesOverride: true, TechniquesOverride: []string{"T1003"}}, []string{FieldTechniquesOverride}, nil},
		{"no techniques", Change{SetTechniquesOverride: true, TechniquesOverride: []string{}}, []string{FieldTechniquesOverride}, nil},
		{"removed techniques", Change{SetTechniquesOverride: true}, []string{FieldTechniquesOverride}, nil},
	} {
		i := base
		changed, err := apply(&i, tt.change)
		if !errors.Is(err, tt.err) || !slices.Equal(changed, tt.changed) {
			t.Errorf("%s: apply() = %v, %v; want %v, %v", tt.name, changed, err, tt.changed, tt.err)
		}
	}

	// The same techniques in another order change nothing.
	i := Incident{TechniquesOverride: []string{"T1078", "T1003"}}
	if changed, _ := apply(&i, Change{SetTechniquesOverride: true, TechniquesOverride: []string{"T1003", "T1078"}}); changed != nil ||
		!slices.Equal(i.TechniquesOverride, []string{"T1078", "T1003"}) {
		t.Errorf("reordered techniques = %v, %v; want no change", changed, i.TechniquesOverride)
	}

	// Removing the override of the techniques differs from setting none.
	i = Incident{TechniquesOverride: []string{}}
	if changed, _ := apply(&i, Change{SetTechniquesOverride: true}); !slices.Equal(changed, []string{FieldTechniquesOverride}) || i.TechniquesOverride != nil {
		t.Errorf("removing an empty override = %v, %v; want it removed", changed, i.TechniquesOverride)
	}
}
