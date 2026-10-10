// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/platform/schematest"
)

// listAll pages through the log with pages of size and returns the IDs in the
// order of the pages.
func listAll(t *testing.T, s *audit.Store, size int) []string {
	t.Helper()
	var (
		ids   []string
		after *audit.Cursor
	)
	for range 100 {
		page, next, err := s.List(t.Context(), size, after)
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if len(page) > size {
			t.Fatalf("List() returned %d entries, want at most %d", len(page), size)
		}
		for _, e := range page {
			ids = append(ids, e.ID)
		}
		if next == nil {
			return ids
		}
		after = next
	}
	t.Fatal("List() never returned the last page")
	return nil
}

func TestList_ReturnsEntriesNewestFirstInPages(t *testing.T) {
	t.Parallel()

	ownerURL, consoleURL := schematest.Console(t)
	pool := schematest.Open(t, consoleURL)
	s := audit.NewStore(pool)
	for range 7 {
		if err := s.Record(t.Context(), systemEntry()); err != nil {
			t.Fatalf("Record() error = %v", err)
		}
	}
	// Entries with the same time are ordered by their identifier, so that no
	// entry is lost or repeated at the border of a page.
	owner := schematest.Open(t, ownerURL)
	if _, err := owner.Exec(t.Context(), `
UPDATE audit_entries SET occurred_at = '2026-10-10T12:00:00Z'
WHERE id IN (SELECT id FROM audit_entries ORDER BY occurred_at LIMIT 4)`); err != nil {
		t.Fatalf("give entries the same time: %v", err)
	}

	var want []string
	if err := pool.QueryRow(t.Context(), `SELECT array_agg(id::text ORDER BY occurred_at DESC, id DESC) FROM audit_entries`).Scan(&want); err != nil {
		t.Fatalf("read IDs: %v", err)
	}
	for _, size := range []int{1, 2, 3, 7, audit.MaxPageSize} {
		if got := listAll(t, s, size); !slices.Equal(got, want) {
			t.Errorf("pages of %d = %v, want %v", size, got, want)
		}
	}
}

// Entries recorded while a client pages through the log appear on its first page
// the next time, but neither repeat nor hide entries on the following pages.
func TestList_NewEntriesDoNotShiftPages(t *testing.T) {
	t.Parallel()

	s, _ := newStore(t)
	for range 4 {
		if err := s.Record(t.Context(), systemEntry()); err != nil {
			t.Fatalf("Record() error = %v", err)
		}
	}
	first, next, err := s.List(t.Context(), 2, nil)
	if err != nil || next == nil {
		t.Fatalf("List() = %v, %v, %v", first, next, err)
	}
	if err := s.Record(t.Context(), systemEntry()); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	second, next, err := s.List(t.Context(), 2, next)
	if err != nil || next != nil || len(second) != 2 {
		t.Fatalf("second page = %d entries, next %v, err %v; want the remaining 2", len(second), next, err)
	}
	for _, e := range second {
		for _, f := range first {
			if e.ID == f.ID {
				t.Errorf("entry %s repeats on the second page", e.ID)
			}
		}
	}
}

func TestList_ReturnsEveryField(t *testing.T) {
	t.Parallel()

	s, pool := newStore(t)
	actorID := createUser(t, pool, "jane@example.com", "Jane Doe")
	resourceID := createUser(t, pool, "john@example.com", "John Doe")
	want := userEntry(actorID, resourceID)
	before := time.Now()
	if err := s.Record(t.Context(), want); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	page, next, err := s.List(t.Context(), 10, nil)
	if err != nil || next != nil || len(page) != 1 {
		t.Fatalf("List() = %d entries, next %v, err %v; want one entry", len(page), next, err)
	}
	got := page[0]
	if !uuidFormat.MatchString(got.ID) || got.OccurredAt.Before(before.Add(-time.Minute)) || got.OccurredAt.Location() != time.UTC {
		t.Errorf("ID = %q, OccurredAt = %v; want a UUID and a recent UTC time", got.ID, got.OccurredAt)
	}
	if got.Action != want.Action || got.Outcome != want.Outcome || got.Actor != want.Actor || got.Resource != want.Resource ||
		!slices.Equal(got.ChangedFields, want.ChangedFields) || got.ClientIP != want.ClientIP || got.RequestID != want.RequestID {
		t.Errorf("entry = %+v, want %+v", got.Entry, want)
	}
	if got.ActorEmail != "jane@example.com" || got.ActorDisplayName != "Jane Doe" {
		t.Errorf("actor copies = %q, %q; want those of the account", got.ActorEmail, got.ActorDisplayName)
	}
}

func TestList_RejectsInvalidPageSize(t *testing.T) {
	t.Parallel()

	s, _ := newStore(t)
	for _, size := range []int{0, -1, audit.MaxPageSize + 1} {
		if _, _, err := s.List(t.Context(), size, nil); !errors.Is(err, audit.ErrInvalidPageSize) {
			t.Errorf("List(%d) error = %v, want ErrInvalidPageSize", size, err)
		}
	}
}
