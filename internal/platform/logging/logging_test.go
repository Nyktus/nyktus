// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
)

func TestNew_ContextAttributesAreAdded(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(&buf, slog.LevelInfo)

	ctx := WithAttrs(t.Context(), slog.String("request_id", "abc"))
	ctx = WithAttrs(ctx, slog.String("actor_id", "u1"))
	logger.InfoContext(ctx, "test: message", "key", "value")

	record := decodeRecord(t, &buf)
	for key, want := range map[string]string{"request_id": "abc", "actor_id": "u1", "key": "value", "msg": "test: message"} {
		if got := record[key]; got != want {
			t.Errorf("record[%q] = %v, want %q", key, got, want)
		}
	}
}

func TestNew_WithoutContextAttributes(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	New(&buf, slog.LevelInfo).InfoContext(t.Context(), "test: message")

	record := decodeRecord(t, &buf)
	if _, ok := record["request_id"]; ok {
		t.Errorf("record contains request_id without context attributes: %v", record)
	}
}

func TestWithAttrs_DoesNotModifyParentContext(t *testing.T) {
	t.Parallel()

	parent := WithAttrs(t.Context(), slog.String("a", "1"))
	_ = WithAttrs(parent, slog.String("b", "2"))

	var buf bytes.Buffer
	New(&buf, slog.LevelInfo).InfoContext(parent, "test: message")

	record := decodeRecord(t, &buf)
	if _, ok := record["b"]; ok {
		t.Errorf("parent context received attribute of child context: %v", record)
	}
}

// The access log receives the request context before the router authenticates the
// request. Attributes added to the scope later must still reach its record.
func TestScope_AttributesAddedLaterReachOuterRecords(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(&buf, slog.LevelInfo)
	outer := WithScope(t.Context())
	inner := WithAttrs(outer, slog.String("request_id", "abc"))
	AddToScope(inner, slog.String("user_id", "u1"))

	logger.InfoContext(outer, "test: message")
	record := decodeRecord(t, &buf)
	if record["user_id"] != "u1" {
		t.Errorf("record = %v, want user_id from the scope", record)
	}
}

func TestAddToScope_WithoutScopeDoesNothing(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	AddToScope(t.Context(), slog.String("user_id", "u1"))
	New(&buf, slog.LevelInfo).InfoContext(t.Context(), "test: message")
	if record := decodeRecord(t, &buf); record["user_id"] != nil {
		t.Errorf("record = %v, want no user_id", record)
	}
}

func TestScope_IsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	ctx := WithScope(t.Context())
	logger := New(io.Discard, slog.LevelInfo)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			AddToScope(ctx, slog.Int("n", 1))
			logger.InfoContext(ctx, "test: message")
		})
	}
	wg.Wait()
}

func TestNew_RespectsLevel(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	New(&buf, slog.LevelWarn).InfoContext(context.Background(), "test: suppressed")

	if buf.Len() != 0 {
		t.Errorf("info record written at warn level: %s", buf.String())
	}
}

func TestParseLevel(t *testing.T) {
	t.Parallel()

	for input, want := range map[string]slog.Level{"debug": slog.LevelDebug, "INFO": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError} {
		got, err := ParseLevel(input)
		if err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v; want %v", input, got, err, want)
		}
	}
	if _, err := ParseLevel("verbose"); err == nil {
		t.Error("ParseLevel(\"verbose\") returned no error")
	}
}

func decodeRecord(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("decode log record %q: %v", buf.String(), err)
	}
	return record
}
