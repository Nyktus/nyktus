// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package clocktest_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock/clocktest"
)

func TestFake_Advance_WakesOnlyWaitsThatAreDue(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	short, long := make(chan error, 1), make(chan error, 1)
	go func() { short <- clk.Wait(t.Context(), time.Second) }()
	go func() { long <- clk.Wait(t.Context(), time.Minute) }()
	clk.BlockUntil(2)

	clk.Advance(time.Second)
	if err := <-short; err != nil {
		t.Errorf("short wait = %v, want nil", err)
	}
	if got := clk.Pending(); got != 1 {
		t.Errorf("Pending() = %d after the short wait, want 1", got)
	}
	clk.Advance(59 * time.Second)
	if err := <-long; err != nil {
		t.Errorf("long wait = %v, want nil", err)
	}
}

func TestFake_Wait_CanceledContext_LeavesNoWait(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- clk.Wait(ctx, time.Hour) }()
	clk.BlockUntil(1)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Wait() = %v, want context.Canceled", err)
	}
	if got := clk.Pending(); got != 0 {
		t.Errorf("Pending() = %d, want 0", got)
	}
}

func TestFake_SetWall_DoesNotMoveTheMonotonicClock(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	before := clk.Deadline(0)
	clk.SetWall(-time.Hour)
	if got := clk.Elapsed(); got != 0 {
		t.Errorf("Elapsed() = %v after the wall clock was set, want 0", got)
	}
	if got := clk.Deadline(0); !got.Equal(before.Add(-time.Hour)) {
		t.Errorf("Deadline(0) = %v, want %v", got, before.Add(-time.Hour))
	}
}
