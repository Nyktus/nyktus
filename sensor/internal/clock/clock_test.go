// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package clock_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock"
)

func TestSystem_Wait_CanceledContext_ReturnsItsError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	// A wait that is already canceled returns at once, whatever its length.
	if err := clock.NewSystem().Wait(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("Wait() = %v, want context.Canceled", err)
	}
}

func TestSystem_Wait_CancelWhileWaiting_ReturnsItsError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- clock.NewSystem().Wait(ctx, time.Hour) }()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Wait() = %v, want context.Canceled", err)
	}
}

func TestSystem_Wait_NoDuration_ReturnsAtOnce(t *testing.T) {
	t.Parallel()

	if err := clock.NewSystem().Wait(t.Context(), 0); err != nil {
		t.Errorf("Wait(0) = %v, want nil", err)
	}
}

func TestSystem_Elapsed_NeverGoesBack(t *testing.T) {
	t.Parallel()

	c := clock.NewSystem()
	prev := c.Elapsed()
	for range 1000 {
		now := c.Elapsed()
		if now < prev {
			t.Fatalf("Elapsed() = %v after %v", now, prev)
		}
		prev = now
	}
}

func TestSystem_Deadline_LiesInTheFuture(t *testing.T) {
	t.Parallel()

	if d := clock.NewSystem().Deadline(time.Hour); !d.After(time.Now().Add(59 * time.Minute)) {
		t.Errorf("Deadline(1h) = %v, want about an hour from now", d)
	}
}
