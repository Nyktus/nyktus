// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package incident

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// Processor processes the jobs of events for the worker and logs what became
// of them.
type Processor struct {
	store  *Store
	logger *slog.Logger
}

// NewProcessor returns a Processor that works on store.
func NewProcessor(store *Store, logger *slog.Logger) *Processor {
	if store == nil || logger == nil {
		panic("incident: nil store or logger")
	}
	return &Processor{store: store, logger: logger}
}

// Process processes the job of an event that is due, if there is one, as
// Store.ProcessNext describes. A job that failed and stays to be tried again
// is logged and counts as processed, because the database worked. Process
// returns an error only if the database could not be reached or the
// transaction failed.
func (p *Processor) Process(ctx context.Context, claimed func()) (bool, error) {
	res, found, err := p.store.ProcessNext(ctx, claimed)
	var jobErr *JobError
	switch {
	case errors.As(err, &jobErr):
		p.logger.ErrorContext(ctx, "incident: event not processed",
			slog.String("event_id", jobErr.EventID),
			slog.Int("attempts", jobErr.Attempts),
			slog.Time("retry_at", jobErr.Retry.UTC().Truncate(time.Second)),
			slog.Any("error", jobErr.Err))
		return true, nil
	case err != nil:
		return found, err
	case found && res.Opened:
		p.logger.InfoContext(ctx, "incident: opened", slog.Any("incident", res))
	case found:
		p.logger.DebugContext(ctx, "incident: event assigned", slog.Any("incident", res))
	}
	return found, nil
}
