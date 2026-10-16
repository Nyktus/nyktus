// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package incident

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/worker"
)

// TaskCloseInactive names the task of CloseInactive.
const TaskCloseInactive = "close_inactive_incidents"

// CloseInactive returns the task that closes incidents, open or acknowledged,
// whose last event was more than inactiveDays ago. A closed incident lets the
// next event of its resource open a new incident with a new alert; one that
// never closes would collect every later event without an alert. With
// inactiveDays 0, incidents stay open until they are triaged.
//
// The worker cannot change the status of an incident itself. A function of
// the database closes the incidents and records each in the audit log with
// the system as the actor.
func CloseInactive(logger *slog.Logger, q db.Querier, inactiveDays int) worker.Task {
	return worker.Task{
		Name:     TaskCloseInactive,
		Interval: 15 * time.Minute,
		Step: func(ctx context.Context) (int64, bool, error) {
			if inactiveDays == 0 {
				return 0, false, nil
			}
			rows, err := q.Query(ctx, `SELECT public.close_inactive_incidents($1, $2)`, inactiveDays, worker.BatchSize)
			if err != nil {
				return 0, false, err
			}
			closed, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				return 0, false, err
			}
			for _, id := range closed {
				logger.InfoContext(ctx, "incident: closed", slog.String("incident_id", id), slog.String("reason", "inactive"))
			}
			return int64(len(closed)), len(closed) >= worker.BatchSize, nil
		},
	}
}
