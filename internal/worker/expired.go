// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"time"

	"nyktus.org/nyktus/internal/platform/db"
)

// Names of the periodic tasks that remove expired data.
const (
	TaskDeleteExpiredSignInData   = "delete_expired_sign_in_data"
	TaskDeleteExpiredAuditEntries = "delete_expired_audit_entries"
	TaskDeleteExpiredIncidentData = "delete_expired_incident_data"
)

// DeleteExpiredSignInData returns the task that removes expired sessions,
// challenges, unconfirmed second factors, links, API keys, sign-ins through
// the identity provider and setup tokens. The worker reads no accounts: a
// function of the database decides what has expired. It runs every five
// minutes, because anyone can start a sign-in through the identity provider,
// which leaves a row until it is removed.
func DeleteExpiredSignInData(q db.Querier) Task {
	return deleteTask(TaskDeleteExpiredSignInData, 5*time.Minute, q, `SELECT public.delete_expired_sign_in_data($1)`)
}

// DeleteExpiredAuditEntries returns the task that removes audit entries older
// than retentionDays. The function of the database refuses a retention below
// its lower limit.
func DeleteExpiredAuditEntries(q db.Querier, retentionDays int) Task {
	return deleteTask(TaskDeleteExpiredAuditEntries, time.Hour, q,
		`SELECT public.delete_expired_audit_entries($2, $1)`, retentionDays)
}

// DeleteExpiredIncidentData returns the task that removes events recorded
// more than retentionDays ago, incidents closed that long ago with their
// alerts and deliveries, and tests of channels requested that long ago.
func DeleteExpiredIncidentData(q db.Querier, retentionDays int) Task {
	return deleteTask(TaskDeleteExpiredIncidentData, time.Hour, q,
		`SELECT public.delete_expired_incident_data($2, $1)`, retentionDays)
}

// deleteTask returns a task that calls a function of the database with
// BatchSize as $1 and args from $2 on. The function removes up to a batch
// from each of its tables and returns how many rows it removed, so a total
// below one batch means that every table is done.
func deleteTask(name string, interval time.Duration, q db.Querier, query string, args ...any) Task {
	args = append([]any{BatchSize}, args...)
	return Task{
		Name:     name,
		Interval: interval,
		Step: func(ctx context.Context) (int64, bool, error) {
			var n int64
			if err := q.QueryRow(ctx, query, args...).Scan(&n); err != nil {
				return 0, false, err
			}
			return n, n >= BatchSize, nil
		},
	}
}
