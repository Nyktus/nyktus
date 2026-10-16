// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"time"

	"nyktus.org/nyktus/internal/platform/db"
)

// TaskDeleteExpiredSignInData names the task of DeleteExpiredSignInData.
const TaskDeleteExpiredSignInData = "delete_expired_sign_in_data"

// DeleteExpiredSignInData returns the task that removes expired sessions,
// challenges, unconfirmed second factors, links, API keys, sign-ins through
// the identity provider and setup tokens. The worker reads no accounts: a
// function of the database decides what has expired. It runs every five
// minutes, because anyone can start a sign-in through the identity provider,
// which leaves a row until it is removed.
func DeleteExpiredSignInData(q db.Querier) Task {
	return Task{
		Name:     TaskDeleteExpiredSignInData,
		Interval: 5 * time.Minute,
		Step: func(ctx context.Context) (int64, bool, error) {
			var n int64
			if err := q.QueryRow(ctx, `SELECT public.delete_expired_sign_in_data($1)`, BatchSize).Scan(&n); err != nil {
				return 0, false, err
			}
			// The function removes up to a batch from each table, so a total
			// below one batch means that every table is done.
			return n, n >= BatchSize, nil
		},
	}
}
