// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"

	"nyktus.org/nyktus/internal/platform/db"
)

// scope is everything that the worker's database role reaches: the jobs of
// events, incidents and their alerts, and the channels and deliveries of the
// alerts. It reads no inventory, because an event holds what its incident
// needs, and no accounts or audit entries.
var scope = db.Scope{
	GroupRole: "nyktus_worker",
	Tables: []string{
		"event_jobs", "events", "incidents", "alerts", "alert_channels", "alert_channel_secrets", "alert_deliveries",
	},
	// The checks of the techniques run with the privileges of the role that
	// writes.
	Functions: []string{"public.attack_technique_ids_valid(text[])"},
}

// CheckPrivileges returns db.ErrRolePrivileges unless the connected role stays
// within the scope of the worker, as a member of nyktus_worker.
func CheckPrivileges(ctx context.Context, q db.Querier) error {
	return db.CheckScope(ctx, q, scope)
}
