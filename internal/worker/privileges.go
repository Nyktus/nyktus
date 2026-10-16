// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"

	"nyktus.org/nyktus/internal/platform/db"
)

// scope is everything that the worker's database role reaches: the jobs of
// events, incidents and their alerts, the channels and deliveries of the
// alerts, and the periodic tasks. It reads no inventory, because an event holds
// what its incident needs, and no accounts or audit entries: what it removes
// of them, it removes through functions that decide what has expired.
var scope = db.Scope{
	GroupRole: "nyktus_worker",
	Tables: []string{
		"event_jobs", "events", "incidents", "alerts", "alert_channels", "alert_channel_secrets", "alert_deliveries",
		"periodic_tasks",
	},
	Functions: []string{
		// The checks of the techniques run with the privileges of the role
		// that writes.
		"public.attack_technique_ids_valid(text[])",
		"public.delete_expired_sign_in_data(integer)",
		"public.delete_expired_audit_entries(integer, integer)",
		"public.delete_expired_incident_data(integer, integer)",
		"public.close_inactive_incidents(integer, integer)",
	},
}

// CheckPrivileges returns db.ErrRolePrivileges unless the connected role stays
// within the scope of the worker, as a member of nyktus_worker.
func CheckPrivileges(ctx context.Context, q db.Querier) error {
	return db.CheckScope(ctx, q, scope)
}
