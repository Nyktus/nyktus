// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/schematest"
)

// The worker refuses to start with a login that reaches more than its tables,
// such as the login of the console, or that is no member of its group role.
func TestCheckPrivileges(t *testing.T) {
	t.Parallel()

	ownerURL, workerURL := schematest.Worker(t)
	if err := CheckPrivileges(t.Context(), schematest.Open(t, workerURL)); err != nil {
		t.Errorf("CheckPrivileges(worker) = %v, want nil", err)
	}

	_, consoleURL := dbtest.Role(t, ownerURL, "console", "IN ROLE "+pgx.Identifier{schematest.ConsoleRole}.Sanitize())
	// The console cannot run the functions of the worker, which is checked
	// before its other privileges.
	if err := CheckPrivileges(t.Context(), schematest.Open(t, consoleURL)); !errors.Is(err, db.ErrRolePrivileges) || !strings.Contains(err.Error(), "public.delete_expired_sign_in_data(integer)") ||
		!strings.Contains(err.Error(), "connect as a member of nyktus_worker") {
		t.Errorf("CheckPrivileges(console) = %v, want ErrRolePrivileges naming the function of the worker", err)
	}
	// A member of the worker's group role with a privilege of its own.
	name, widerURL := dbtest.Role(t, ownerURL, "wider", "IN ROLE "+pgx.Identifier{schematest.WorkerRole}.Sanitize())
	dbtest.Exec(t, ownerURL, "GRANT SELECT ON honeytokens TO "+pgx.Identifier{name}.Sanitize())
	if err := CheckPrivileges(t.Context(), schematest.Open(t, widerURL)); !errors.Is(err, db.ErrRolePrivileges) || !strings.Contains(err.Error(), "tables [honeytokens]") {
		t.Errorf("CheckPrivileges(wider) = %v, want ErrRolePrivileges naming the honeytokens", err)
	}
	// A login that may change what an event recorded, through a grant of its
	// own on a table of the worker.
	name, ownURL := dbtest.Role(t, ownerURL, "own", "IN ROLE "+pgx.Identifier{schematest.WorkerRole}.Sanitize())
	dbtest.Exec(t, ownerURL, "GRANT UPDATE ON events TO "+pgx.Identifier{name}.Sanitize())
	if err := CheckPrivileges(t.Context(), schematest.Open(t, ownURL)); !errors.Is(err, db.ErrRolePrivileges) || !strings.Contains(err.Error(), "lacks: [events: UPDATE]") {
		t.Errorf("CheckPrivileges(own) = %v, want ErrRolePrivileges naming UPDATE on events", err)
	}
	_, triggerURL := dbtest.Role(t, ownerURL, "trigger", "IN ROLE "+pgx.Identifier{schematest.TriggerRole}.Sanitize())
	if err := CheckPrivileges(t.Context(), schematest.Open(t, triggerURL)); !errors.Is(err, db.ErrRolePrivileges) || !strings.Contains(err.Error(), "cannot execute") {
		t.Errorf("CheckPrivileges(trigger) = %v, want ErrRolePrivileges containing %q", err, "cannot execute")
	}
}
