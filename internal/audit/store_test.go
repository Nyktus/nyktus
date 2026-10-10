// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/platform/request"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/user"
)

// keyID stands in for the identifier of an API key.
const keyID = "00000000-0000-4000-8000-000000000001"

var uuidFormat = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// newStore returns a store connected as the console's database role.
func newStore(t *testing.T) (*audit.Store, *pgxpool.Pool) {
	t.Helper()
	_, consoleURL := schematest.Console(t)
	pool := schematest.Open(t, consoleURL)
	return audit.NewStore(pool), pool
}

// createUser inserts an account and returns its ID.
func createUser(t *testing.T, q db.Querier, email, displayName string) string {
	t.Helper()
	var id string
	err := q.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status) VALUES ($1, $2, 'admin', 'pending')
RETURNING id`, email, displayName).Scan(&id)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return id
}

// userEntry returns a valid entry of userID that updates another user.
func userEntry(userID, resourceID string) audit.Entry {
	return audit.Entry{
		Action:        "user.update",
		Outcome:       audit.OutcomeSuccess,
		Actor:         audit.Actor{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: userID},
		Resource:      audit.Resource{Type: "user", ID: resourceID},
		ChangedFields: []string{"role", "display_name"},
		ClientIP:      netip.MustParseAddr("192.0.2.10"),
		RequestID:     rand.Text(),
	}
}

// systemEntry returns a valid entry of the command line.
func systemEntry() audit.Entry {
	return audit.Entry{
		Action:  "user.create",
		Outcome: audit.OutcomeSuccess,
		Actor:   audit.Actor{Kind: audit.ActorSystem, Method: audit.AuthCLI},
	}
}

// requestID returns an ID from the request ID middleware. The schema checks its
// format, so a change of the generator must fail here instead of failing every
// audited action.
func requestID(t *testing.T) string {
	t.Helper()
	var id string
	h := httpx.RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		id = request.ID(r.Context())
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if id == "" {
		t.Fatal("the middleware assigned no request ID")
	}
	return id
}

// row is an entry as stored, read as the console's database role.
type row struct {
	ID               string
	OccurredAt       time.Time
	Action           string
	Outcome          string
	ActorKind        string
	AuthMethod       string
	ActorUserID      *string
	ActorEmail       *string
	ActorDisplayName *string
	APIKeyID         *string
	ResourceType     *string
	ResourceID       *string
	ChangedFields    []string
	ClientIP         *string
	RequestID        *string
}

// querier is implemented by a connection pool and a transaction.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func readEntries(t *testing.T, q querier) []row {
	t.Helper()
	rows, err := q.Query(t.Context(), `
SELECT id, occurred_at, action, outcome, actor_kind, auth_method, actor_user_id::text, actor_email,
	actor_display_name, api_key_id::text, resource_type, resource_id::text, changed_fields,
	host(client_ip), request_id
FROM audit_entries
ORDER BY occurred_at, id`)
	if err != nil {
		t.Fatalf("query entries: %v", err)
	}
	entries, err := pgx.CollectRows(rows, pgx.RowToStructByPos[row])
	if err != nil {
		t.Fatalf("read entries: %v", err)
	}
	return entries
}

func readEntry(t *testing.T, q querier) row {
	t.Helper()
	entries := readEntries(t, q)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	return entries[0]
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func TestRecord_StoresEntryOfUser(t *testing.T) {
	t.Parallel()

	_, pool := newStore(t)
	actorID := createUser(t, pool, "jane@example.com", "Jane Doe")
	resourceID := createUser(t, pool, "john@example.com", "John Doe")
	e := userEntry(actorID, resourceID)
	e.RequestID = requestID(t)
	if err := audit.NewStore(pool).Record(t.Context(), e); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	r := readEntry(t, pool)
	if !uuidFormat.MatchString(r.ID) {
		t.Errorf("id = %q, want a random UUID", r.ID)
	}
	if r.Action != "user.update" || r.Outcome != "success" || r.ActorKind != "user" || r.AuthMethod != "session" {
		t.Errorf("action, outcome, actor = %s, %s, %s/%s, want user.update, success, user/session",
			r.Action, r.Outcome, r.ActorKind, r.AuthMethod)
	}
	if deref(r.ActorUserID) != actorID || deref(r.ActorEmail) != "jane@example.com" || deref(r.ActorDisplayName) != "Jane Doe" {
		t.Errorf("actor = %s, %s, %s, want %s with the address and name of the account",
			deref(r.ActorUserID), deref(r.ActorEmail), deref(r.ActorDisplayName), actorID)
	}
	if r.APIKeyID != nil {
		t.Errorf("api_key_id = %s, want NULL", *r.APIKeyID)
	}
	if deref(r.ResourceType) != "user" || deref(r.ResourceID) != resourceID {
		t.Errorf("resource = %s %s, want user %s", deref(r.ResourceType), deref(r.ResourceID), resourceID)
	}
	if !slices.Equal(r.ChangedFields, []string{"role", "display_name"}) {
		t.Errorf("changed_fields = %v, want [role display_name]", r.ChangedFields)
	}
	if deref(r.ClientIP) != "192.0.2.10" || deref(r.RequestID) != e.RequestID {
		t.Errorf("client_ip, request_id = %s, %s, want 192.0.2.10, %s", deref(r.ClientIP), deref(r.RequestID), e.RequestID)
	}
}

// Entries take the time of the write, so the entries of one transaction keep
// their order. Every statement is a round trip to the database, which takes far
// longer than the microsecond resolution of a timestamp.
func TestRecord_OrdersEntriesOfOneTransaction(t *testing.T) {
	t.Parallel()

	_, pool := newStore(t)
	var (
		entries               []row
		txStart, beforeCommit time.Time
	)
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		s := audit.NewStore(tx)
		for _, action := range []audit.Action{"user.create", "user.update"} {
			e := systemEntry()
			e.Action = action
			if err := s.Record(t.Context(), e); err != nil {
				return err
			}
		}
		entries = readEntries(t, tx)
		return tx.QueryRow(t.Context(), "SELECT now(), clock_timestamp()").Scan(&txStart, &beforeCommit)
	})
	if err != nil {
		t.Fatalf("transaction error = %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	first, second := entries[0], entries[1]
	if first.Action != "user.create" || !first.OccurredAt.After(txStart) ||
		!second.OccurredAt.After(first.OccurredAt) || second.OccurredAt.After(beforeCommit) {
		t.Errorf("transaction started at %v; entries %s at %v, %s at %v; want ascending times of the writes",
			txStart, first.Action, first.OccurredAt, second.Action, second.OccurredAt)
	}
}

// Every outcome of the code is accepted by the schema.
func TestRecord_StoresEveryOutcome(t *testing.T) {
	t.Parallel()

	s, pool := newStore(t)
	outcomes := []audit.Outcome{audit.OutcomeSuccess, audit.OutcomeFailure, audit.OutcomeDenied}
	for _, outcome := range outcomes {
		e := systemEntry()
		e.Outcome = outcome
		if err := s.Record(t.Context(), e); err != nil {
			t.Errorf("Record() with outcome %s: error = %v, want nil", outcome, err)
		}
	}

	var got []string
	for _, r := range readEntries(t, pool) {
		got = append(got, r.Outcome)
	}
	slices.Sort(got)
	if want := []string{"denied", "failure", "success"}; !slices.Equal(got, want) {
		t.Errorf("outcomes = %v, want %v", got, want)
	}
}

func TestRecord_StoresEveryKindOfActor(t *testing.T) {
	t.Parallel()

	s, pool := newStore(t)
	userID := createUser(t, pool, "jane@example.com", "Jane Doe")
	actors := []audit.Actor{
		{Kind: audit.ActorUser, Method: audit.AuthPassword, UserID: userID},
		{Kind: audit.ActorUser, Method: audit.AuthOIDC, UserID: userID},
		{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: userID},
		{Kind: audit.ActorUser, Method: audit.AuthAPIKey, UserID: userID, APIKeyID: keyID},
		{Kind: audit.ActorSetup, Method: audit.AuthSetupToken},
		{Kind: audit.ActorSystem, Method: audit.AuthCLI},
		{Kind: audit.ActorSystem, Method: audit.AuthNone},
		{Kind: audit.ActorAnonymous, Method: audit.AuthPassword},
		{Kind: audit.ActorAnonymous, Method: audit.AuthOIDC},
		{Kind: audit.ActorAnonymous, Method: audit.AuthSetupToken},
	}
	for _, actor := range actors {
		e := systemEntry()
		e.Actor = actor
		if err := s.Record(t.Context(), e); err != nil {
			t.Errorf("Record() with actor %+v: error = %v, want nil", actor, err)
		}
	}

	entries := readEntries(t, pool)
	if len(entries) != len(actors) {
		t.Fatalf("got %d entries, want %d", len(entries), len(actors))
	}
	for _, r := range entries {
		isUser := r.ActorKind == string(audit.ActorUser)
		if hasCopy := r.ActorEmail != nil && r.ActorDisplayName != nil; hasCopy != isUser {
			t.Errorf("actor %s/%s: copy of address and name = %v, want %v", r.ActorKind, r.AuthMethod, hasCopy, isUser)
		}
		if hasKey := deref(r.APIKeyID) == keyID; hasKey != (r.AuthMethod == string(audit.AuthAPIKey)) {
			t.Errorf("actor %s/%s: api_key_id = %s", r.ActorKind, r.AuthMethod, deref(r.APIKeyID))
		}
	}
}

func TestRecord_StoresAbsentValuesAsNull(t *testing.T) {
	t.Parallel()

	s, pool := newStore(t)
	if err := s.Record(t.Context(), systemEntry()); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	r := readEntry(t, pool)
	if r.ActorUserID != nil || r.ActorEmail != nil || r.ActorDisplayName != nil || r.APIKeyID != nil {
		t.Errorf("actor columns = %s, %s, %s, %s, want NULL",
			deref(r.ActorUserID), deref(r.ActorEmail), deref(r.ActorDisplayName), deref(r.APIKeyID))
	}
	if r.ResourceType != nil || r.ResourceID != nil || r.ClientIP != nil || r.RequestID != nil {
		t.Errorf("resource, client_ip, request_id = %s %s, %s, %s, want NULL",
			deref(r.ResourceType), deref(r.ResourceID), deref(r.ClientIP), deref(r.RequestID))
	}
	if r.ChangedFields == nil || len(r.ChangedFields) != 0 {
		t.Errorf("changed_fields = %#v, want an empty list", r.ChangedFields)
	}
}

func TestRecord_StoresOneSpellingPerClientAddress(t *testing.T) {
	t.Parallel()

	s, pool := newStore(t)
	for _, addr := range []string{"::ffff:192.0.2.1", "fe80::1%eth0", "2001:db8::1"} {
		e := systemEntry()
		e.ClientIP = netip.MustParseAddr(addr)
		if err := s.Record(t.Context(), e); err != nil {
			t.Fatalf("Record() with client %s: error = %v", addr, err)
		}
	}

	var got []string
	for _, r := range readEntries(t, pool) {
		got = append(got, deref(r.ClientIP))
	}
	slices.Sort(got)
	if want := []string{"192.0.2.1", "2001:db8::1", "fe80::1"}; !slices.Equal(got, want) {
		t.Errorf("client addresses = %v, want %v", got, want)
	}
}

// The schema is the only validation of an entry, so every constraint is tested
// through the store, as the console's database role.
func TestRecord_StoresClientAndRequestOfTheMiddleware(t *testing.T) {
	t.Parallel()

	store, pool := newStore(t)
	e, requestID := requestEntry(t, systemEntry())
	if err := store.Record(t.Context(), e); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	got := readEntry(t, pool)
	if deref(got.ClientIP) != "203.0.113.9" || deref(got.RequestID) != requestID {
		t.Errorf("client_ip = %q, request_id = %q, want 203.0.113.9 and %q", deref(got.ClientIP), deref(got.RequestID), requestID)
	}
}

func TestRecord_RejectsInvalidEntries(t *testing.T) {
	t.Parallel()

	s, pool := newStore(t)
	userID := createUser(t, pool, "jane@example.com", "Jane Doe")
	unknownUserID := "00000000-0000-4000-8000-000000000002"
	fields := func(n int) []string {
		names := make([]string, n)
		for i := range names {
			names[i] = "field_" + strings.Repeat("x", i)
		}
		return names
	}

	tests := []struct {
		name       string
		modify     func(*audit.Entry)
		constraint string
	}{
		{name: "empty action", modify: func(e *audit.Entry) { e.Action = "" }, constraint: "audit_entries_action_check"},
		{name: "action without verb", modify: func(e *audit.Entry) { e.Action = "user" }, constraint: "audit_entries_action_check"},
		{name: "action with empty verb", modify: func(e *audit.Entry) { e.Action = "user." }, constraint: "audit_entries_action_check"},
		{name: "action in upper case", modify: func(e *audit.Entry) { e.Action = "User.create" }, constraint: "audit_entries_action_check"},
		{name: "action with three parts", modify: func(e *audit.Entry) { e.Action = "user.role.update" }, constraint: "audit_entries_action_check"},
		{name: "action with hyphen", modify: func(e *audit.Entry) { e.Action = "api-key.create" }, constraint: "audit_entries_action_check"},
		{name: "action with newline", modify: func(e *audit.Entry) { e.Action = "user.create\n" }, constraint: "audit_entries_action_check"},
		{
			name:       "action too long",
			modify:     func(e *audit.Entry) { e.Action = audit.Action(strings.Repeat("a", 32) + "." + strings.Repeat("b", 32)) },
			constraint: "audit_entries_action_check",
		},
		{name: "unknown outcome", modify: func(e *audit.Entry) { e.Outcome = "ok" }, constraint: "audit_entries_outcome_check"},
		{name: "unknown actor kind", modify: func(e *audit.Entry) { e.Actor.Kind = "admin" }, constraint: "audit_entries_actor_check"},
		{name: "unknown method", modify: func(e *audit.Entry) { e.Actor.Method = "kerberos" }, constraint: "audit_entries_actor_check"},
		{
			name:       "user through the command line",
			modify:     func(e *audit.Entry) { e.Actor.Method = audit.AuthCLI },
			constraint: "audit_entries_actor_check",
		},
		{
			name:       "user through the setup token",
			modify:     func(e *audit.Entry) { e.Actor.Method = audit.AuthSetupToken },
			constraint: "audit_entries_actor_check",
		},
		{
			name:       "user without account",
			modify:     func(e *audit.Entry) { e.Actor.UserID = "" },
			constraint: "audit_entries_actor_check",
		},
		{
			name:       "user with unknown account",
			modify:     func(e *audit.Entry) { e.Actor.UserID = unknownUserID },
			constraint: "audit_entries_actor_check",
		},
		{
			name: "setup with password",
			modify: func(e *audit.Entry) {
				e.Actor = audit.Actor{Kind: audit.ActorSetup, Method: audit.AuthPassword}
			},
			constraint: "audit_entries_actor_check",
		},
		{
			name: "system with session",
			modify: func(e *audit.Entry) {
				e.Actor = audit.Actor{Kind: audit.ActorSystem, Method: audit.AuthSession}
			},
			constraint: "audit_entries_actor_check",
		},
		{
			name: "anonymous with session",
			modify: func(e *audit.Entry) {
				e.Actor = audit.Actor{Kind: audit.ActorAnonymous, Method: audit.AuthSession}
			},
			constraint: "audit_entries_actor_check",
		},
		{
			name: "anonymous with API key",
			modify: func(e *audit.Entry) {
				e.Actor = audit.Actor{Kind: audit.ActorAnonymous, Method: audit.AuthAPIKey, APIKeyID: keyID}
			},
			constraint: "audit_entries_actor_check",
		},
		{
			name: "system with account",
			modify: func(e *audit.Entry) {
				e.Actor = audit.Actor{Kind: audit.ActorSystem, Method: audit.AuthCLI, UserID: userID}
			},
			constraint: "audit_entries_actor_check",
		},
		{
			name: "anonymous with account",
			modify: func(e *audit.Entry) {
				e.Actor = audit.Actor{Kind: audit.ActorAnonymous, Method: audit.AuthPassword, UserID: userID}
			},
			constraint: "audit_entries_actor_check",
		},
		{
			name:       "API key without identifier",
			modify:     func(e *audit.Entry) { e.Actor.Method = audit.AuthAPIKey },
			constraint: "audit_entries_api_key_check",
		},
		{
			name:       "key identifier with session",
			modify:     func(e *audit.Entry) { e.Actor.APIKeyID = keyID },
			constraint: "audit_entries_api_key_check",
		},
		{
			name:       "resource type without identifier",
			modify:     func(e *audit.Entry) { e.Resource.ID = "" },
			constraint: "audit_entries_resource_check",
		},
		{
			name:       "resource identifier without type",
			modify:     func(e *audit.Entry) { e.Resource.Type = "" },
			constraint: "audit_entries_resource_check",
		},
		{
			name:       "resource type in upper case",
			modify:     func(e *audit.Entry) { e.Resource.Type = "User" },
			constraint: "audit_entries_resource_check",
		},
		{
			name:       "resource type too long",
			modify:     func(e *audit.Entry) { e.Resource.Type = strings.Repeat("a", 65) },
			constraint: "audit_entries_resource_check",
		},
		{
			name:       "field name in upper case",
			modify:     func(e *audit.Entry) { e.ChangedFields = []string{"Email"} },
			constraint: "audit_entries_changed_fields_check",
		},
		{
			name:       "empty field name",
			modify:     func(e *audit.Entry) { e.ChangedFields = []string{""} },
			constraint: "audit_entries_changed_fields_check",
		},
		{
			name:       "field name with value",
			modify:     func(e *audit.Entry) { e.ChangedFields = []string{"role=admin"} },
			constraint: "audit_entries_changed_fields_check",
		},
		{
			name:       "field name too long",
			modify:     func(e *audit.Entry) { e.ChangedFields = []string{strings.Repeat("a", 65)} },
			constraint: "audit_entries_changed_fields_check",
		},
		{
			name:       "duplicate field name",
			modify:     func(e *audit.Entry) { e.ChangedFields = []string{"role", "role"} },
			constraint: "audit_entries_changed_fields_check",
		},
		{
			name:       "too many fields",
			modify:     func(e *audit.Entry) { e.ChangedFields = fields(33) },
			constraint: "audit_entries_changed_fields_check",
		},
		{
			name:       "request ID from a client",
			modify:     func(e *audit.Entry) { e.RequestID = "client-supplied" },
			constraint: "audit_entries_request_id_check",
		},
		{
			name:       "request ID in lower case",
			modify:     func(e *audit.Entry) { e.RequestID = strings.ToLower(rand.Text()) },
			constraint: "audit_entries_request_id_check",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := userEntry(userID, userID)
			tt.modify(&e)
			wantConstraint(t, s.Record(t.Context(), e), tt.constraint)
		})
	}

	t.Run("longest valid values", func(t *testing.T) {
		e := userEntry(userID, userID)
		e.Action = audit.Action(strings.Repeat("a", 31) + "." + strings.Repeat("b", 32))
		e.Resource.Type = strings.Repeat("a", 64)
		e.ChangedFields = append(fields(31), strings.Repeat("a", 64))
		if err := s.Record(t.Context(), e); err != nil {
			t.Errorf("Record() error = %v, want nil", err)
		}
	})

	for _, field := range []string{"Actor.UserID", "Resource.ID"} {
		t.Run(field+" that is not a UUID", func(t *testing.T) {
			e := userEntry(userID, userID)
			if field == "Actor.UserID" {
				e.Actor.UserID = "jane"
			} else {
				e.Resource.ID = "jane"
			}
			var pgErr *pgconn.PgError
			// 22P02 is invalid_text_representation.
			if err := s.Record(t.Context(), e); !errors.As(err, &pgErr) || pgErr.Code != "22P02" {
				t.Errorf("Record() error = %v, want invalid_text_representation", err)
			}
		})
	}
}

// Values that the store cannot produce are tested against the schema directly.
func TestSchema_RejectsInvalidEntries(t *testing.T) {
	t.Parallel()

	_, pool := newStore(t)
	tests := []struct {
		name, column, value, constraint string
	}{
		{name: "network instead of address", column: "client_ip", value: "192.0.2.0/24", constraint: "audit_entries_client_ip_check"},
		{name: "IPv6 network", column: "client_ip", value: "2001:db8::/64", constraint: "audit_entries_client_ip_check"},
		{name: "field name NULL", column: "changed_fields", value: "{role,NULL}", constraint: "audit_entries_changed_fields_check"},
		{name: "nested field names", column: "changed_fields", value: "{{role},{email}}", constraint: "audit_entries_changed_fields_check"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := map[string]string{"client_ip": "192.0.2.1", "changed_fields": "{}"}
			values[tt.column] = tt.value
			_, err := pool.Exec(t.Context(), `
INSERT INTO audit_entries (action, outcome, actor_kind, auth_method, client_ip, changed_fields)
VALUES ('user.create', 'success', 'system', 'cli', $1, $2)`, values["client_ip"], values["changed_fields"])
			wantConstraint(t, err, tt.constraint)
		})
	}
}

func wantConstraint(t *testing.T, err error, constraint string) {
	t.Helper()
	var pgErr *pgconn.PgError
	// 23514 is check_violation.
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != constraint {
		t.Errorf("error = %v, want a violation of %s", err, constraint)
	}
}

func TestRecord_IsAtomicWithTheAction(t *testing.T) {
	t.Parallel()

	_, pool := newStore(t)
	errAction := errors.New("action failed")

	t.Run("rolled back", func(t *testing.T) {
		err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			u, err := user.NewStore(tx).Create(t.Context(), user.NewUser{Email: "rollback@example.com", DisplayName: "Rollback", Role: user.RoleViewer})
			if err != nil {
				return err
			}
			if err := audit.NewStore(tx).Record(t.Context(), userEntry(u.ID, u.ID)); err != nil {
				return err
			}
			return errAction
		})
		if !errors.Is(err, errAction) {
			t.Fatalf("transaction error = %v, want %v", err, errAction)
		}
		var users int
		if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM users").Scan(&users); err != nil {
			t.Fatalf("count users: %v", err)
		}
		if entries := readEntries(t, pool); len(entries) != 0 || users != 0 {
			t.Errorf("got %d entries and %d users after the rollback, want none", len(entries), users)
		}
	})

	// A rejected entry aborts the transaction, so the action cannot be committed
	// without it, even by a caller that ignores the error of Record.
	t.Run("entry rejected", func(t *testing.T) {
		err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			u, err := user.NewStore(tx).Create(t.Context(), user.NewUser{Email: "rejected@example.com", DisplayName: "Rejected", Role: user.RoleViewer})
			if err != nil {
				return err
			}
			e := userEntry(u.ID, u.ID)
			e.Action = "invalid"
			if err := audit.NewStore(tx).Record(t.Context(), e); err == nil {
				t.Error("Record() error = nil, want a violation")
			}
			return nil
		})
		if !errors.Is(err, pgx.ErrTxCommitRollback) {
			t.Errorf("commit error = %v, want %v", err, pgx.ErrTxCommitRollback)
		}
		var users int
		if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM users WHERE email = 'rejected@example.com'").Scan(&users); err != nil {
			t.Fatalf("count users: %v", err)
		}
		if users != 0 {
			t.Error("the action was committed without its entry")
		}
	})

	t.Run("committed", func(t *testing.T) {
		err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			u, err := user.NewStore(tx).Create(t.Context(), user.NewUser{Email: "commit@example.com", DisplayName: "Commit", Role: user.RoleViewer})
			if err != nil {
				return err
			}
			return audit.NewStore(tx).Record(t.Context(), userEntry(u.ID, u.ID))
		})
		if err != nil {
			t.Fatalf("transaction error = %v", err)
		}
		if r := readEntry(t, pool); deref(r.ActorEmail) != "commit@example.com" {
			t.Errorf("actor_email = %s, want commit@example.com", deref(r.ActorEmail))
		}
	})
}

func TestEntry_RemainsReadableAfterUserIsDeleted(t *testing.T) {
	t.Parallel()

	s, pool := newStore(t)
	actorID := createUser(t, pool, "jane@example.com", "Jane Doe")
	resourceID := createUser(t, pool, "john@example.com", "John Doe")
	if err := s.Record(t.Context(), userEntry(actorID, resourceID)); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	// The console deletes users with its own role; the database clears the
	// references of the entries.
	if _, err := pool.Exec(t.Context(), "DELETE FROM users"); err != nil {
		t.Fatalf("delete users: %v", err)
	}

	r := readEntry(t, pool)
	if r.ActorUserID != nil {
		t.Errorf("actor_user_id = %s, want NULL", *r.ActorUserID)
	}
	if r.ActorKind != "user" || deref(r.ActorEmail) != "jane@example.com" || deref(r.ActorDisplayName) != "Jane Doe" {
		t.Errorf("actor = %s, %s, %s, want user, jane@example.com, Jane Doe",
			r.ActorKind, deref(r.ActorEmail), deref(r.ActorDisplayName))
	}
	if deref(r.ResourceID) != resourceID {
		t.Errorf("resource_id = %s, want %s", deref(r.ResourceID), resourceID)
	}
}

func TestEntry_KeepsTheActorAsOfTheAction(t *testing.T) {
	t.Parallel()

	s, pool := newStore(t)
	actorID := createUser(t, pool, "jane@example.com", "Jane Doe")
	if err := s.Record(t.Context(), userEntry(actorID, actorID)); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	_, err := pool.Exec(t.Context(), `
UPDATE users SET email = 'jane.roe@example.com', display_name = 'Jane Roe', updated_at = now()
WHERE id = $1`, actorID)
	if err != nil {
		t.Fatalf("update user: %v", err)
	}

	if r := readEntry(t, pool); deref(r.ActorEmail) != "jane@example.com" || deref(r.ActorDisplayName) != "Jane Doe" {
		t.Errorf("actor = %s, %s, want the address and name at the time of the action",
			deref(r.ActorEmail), deref(r.ActorDisplayName))
	}
}

func TestAuditLog_IsAppendOnlyForTheConsole(t *testing.T) {
	t.Parallel()

	s, pool := newStore(t)
	actorID := createUser(t, pool, "jane@example.com", "Jane Doe")
	if err := s.Record(t.Context(), userEntry(actorID, actorID)); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	before := readEntry(t, pool)

	denied := []string{
		"UPDATE audit_entries SET outcome = 'failure'",
		"UPDATE audit_entries SET occurred_at = now() - interval '1 year'",
		"UPDATE audit_entries SET actor_email = 'someone@example.com'",
		"UPDATE audit_entries SET actor_user_id = NULL",
		"DELETE FROM audit_entries",
		"TRUNCATE audit_entries",
		"ALTER TABLE audit_entries DISABLE TRIGGER audit_entries_copy_actor",
		"DROP TRIGGER audit_entries_copy_actor ON audit_entries",
		"ALTER TABLE audit_entries DROP CONSTRAINT audit_entries_actor_check",
		"DROP TABLE audit_entries",
		// The database sets the identifier, the time and the copies of the actor.
		`INSERT INTO audit_entries (id, action, outcome, actor_kind, auth_method, changed_fields)
			VALUES (gen_random_uuid(), 'user.create', 'success', 'system', 'cli', '{}')`,
		`INSERT INTO audit_entries (occurred_at, action, outcome, actor_kind, auth_method, changed_fields)
			VALUES (now() - interval '1 year', 'user.create', 'success', 'system', 'cli', '{}')`,
		`INSERT INTO audit_entries (actor_email, action, outcome, actor_kind, auth_method, changed_fields)
			VALUES ('someone@example.com', 'user.create', 'success', 'system', 'cli', '{}')`,
		`INSERT INTO audit_entries (actor_display_name, action, outcome, actor_kind, auth_method, changed_fields)
			VALUES ('Someone', 'user.create', 'success', 'system', 'cli', '{}')`,
	}
	for _, statement := range denied {
		_, err := pool.Exec(t.Context(), statement)
		var pgErr *pgconn.PgError
		// 42501 is insufficient_privilege.
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s: error = %v, want insufficient_privilege", statement, err)
		}
	}

	if after := readEntry(t, pool); !reflect.DeepEqual(after, before) {
		t.Errorf("entry changed from %+v to %+v", before, after)
	}
}
