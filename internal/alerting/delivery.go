// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package alerting

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/platform/db"
)

// Status is the state of a delivery.
type Status string

// States of a delivery.
const (
	// StatusPending waits for its next attempt.
	StatusPending Status = "pending"
	// StatusDelivered was accepted by the receiver.
	StatusDelivered Status = "delivered"
	// StatusDead failed for the last time; an administrator can retry it.
	StatusDead Status = "dead"
	// StatusCanceled was not delivered, because its channel was disabled or
	// deleted first.
	StatusCanceled Status = "canceled"
)

// Statuses lists every state, in the order of the documentation.
var Statuses = []Status{StatusPending, StatusDelivered, StatusDead, StatusCanceled}

// Failure is the class of a failed attempt. Responses and network errors are
// never stored: they may hold the URL of the channel.
type Failure string

// Classes of failed attempts.
const (
	// FailureHTTPStatus means that the receiver answered with a status other
	// than 2xx.
	FailureHTTPStatus Failure = "http_status"
	// FailureRedirect means that the receiver answered with a redirect, which
	// is never followed.
	FailureRedirect Failure = "redirect"
	FailureTimeout  Failure = "timeout"
	FailureNetwork  Failure = "network"
	FailureTLS      Failure = "tls"
	// FailureBlocked means that the target resolved to an address that is not
	// allowed.
	FailureBlocked Failure = "blocked"
	// FailureInvalidChannel means that the channel cannot be sent to, for
	// example because its secret cannot be decrypted.
	FailureInvalidChannel Failure = "invalid_channel"
)

// Failures lists every class of failure.
var Failures = []Failure{
	FailureHTTPStatus, FailureRedirect, FailureTimeout, FailureNetwork, FailureTLS, FailureBlocked, FailureInvalidChannel,
}

// Limits of the retries.
const (
	// MaxAttempts bounds the attempts of the delivery of an alert. With the
	// backoff below, the last one comes about three hours after the first.
	MaxAttempts = 10
	// firstBackoff is the wait after the first failed attempt. It doubles
	// with every further one.
	firstBackoff = 30 * time.Second
	// MaxBackoff bounds the wait between two attempts, also the wait that a
	// receiver asks for with Retry-After.
	MaxBackoff = time.Hour
)

// Backoff returns the wait after the failed attempt number attempts, counted
// from 1.
func Backoff(attempts int) time.Duration {
	d := firstBackoff
	for i := 1; i < attempts && d < MaxBackoff; i++ {
		d *= 2
	}
	return min(d, MaxBackoff)
}

// Delivery describes the delivery of an alert to a channel, or a test of a
// channel.
type Delivery struct {
	ID string
	// AlertID is the incident of the alert, or nil for a test.
	AlertID     *string
	ChannelID   string
	ChannelType Type
	ChannelName string
	Status      Status
	Attempts    int
	// NotBefore is when the next attempt is due, while the delivery is
	// pending.
	NotBefore      time.Time
	LastAttemptAt  *time.Time
	LastStatusCode *int
	LastError      *Failure
	LastDurationMs *int
	DeliveredAt    *time.Time
	CreatedAt      time.Time
}

// LogValue names the delivery by its identifiers.
func (d Delivery) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("id", d.ID), slog.String("channel_id", d.ChannelID), slog.String("channel_type", string(d.ChannelType)),
	}
	if d.AlertID != nil {
		attrs = append(attrs, slog.String("incident_id", *d.AlertID))
	}
	return slog.GroupValue(attrs...)
}

// Errors of the deliveries.
var (
	ErrDeliveryNotFound = errors.New("alert delivery not found")
	// ErrNotDead means that a delivery that is not dead was to be retried.
	ErrNotDead = errors.New("alert delivery is not dead")
	// ErrTestPending means that a test of the channel waits for the worker.
	ErrTestPending = errors.New("a test of the alert channel is pending")
)

// Enqueue creates the deliveries of the alert of the incident incidentID, one
// for every enabled channel, and returns how many. It runs in the transaction
// that raises the alert, so that an alert never exists without its
// deliveries; a channel that is enabled later does not receive it.
func Enqueue(ctx context.Context, q db.Querier, incidentID string) (int, error) {
	tag, err := q.Exec(ctx, `
INSERT INTO public.alert_deliveries (alert_id, channel_id, channel_type, channel_name)
SELECT $1, id, type, name FROM public.alert_channels WHERE enabled
ON CONFLICT (alert_id, channel_id) WHERE alert_id IS NOT NULL DO NOTHING`, incidentID)
	if err != nil {
		return 0, fmt.Errorf("enqueue deliveries of alert %s: %w", incidentID, err)
	}
	return int(tag.RowsAffected()), nil
}

const deliveryColumns = `id, alert_id, channel_id, channel_type, channel_name, status, attempts, not_before,
	last_attempt_at, last_status_code, last_error, last_duration_ms, delivered_at, created_at`

func scanDelivery(row pgx.Row) (Delivery, error) {
	var d Delivery
	err := row.Scan(&d.ID, &d.AlertID, &d.ChannelID, &d.ChannelType, &d.ChannelName, &d.Status, &d.Attempts, &d.NotBefore,
		&d.LastAttemptAt, &d.LastStatusCode, &d.LastError, &d.LastDurationMs, &d.DeliveredAt, &d.CreatedAt)
	return d, err
}

// ErrIncidentNotFound means that no incident has the identifier.
var ErrIncidentNotFound = errors.New("incident not found")

// IncidentDeliveries returns the deliveries of the alert of the incident
// incidentID, ordered by the name of their channel. An incident has at most
// one delivery per channel, so the list has no pages. It returns
// ErrIncidentNotFound if there is no such incident.
func IncidentDeliveries(ctx context.Context, q db.Querier, incidentID string) ([]Delivery, error) {
	var exists bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT FROM public.incidents WHERE id = $1)`, incidentID).Scan(&exists)
	if db.NotFound(err) || (err == nil && !exists) {
		return nil, ErrIncidentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("look up incident %s: %w", incidentID, err)
	}
	rows, err := q.Query(ctx, `
SELECT `+deliveryColumns+` FROM public.alert_deliveries
WHERE alert_id = $1
ORDER BY channel_name, id`, incidentID)
	if err != nil {
		return nil, fmt.Errorf("list deliveries of incident %s: %w", incidentID, err)
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Delivery, error) { return scanDelivery(row) })
	if err != nil {
		return nil, fmt.Errorf("list deliveries of incident %s: %w", incidentID, err)
	}
	return list, nil
}

// GetDelivery returns the delivery id.
func GetDelivery(ctx context.Context, q db.Querier, id string) (Delivery, error) {
	d, err := scanDelivery(q.QueryRow(ctx, `SELECT `+deliveryColumns+` FROM public.alert_deliveries WHERE id = $1`, id))
	if db.NotFound(err) {
		return Delivery{}, ErrDeliveryNotFound
	}
	if err != nil {
		return Delivery{}, fmt.Errorf("get alert delivery %s: %w", id, err)
	}
	return d, nil
}

// RequestTest creates a test of the channel id for the worker to send, also
// for a disabled channel, so that it can be tried before it receives alerts.
// It returns ErrNotFound if there is no such channel and ErrTestPending if a
// test of it waits already.
func RequestTest(ctx context.Context, q db.Querier, id string) (Delivery, error) {
	d, err := scanDelivery(q.QueryRow(ctx, `
INSERT INTO public.alert_deliveries (channel_id, channel_type, channel_name)
SELECT id, type, name FROM public.alert_channels WHERE id = $1
RETURNING `+deliveryColumns, id))
	switch {
	case db.NotFound(err):
		return Delivery{}, ErrNotFound
	case db.Violation(err, db.UniqueViolation) == "alert_deliveries_pending_test_key":
		return Delivery{}, ErrTestPending
	case err != nil:
		return Delivery{}, fmt.Errorf("request test of alert channel %s: %w", id, err)
	}
	return d, nil
}

// Retry makes the dead delivery id of an alert pending again, with a new count
// of attempts. It returns ErrDeliveryNotFound if there is no such delivery and
// ErrNotDead if it is not a dead delivery of an alert.
func Retry(ctx context.Context, q db.Querier, id string) (Delivery, error) {
	var retried bool
	err := q.QueryRow(ctx, `SELECT public.retry_alert_delivery($1)`, id).Scan(&retried)
	if db.NotFound(err) {
		return Delivery{}, ErrDeliveryNotFound
	}
	if err != nil {
		return Delivery{}, fmt.Errorf("retry alert delivery %s: %w", id, err)
	}
	d, err := GetDelivery(ctx, q, id)
	if err != nil {
		return Delivery{}, err
	}
	if !retried {
		return Delivery{}, ErrNotDead
	}
	return d, nil
}

// RecordTest requests a test of the channel id on behalf of actor, as
// RequestTest does, and records it in the audit log.
func RecordTest(ctx context.Context, d DB, actor audit.Actor, id string) (Delivery, error) {
	var del Delivery
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		var err error
		if del, err = RequestTest(ctx, tx, id); err != nil {
			return err
		}
		return record(ctx, tx, actor, audit.ActionAlertChannelTest, id, nil)
	})
	if err != nil {
		return Delivery{}, fmt.Errorf("test alert channel: %w", err)
	}
	return del, nil
}

// RecordRetry retries the dead delivery id on behalf of actor, as Retry does,
// and records it in the audit log.
func RecordRetry(ctx context.Context, d DB, actor audit.Actor, id string) (Delivery, error) {
	var del Delivery
	err := pgx.BeginFunc(ctx, d, func(tx pgx.Tx) error {
		var err error
		if del, err = Retry(ctx, tx, id); err != nil {
			return err
		}
		return audit.NewStore(tx).Record(ctx, audit.Entry{
			Action:   audit.ActionAlertDeliveryRetry,
			Outcome:  audit.OutcomeSuccess,
			Actor:    actor,
			Resource: audit.Resource{Type: "alert_delivery", ID: id},
		}.WithRequest(ctx))
	})
	if err != nil {
		return Delivery{}, fmt.Errorf("retry alert delivery: %w", err)
	}
	return del, nil
}
