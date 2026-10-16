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

	"nyktus.org/nyktus/internal/platform/secretbox"
	"nyktus.org/nyktus/internal/platform/smtp"
)

// DelivererOptions configures a Deliverer.
type DelivererOptions struct {
	Logger *slog.Logger
	DB     DB
	Keys   *secretbox.Keyring
	// Client sends the requests. It must be the client of the SSRF guard.
	Client Sender
	// ConsoleURL is the address of the console, to which an alert links its
	// incident.
	ConsoleURL string
	// Mail sends the mail of channels of the type email, or is nil if no SMTP
	// server is configured; their deliveries are then dead.
	Mail *smtp.Client
}

// Deliverer delivers alerts and tests to their channels, one delivery at a
// time. It implements the queue of a worker.
type Deliverer struct {
	logger     *slog.Logger
	db         DB
	keys       *secretbox.Keyring
	transports map[Type]transport
}

// transport sends the message of an attempt over one kind of channel and
// classifies the result. It keeps no error: the error of a request may name
// the target of its channel.
type transport interface {
	send(ctx context.Context, a attempt) outcome
}

// NewDeliverer returns a Deliverer. It panics on missing options, which are
// programming errors.
func NewDeliverer(o DelivererOptions) *Deliverer {
	if o.Logger == nil || o.DB == nil || o.Keys == nil || o.Client == nil || o.ConsoleURL == "" {
		panic("alerting: deliverer needs a logger, a database, keys, a client and the address of the console")
	}
	web := &httpTransport{client: o.Client, consoleURL: o.ConsoleURL}
	return &Deliverer{
		logger: o.Logger, db: o.DB, keys: o.Keys,
		transports: map[Type]transport{
			TypeWebhook: web, TypeSlack: web, TypeTeams: web,
			TypeEmail: &mailTransport{client: o.Mail, consoleURL: o.ConsoleURL},
		},
	}
}

// recordTimeout bounds recording the outcome of an attempt, which runs after
// the request, also when the worker stops meanwhile.
const recordTimeout = 5 * time.Second

// attempt is a delivery that the deliverer has claimed, with what it needs to
// send it.
type attempt struct {
	Delivery
	// number counts this attempt, from 1.
	number  int
	channel target
	message message
	// cause is why the secrets of the channel could not be decrypted.
	cause error
}

// target is where a delivery goes, with its secrets in plain text.
type target struct {
	url         Secret
	headerName  *string
	headerValue Secret
	recipients  []string
}

// Process delivers the next delivery that is due, if there is one. It claims
// the delivery in a transaction of its own that counts the attempt and sets
// the next one as if this one fails, and sends the request after the commit,
// so that no connection to the database waits for the receiver. If the
// outcome cannot be recorded, or the worker ends meanwhile, the delivery is
// due again after its backoff instead of at once: a receiver is never sent the
// same alert in a tight loop. A delivery may therefore reach its receiver more
// than once; the message carries its identifier.
//
// Canceling ctx ends the search for a delivery, but not one that was claimed:
// its request runs to its end within its timeout.
func (d *Deliverer) Process(ctx context.Context, claimed func()) (bool, error) {
	a, found, err := d.claim(ctx)
	if err != nil && found && ctx.Err() == nil {
		// A delivery that cannot be claimed waits for its backoff, so that
		// it does not hold up the deliveries behind it. A claim that a stop
		// broke off was rolled back and stays due.
		return true, d.postpone(ctx, a.Delivery, err)
	}
	if err != nil || !found {
		return found, err
	}
	claimed()
	ctx, cancel := withoutCancel(ctx)
	defer cancel()

	if a.Status == StatusCanceled || a.Status == StatusDead {
		// The claim settled it, because its channel is gone or disabled or
		// its secrets cannot be decrypted.
		d.logOutcome(ctx, a, outcome{failure: FailureInvalidChannel})
		return true, nil
	}
	o := d.send(ctx, a)
	if err := d.record(ctx, a, o); err != nil {
		return true, err
	}
	d.logOutcome(ctx, a, o)
	return true, nil
}

// withoutCancel returns a context that keeps the values and the deadline of
// ctx, but is not canceled with it.
func withoutCancel(ctx context.Context) (context.Context, context.CancelFunc) {
	detached := context.WithoutCancel(ctx)
	if deadline, ok := ctx.Deadline(); ok {
		return context.WithDeadline(detached, deadline)
	}
	return detached, func() {}
}

// claim takes the next delivery that is due and counts its attempt. A delivery
// whose channel is gone, or disabled for an alert, is canceled; one whose
// secrets cannot be decrypted is dead, because no retry mends that.
func (d *Deliverer) claim(ctx context.Context) (a attempt, found bool, err error) {
	err = pgx.BeginFunc(ctx, d.db, func(tx pgx.Tx) error {
		// SKIP LOCKED lets concurrent workers take different deliveries
		// instead of waiting for each other.
		a.Delivery, err = scanDelivery(tx.QueryRow(ctx, `
SELECT `+deliveryColumns+` FROM public.alert_deliveries
WHERE status = 'pending' AND not_before <= statement_timestamp()
ORDER BY not_before
LIMIT 1
FOR UPDATE SKIP LOCKED`))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("take alert delivery: %w", err)
		}
		found = true
		a.number = a.Attempts + 1

		ch, ok, err := d.loadChannel(ctx, tx, a.ChannelID, a.AlertID == nil)
		switch {
		case err != nil:
			return err
		case !ok:
			a.Status = StatusCanceled
			return settle(ctx, tx, a.ID, StatusCanceled, nil)
		}
		a.channel, err = d.open(ctx, tx, a.ChannelID, ch)
		var unreadable *unreadableError
		switch {
		case errors.As(err, &unreadable):
			// No retry mends a secret that does not decrypt.
			a.Status, a.cause = StatusDead, unreadable.err
			return settle(ctx, tx, a.ID, StatusDead, new(FailureInvalidChannel))
		case err != nil:
			return err
		}
		a.ChannelType = ch.typ
		if a.AlertID != nil {
			if a.message, err = loadAlert(ctx, tx, *a.AlertID); err != nil {
				return err
			}
		}
		// The attempt counts as failed until its outcome is recorded.
		_, err = tx.Exec(ctx, `
UPDATE public.alert_deliveries
SET attempts = $2, last_attempt_at = clock_timestamp(), not_before = clock_timestamp() + $3::interval,
	last_status_code = NULL, last_error = NULL, last_duration_ms = NULL
WHERE id = $1`, a.ID, a.number, Backoff(a.number))
		if err != nil {
			return fmt.Errorf("claim alert delivery %s: %w", a.ID, err)
		}
		return nil
	})
	if err != nil {
		return a, found, err
	}
	return a, found, nil
}

// postpone moves the delivery d, which could not be claimed, to its next
// attempt in a transaction of its own, without counting an attempt: the
// failure lies with the worker or the database, not the receiver.
func (d *Deliverer) postpone(ctx context.Context, del Delivery, cause error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	_, err := d.db.Exec(ctx, `
UPDATE public.alert_deliveries SET not_before = clock_timestamp() + $2::interval
WHERE id = $1 AND status = 'pending'`, del.ID, Backoff(del.Attempts+1))
	if err != nil {
		return fmt.Errorf("claim alert delivery %s: %w; postpone it: %w", del.ID, cause, err)
	}
	return fmt.Errorf("claim alert delivery %s, postponed: %w", del.ID, cause)
}

// storedChannel is a channel as the worker reads it, with its sealed secrets.
type storedChannel struct {
	typ         Type
	headerName  *string
	recipients  []string
	url         []byte
	headerValue []byte
}

// loadChannel reads the channel id with its sealed secrets, if its type has
// any. It reports false if the channel is gone, or disabled unless the
// delivery is a test, which may try a channel before it is enabled. It locks
// the secrets until the end of the claim, so that encrypting them again with a
// new key never overwrites secrets that an administrator replaced meanwhile; a
// replacement waits for the claim, or the claim reads the replacement.
func (d *Deliverer) loadChannel(ctx context.Context, tx pgx.Tx, id string, test bool) (storedChannel, bool, error) {
	var (
		c       storedChannel
		enabled bool
	)
	err := tx.QueryRow(ctx, `SELECT type, enabled, header_name, recipients FROM public.alert_channels WHERE id = $1`, id).
		Scan(&c.typ, &enabled, &c.headerName, &c.recipients)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedChannel{}, false, nil
	}
	if err != nil {
		return storedChannel{}, false, fmt.Errorf("load alert channel %s: %w", id, err)
	}
	if c.typ == TypeEmail {
		return c, enabled || test, nil
	}
	err = tx.QueryRow(ctx, `
SELECT url, header_value FROM public.alert_channel_secrets WHERE channel_id = $1
FOR NO KEY UPDATE`, id).Scan(&c.url, &c.headerValue)
	if errors.Is(err, pgx.ErrNoRows) {
		// The channel was deleted after it was read.
		return storedChannel{}, false, nil
	}
	if err != nil {
		return storedChannel{}, false, fmt.Errorf("load secrets of alert channel %s: %w", id, err)
	}
	return c, enabled || test, nil
}

// unreadableError means that the secrets of a channel cannot be decrypted, for
// example because their key was removed.
type unreadableError struct{ err error }

func (e *unreadableError) Error() string { return e.err.Error() }

func (e *unreadableError) Unwrap() error { return e.err }

// open decrypts the secrets of the channel id and encrypts them again with the
// current key if another one sealed them, so that an old key can be retired
// once every channel has delivered. It returns an *unreadableError if they do
// not decrypt. A channel of the type email has no secrets.
func (d *Deliverer) open(ctx context.Context, tx pgx.Tx, id string, c storedChannel) (target, error) {
	if c.typ == TypeEmail {
		return target{recipients: c.recipients}, nil
	}
	plainURL, err := d.keys.Open(c.url, associatedData(purposeURL, id))
	if err != nil {
		return target{}, &unreadableError{fmt.Errorf("decrypt URL of alert channel %s: %w", id, err)}
	}
	t := target{url: Secret(plainURL), headerName: c.headerName}
	if c.headerName != nil {
		if c.headerValue == nil {
			return target{}, &unreadableError{fmt.Errorf("alert channel %s has a header without a value", id)}
		}
		plainHeader, err := d.keys.Open(c.headerValue, associatedData(purposeHeaderValue, id))
		if err != nil {
			return target{}, &unreadableError{fmt.Errorf("decrypt header of alert channel %s: %w", id, err)}
		}
		t.headerValue = Secret(plainHeader)
	}
	if !d.keys.NeedsReseal(c.url) && (c.headerValue == nil || !d.keys.NeedsReseal(c.headerValue)) {
		return t, nil
	}
	s := Store{db: tx, keys: d.keys}
	var h *Header
	if t.headerName != nil {
		h = &Header{Name: *t.headerName, Value: t.headerValue}
	}
	sealedURL, sealedHeader, err := s.seal(id, &t.url, h)
	if err != nil {
		return target{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE public.alert_channel_secrets SET url = $2, header_value = $3 WHERE channel_id = $1`,
		id, sealedURL, sealedHeader); err != nil {
		return target{}, fmt.Errorf("encrypt secrets of alert channel %s again: %w", id, err)
	}
	return t, nil
}

// settle ends the delivery id with status, without an attempt.
func settle(ctx context.Context, tx pgx.Tx, id string, status Status, failure *Failure) error {
	_, err := tx.Exec(ctx, `UPDATE public.alert_deliveries SET status = $2, last_error = $3,
	attempts = CASE WHEN $3::text IS NULL THEN attempts ELSE attempts + 1 END,
	last_attempt_at = CASE WHEN $3::text IS NULL THEN last_attempt_at ELSE clock_timestamp() END,
	last_status_code = CASE WHEN $3::text IS NULL THEN last_status_code END,
	last_duration_ms = CASE WHEN $3::text IS NULL THEN last_duration_ms END
WHERE id = $1`, id, status, failure)
	if err != nil {
		return fmt.Errorf("settle alert delivery %s: %w", id, err)
	}
	return nil
}

// send sends the message of a over the transport of its channel.
func (d *Deliverer) send(ctx context.Context, a attempt) outcome {
	t, ok := d.transports[a.ChannelType]
	if !ok {
		return outcome{permanent: true, failure: FailureInvalidChannel}
	}
	return t.send(ctx, a)
}

// outcome is how an attempt ended.
type outcome struct {
	delivered bool
	// permanent means that no retry can succeed.
	permanent  bool
	failure    Failure
	statusCode *int
	retryAfter time.Duration
	duration   time.Duration
}

// next returns the status of a delivery after its attempt number with outcome
// o, and the wait until the next attempt if it stays pending. A test is
// attempted once.
func next(number int, test bool, o outcome) (Status, time.Duration) {
	switch {
	case o.delivered:
		return StatusDelivered, 0
	case o.permanent || test || number >= MaxAttempts:
		return StatusDead, 0
	}
	return StatusPending, max(Backoff(number), o.retryAfter)
}

// record records the outcome of the attempt a.
func (d *Deliverer) record(ctx context.Context, a attempt, o outcome) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()

	status, wait := next(a.number, a.AlertID == nil, o)
	var failure *Failure
	if !o.delivered {
		failure = &o.failure
	}
	tag, err := d.db.Exec(ctx, `
UPDATE public.alert_deliveries
SET status = $2,
	not_before = CASE WHEN $2 = 'pending' THEN last_attempt_at + $3::interval ELSE not_before END,
	delivered_at = CASE WHEN $2 = 'delivered' THEN clock_timestamp() END,
	last_status_code = $4, last_error = $5, last_duration_ms = $6
WHERE id = $1 AND status = 'pending' AND attempts = $7`,
		a.ID, status, wait, o.statusCode, failure, o.duration.Milliseconds(), a.number)
	if err != nil {
		return fmt.Errorf("record attempt %d of alert delivery %s: %w", a.number, a.ID, err)
	}
	if tag.RowsAffected() == 0 {
		// Another attempt was claimed or the delivery was settled
		// meanwhile; the later state stands.
		d.logger.WarnContext(ctx, "alerting: attempt not recorded", slog.Any("delivery", a.Delivery), slog.Int("attempt", a.number))
	}
	return nil
}

// logOutcome logs how the attempt a ended. It names the delivery, never its
// URL.
func (d *Deliverer) logOutcome(ctx context.Context, a attempt, o outcome) {
	attrs := []any{slog.Any("delivery", a.Delivery), slog.Int("attempt", a.number)}
	if o.statusCode != nil {
		attrs = append(attrs, slog.Int("status_code", *o.statusCode))
	}
	status, wait := next(a.number, a.AlertID == nil, o)
	switch {
	case a.Status == StatusCanceled:
		d.logger.InfoContext(ctx, "alerting: delivery canceled", attrs...)
	case a.Status == StatusDead:
		d.logger.ErrorContext(ctx, "alerting: delivery dead",
			append(attrs, slog.String("failure", string(FailureInvalidChannel)), slog.Any("error", a.cause))...)
	case status == StatusDelivered:
		d.logger.InfoContext(ctx, "alerting: alert delivered", append(attrs, slog.Duration("duration", o.duration))...)
	case status == StatusDead:
		d.logger.ErrorContext(ctx, "alerting: delivery dead", append(attrs, slog.String("failure", string(o.failure)))...)
	default:
		d.logger.WarnContext(ctx, "alerting: delivery failed",
			append(attrs, slog.String("failure", string(o.failure)), slog.Duration("retry_in", wait))...)
	}
}
