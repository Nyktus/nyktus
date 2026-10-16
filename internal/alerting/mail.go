// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package alerting

import (
	"context"
	"errors"
	"time"

	"nyktus.org/nyktus/internal/platform/smtp"
)

// mailTransport sends the message as mail to the recipients of a channel of
// the type email, through the SMTP server of the operator.
type mailTransport struct {
	// client is nil if no SMTP server is configured.
	client     *smtp.Client
	consoleURL string
}

// send sends the message of a in a conversation of its own and classifies the
// result. Without an SMTP server, the delivery is dead at once: no retry
// mends the configuration of the worker.
func (t *mailTransport) send(ctx context.Context, a attempt) outcome {
	if t.client == nil {
		return outcome{permanent: true, failure: FailureNotConfigured}
	}
	start := time.Now()
	o := classifyMail(t.client.Send(ctx, emailMessage(a.message, a.Delivery, a.channel.recipients, t.consoleURL)))
	o.duration = time.Since(start)
	return o
}

// classifyMail maps the result of sending a message to an outcome. A refusal
// of the server keeps its reply code: 4xx is tried again, 5xx is final.
func classifyMail(err error) outcome {
	var reply *smtp.ReplyError
	switch {
	case err == nil:
		return outcome{delivered: true}
	case errors.As(err, &reply):
		code := reply.Code
		return outcome{permanent: !reply.Temporary(), failure: FailureSMTPStatus, statusCode: &code}
	case errors.Is(err, smtp.ErrInvalidAddress), errors.Is(err, smtp.ErrInvalidMessage):
		return outcome{permanent: true, failure: FailureInvalidChannel}
	case errors.Is(err, smtp.ErrNoAuth):
		return outcome{permanent: true, failure: FailureNotConfigured}
	case errors.Is(err, smtp.ErrNoSTARTTLS):
		// A server that offers no STARTTLS today may offer it again; until
		// then, nobody can read along.
		return outcome{failure: FailureTLS}
	default:
		return classifyConnection(err)
	}
}
