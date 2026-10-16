// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
)

// PayloadVersion is the version of the JSON that a webhook receives. It
// changes only when a member changes its meaning or disappears; new members
// may appear within a version.
const PayloadVersion = 1

// message is what an alert reports: the incident as it was when it opened.
// It holds no inventory, such as the name or notes of a honeytoken, and no
// personal data, such as the client address of an event, because it leaves
// the installation, often to a service of a third party. Receivers fetch the
// details through the API.
type message struct {
	incidentID   string
	severity     string
	techniques   []string
	resourceType string
	resourceID   string
	openedAt     time.Time
	firstEventAt time.Time
}

// loadAlert reads what the alert of the incident incidentID reports. Severity
// and techniques are those of the alert, which keeps them as they were when
// the incident opened.
func loadAlert(ctx context.Context, tx pgx.Tx, incidentID string) (message, error) {
	m := message{incidentID: incidentID}
	err := tx.QueryRow(ctx, `
SELECT a.severity, a.techniques, i.resource_type, i.resource_id, i.opened_at, i.first_event_at
FROM public.alerts AS a
JOIN public.incidents AS i ON i.id = a.incident_id
WHERE a.incident_id = $1`, incidentID).Scan(&m.severity, &m.techniques, &m.resourceType, &m.resourceID, &m.openedAt,
		&m.firstEventAt)
	if err != nil {
		return message{}, fmt.Errorf("load alert %s: %w", incidentID, err)
	}
	if m.techniques == nil {
		m.techniques = []string{}
	}
	return m, nil
}

// webhookPayload is the JSON that a webhook receives.
type webhookPayload struct {
	Version int `json:"version"`
	// Type is "alert" or "test".
	Type string `json:"type"`
	// DeliveryID identifies the delivery. A receiver can recognize a delivery
	// that reaches it twice by it.
	DeliveryID string           `json:"delivery_id"`
	Incident   *webhookIncident `json:"incident,omitempty"`
}

type webhookIncident struct {
	ID           string    `json:"id"`
	URL          string    `json:"url"`
	Severity     string    `json:"severity"`
	Techniques   []string  `json:"techniques"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	OpenedAt     time.Time `json:"opened_at"`
	FirstEventAt time.Time `json:"first_event_at"`
}

// errUnsupportedType means that a channel has a type whose format the
// deliverer does not know.
var errUnsupportedType = errors.New("alerting: unsupported channel type")

// incidentURL returns the address of the incident id in the console.
func incidentURL(consoleURL, id string) string {
	return consoleURL + "/incidents/" + url.PathEscape(id)
}

// format returns the body of a delivery d of the message m to a channel of
// type t, and its content type. A test has no message.
func format(t Type, m message, d Delivery, consoleURL string) ([]byte, string, error) {
	switch t {
	case TypeWebhook:
		p := webhookPayload{Version: PayloadVersion, Type: "test", DeliveryID: d.ID}
		if d.AlertID != nil {
			p.Type = "alert"
			p.Incident = &webhookIncident{
				ID: m.incidentID, URL: incidentURL(consoleURL, m.incidentID), Severity: m.severity,
				Techniques: m.techniques, ResourceType: m.resourceType, ResourceID: m.resourceID,
				OpenedAt: m.openedAt.UTC(), FirstEventAt: m.firstEventAt.UTC(),
			}
		}
		b, err := json.Marshal(p)
		return b, "application/json", err
	default:
		return nil, "", errUnsupportedType
	}
}
