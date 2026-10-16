// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/platform/smtp"
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
	case TypeSlack:
		b, err := json.Marshal(slackMessage(m, d, consoleURL))
		return b, "application/json", err
	case TypeTeams:
		b, err := json.Marshal(teamsMessage(m, d, consoleURL))
		return b, "application/json", err
	default:
		return nil, "", errUnsupportedType
	}
}

// summary is what a chat message says, as label and value. A test has none.
func summary(m message) [][2]string {
	techniques := "none"
	if len(m.techniques) > 0 {
		techniques = strings.Join(m.techniques, ", ")
	}
	return [][2]string{
		{"Severity", m.severity},
		{"Techniques", techniques},
		{"Resource", m.resourceType + " " + m.resourceID},
		{"First event", m.firstEventAt.UTC().Format(time.RFC3339)},
	}
}

const (
	alertTitle   = "Nyktus: incident opened"
	testTitle    = "Nyktus: test message"
	testText     = "This channel receives the alerts of Nyktus."
	openIncident = "Open the incident"
)

// Layout of a mail: labels are padded to the same width, and lists wrap
// before mailWidth, so that no line comes near the limit of SMTP.
const (
	mailLabelWidth = 13
	mailWidth      = 76
)

// emailMessage is the mail of a delivery d of the message m to the
// recipients to: plain text with what a chat message says. The subject names
// the severity, so that a list of mail shows it; the delivery is the
// identifier of the message. A test has no message.
func emailMessage(m message, d Delivery, to []string, consoleURL string) smtp.Message {
	msg := smtp.Message{To: to, ID: d.ID}
	if d.AlertID == nil {
		msg.Subject = testTitle
		msg.Body = testText + "\n\nDelivery " + d.ID + "\n"
		return msg
	}
	msg.Subject = alertTitle + " (" + m.severity + ")"
	var b strings.Builder
	b.WriteString("An incident opened in Nyktus.\n\n")
	for _, f := range summary(m) {
		value := f[1]
		if f[0] == "Techniques" && len(m.techniques) > 0 {
			value = wrapList(m.techniques, mailLabelWidth, mailWidth)
		}
		fmt.Fprintf(&b, "%-*s%s\n", mailLabelWidth, f[0]+":", value)
	}
	b.WriteString("\n" + openIncident + ": " + incidentURL(consoleURL, m.incidentID) + "\n\n")
	b.WriteString("Delivery " + d.ID + "\n")
	msg.Body = b.String()
	return msg
}

// wrapList joins items with commas into lines of at most width characters,
// indenting every line after the first by indent.
func wrapList(items []string, indent, width int) string {
	var b strings.Builder
	col := indent
	for i, item := range items {
		if i > 0 {
			b.WriteString(",")
			col++
			if col+1+len(item) > width {
				b.WriteString("\n" + strings.Repeat(" ", indent))
				col = indent
			} else {
				b.WriteString(" ")
				col++
			}
		}
		b.WriteString(item)
		col += len(item)
	}
	return b.String()
}

// slackEscape escapes the characters that Slack reads as markup in text.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// slackMessage is the message of an incoming webhook of Slack: a text that
// notifications show, and blocks that the channel shows. The link to the
// incident is part of the text, because a button would need an app that
// handles interactions.
func slackMessage(m message, d Delivery, consoleURL string) map[string]any {
	if d.AlertID == nil {
		return map[string]any{
			"text": testTitle,
			"blocks": []any{
				map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": "*" + testTitle + "*\n" + testText}},
			},
		}
	}
	var fields []any
	for _, f := range summary(m) {
		fields = append(fields, map[string]any{"type": "mrkdwn", "text": "*" + f[0] + "*\n" + slackEscape(f[1])})
	}
	link := "<" + slackEscape(incidentURL(consoleURL, m.incidentID)) + "|" + openIncident + ">"
	return map[string]any{
		"text": alertTitle + ": " + slackEscape(m.severity),
		"blocks": []any{
			map[string]any{"type": "header", "text": map[string]any{"type": "plain_text", "text": alertTitle}},
			map[string]any{"type": "section", "fields": fields},
			map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": link}},
			map[string]any{"type": "context", "elements": []any{
				map[string]any{"type": "mrkdwn", "text": "Delivery " + slackEscape(d.ID)},
			}},
		},
	}
}

// teamsMessage is the message of a workflow of Microsoft Teams that posts to
// a channel: an adaptive card in the envelope that the workflow expects.
func teamsMessage(m message, d Delivery, consoleURL string) map[string]any {
	body := []any{map[string]any{"type": "TextBlock", "text": alertTitle, "weight": "Bolder", "size": "Medium", "wrap": true}}
	var actions []any
	if d.AlertID == nil {
		body[0] = map[string]any{"type": "TextBlock", "text": testTitle, "weight": "Bolder", "size": "Medium", "wrap": true}
		body = append(body, map[string]any{"type": "TextBlock", "text": testText, "wrap": true})
	} else {
		var facts []any
		for _, f := range summary(m) {
			facts = append(facts, map[string]any{"title": f[0], "value": f[1]})
		}
		facts = append(facts, map[string]any{"title": "Delivery", "value": d.ID})
		body = append(body, map[string]any{"type": "FactSet", "facts": facts})
		actions = []any{map[string]any{"type": "Action.OpenUrl", "title": openIncident, "url": incidentURL(consoleURL, m.incidentID)}}
	}
	card := map[string]any{"type": "AdaptiveCard", "version": "1.4", "body": body}
	if actions != nil {
		card["actions"] = actions
	}
	return map[string]any{
		"type": "message",
		"attachments": []any{
			map[string]any{"contentType": "application/vnd.microsoft.card.adaptive", "content": card},
		},
	}
}
