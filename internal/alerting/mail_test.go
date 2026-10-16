// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package alerting

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"nyktus.org/nyktus/internal/platform/smtp"
	"nyktus.org/nyktus/internal/platform/smtp/smtptest"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const smtpPassword = "smtp-s3cr3t-password"

// render shows a mail as the golden files keep it: the headers that the
// alerting chooses, then the body.
func render(m smtp.Message) string {
	return fmt.Sprintf("To: %s\nSubject: %s\nID: %s\n\n%s", strings.Join(m.To, ", "), m.Subject, m.ID, m.Body)
}

func golden(t *testing.T, path, got string) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) //nolint:gosec // The path is a constant of the test.
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s =\n%s\nwant\n%s", path, got, want)
	}
}

// The mail reports the incident as a chat message does: no inventory, such as
// the name of a honeytoken, no personal data, such as a client address, and
// not the name of the channel.
func TestEmailMessage_MatchesTheGoldenFiles(t *testing.T) {
	t.Parallel()

	m, d := chatFixture()
	to := []string{"soc@example.com", "oncall@example.org"}
	golden(t, "testdata/email_alert.golden", render(emailMessage(m, d, to, consoleURL)))
	golden(t, "testdata/email_test.golden", render(emailMessage(message{}, Delivery{ID: d.ID}, to, consoleURL)))
}

// An alert may carry many techniques; they wrap, so that no line comes near
// the limit of SMTP and the mail is never refused for its length.
func TestEmailMessage_WrapsLongLists(t *testing.T) {
	t.Parallel()

	m, d := chatFixture()
	m.techniques = nil
	for i := range 1000 {
		m.techniques = append(m.techniques, fmt.Sprintf("T%04d.%03d", i, i%1000))
	}
	msg := emailMessage(m, d, []string{"soc@example.com"}, consoleURL)
	for line := range strings.SplitSeq(msg.Body, "\n") {
		// The link is as long as the address of the console makes it.
		if (strings.HasPrefix(line, "Techniques:") || strings.HasPrefix(line, " ")) && len(line) > mailWidth {
			t.Fatalf("line of %d characters: %q", len(line), line)
		}
	}
	if !strings.Contains(msg.Body, "T0999.999\n") || !strings.Contains(msg.Body, "Techniques:  T0000.000, T0001.001,") {
		t.Errorf("body = %s", msg.Body)
	}
	if got := wrapList([]string{"T1078"}, mailLabelWidth, mailWidth); got != "T1078" {
		t.Errorf("wrapList(one) = %q", got)
	}
}

// mailServer starts an SMTP server that requires the password smtpPassword
// and answers as respond chooses, and returns a client of it.
func mailServer(t *testing.T, respond func(verb, arg string) string) (*smtptest.Server, *smtp.Client) {
	t.Helper()
	s := smtptest.New(t, smtptest.Options{
		Auth: &smtptest.Credentials{Username: "nyktus", Password: smtpPassword}, CertHosts: []string{"127.0.0.1"},
		Respond: respond,
	})
	return s, smtp.New(smtp.Options{
		Host: s.Host, Port: s.Port, TLS: smtp.TLSStartTLS, Username: "nyktus", Password: smtpPassword,
		From: "nyktus@example.com", HeloName: "worker.example.com", RootCAs: s.RootCAs,
	})
}

func (f deliveryFixture) mailDeliverer(mail *smtp.Client) *Deliverer {
	return NewDeliverer(DelivererOptions{
		Logger: slog.New(slog.NewJSONHandler(f.logs, nil)), DB: f.worker, Keys: f.keys, Client: http.DefaultClient,
		ConsoleURL: consoleURL, Mail: mail,
	})
}

func emailSpec(name string, to ...string) Spec {
	return Spec{Name: name, Type: TypeEmail, Enabled: true, Recipients: to}
}

func TestProcess_DeliversTheAlertByMail(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	s, mail := mailServer(t, nil)
	c := f.channel(t, emailSpec("SOC", "soc@example.com", "oncall@example.org"))
	alertID := f.alert(t)
	d := f.mailDeliverer(mail)

	if !process(t, d) {
		t.Fatal("no delivery was due")
	}
	if process(t, d) {
		t.Fatal("a second delivery was due")
	}
	got := f.delivery(t, alertID, c.ID)
	msgs := s.Messages()
	if len(msgs) != 1 {
		t.Fatalf("messages = %d, want 1", len(msgs))
	}
	data := string(msgs[0].Data)
	if !slices.Equal(msgs[0].To, []string{"soc@example.com", "oncall@example.org"}) || !msgs[0].TLS ||
		!strings.Contains(data, "Message-ID: <"+got.ID+"@example.com>\r\n") ||
		!strings.Contains(data, "Subject: Nyktus: incident opened (medium)\r\n") ||
		!strings.Contains(data, consoleURL+"/incidents/"+alertID+"\r\n") {
		t.Errorf("message to %v over TLS %v:\n%s", msgs[0].To, msgs[0].TLS, data)
	}
	if got.Status != StatusDelivered || got.Attempts != 1 || got.DeliveredAt == nil || got.LastStatusCode != nil ||
		got.LastError != nil || got.ChannelType != TypeEmail {
		t.Errorf("delivery = %+v", got)
	}
	if !strings.Contains(f.logs.String(), `"msg":"alerting: alert delivered"`) {
		t.Errorf("log = %s", f.logs)
	}
}

// Every enabled channel receives the alert once, also when two workers look
// for deliveries at the same time: a worker that sends holds its delivery.
func TestProcess_MailReachesEveryChannelOnceWithTwoWorkers(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	s, mail := mailServer(t, func(verb, _ string) string {
		if verb == "MESSAGE" {
			arrived <- struct{}{}
			<-release
		}
		return ""
	})
	a := f.channel(t, emailSpec("a", "a@example.com"))
	b := f.channel(t, emailSpec("b", "b@example.com"))
	f.channel(t, Spec{Name: "c disabled", Type: TypeEmail, Recipients: []string{"c@example.com"}})
	alertID := f.alert(t)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			_, err := f.mailDeliverer(mail).Process(t.Context(), func() {})
			errs <- err
		})
	}
	// Both deliveries are being sent, one by each worker; a third worker
	// finds nothing.
	<-arrived
	<-arrived
	if process(t, f.mailDeliverer(mail)) {
		t.Error("a third worker took a delivery while both were sent")
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var to []string
	for _, m := range s.Messages() {
		to = append(to, m.To...)
	}
	if !sameElements(to, []string{"a@example.com", "b@example.com"}) {
		t.Errorf("recipients = %v, want each enabled channel once", to)
	}
	for _, c := range []Channel{a, b} {
		if got := f.delivery(t, alertID, c.ID); got.Status != StatusDelivered || got.Attempts != 1 {
			t.Errorf("delivery to %s = %+v", c.Name, got)
		}
	}
}

func sameElements(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

// A server that asks to try again later is tried again after the backoff, up
// to MaxAttempts times; then the delivery is dead. Time passes by moving the
// stored times.
func TestProcess_TemporaryRefusalOfMailRetriesThenDies(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	s, mail := mailServer(t, func(verb, _ string) string {
		if verb == "MAIL" {
			return "451 4.3.0 try again later"
		}
		return ""
	})
	c := f.channel(t, emailSpec("SOC", "soc@example.com"))
	alertID := f.alert(t)
	d := f.mailDeliverer(mail)

	for n := 1; n <= MaxAttempts; n++ {
		if !process(t, d) {
			t.Fatalf("attempt %d was not due", n)
		}
		got := f.delivery(t, alertID, c.ID)
		if got.Attempts != n || got.LastError == nil || *got.LastError != FailureSMTPStatus || got.LastStatusCode == nil ||
			*got.LastStatusCode != 451 {
			t.Fatalf("after attempt %d: %+v", n, got)
		}
		if n < MaxAttempts {
			if got.Status != StatusPending {
				t.Fatalf("after attempt %d: status %s", n, got.Status)
			}
			if wait := f.waitAfterLastAttempt(t, got.ID); wait != Backoff(n) {
				t.Errorf("wait after attempt %d = %v, want %v", n, wait, Backoff(n))
			}
			if process(t, d) {
				t.Fatalf("attempt %d+1 was due before its backoff", n)
			}
			f.due(t)
		}
	}
	if got := f.delivery(t, alertID, c.ID); got.Status != StatusDead || len(s.Messages()) != 0 {
		t.Errorf("after %d attempts: %+v, %d messages", MaxAttempts, got, len(s.Messages()))
	}
	f.due(t)
	if process(t, d) {
		t.Error("a dead delivery was attempted again")
	}
}

func TestProcess_FinalOutcomesOfMail(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		respond func(verb, arg string) string
		// noServer sends without an SMTP server.
		noServer bool
		status   Status
		failure  Failure
		code     int
	}{
		{"refused recipient", func(verb, arg string) string {
			if verb == "RCPT" && strings.Contains(arg, "gone@example.com") {
				return "550 5.1.1 no such user"
			}
			return ""
		}, false, StatusDead, FailureSMTPStatus, 550},
		{"rejected message", func(verb, _ string) string {
			if verb == "MESSAGE" {
				return "554 5.7.1 rejected"
			}
			return ""
		}, false, StatusDead, FailureSMTPStatus, 554},
		{"wrong password", func(verb, _ string) string {
			if verb == "AUTH" {
				return "535 5.7.8 authentication failed"
			}
			return ""
		}, false, StatusDead, FailureSMTPStatus, 535},
		{"no SMTP server", nil, true, StatusDead, FailureNotConfigured, 0},
		{"hangup", func(verb, _ string) string {
			if verb == "MESSAGE" {
				return smtptest.Hangup
			}
			return ""
		}, false, StatusPending, FailureNetwork, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newDeliveryFixture(t)
			s, mail := mailServer(t, tt.respond)
			if tt.noServer {
				mail = nil
			}
			c := f.channel(t, emailSpec("SOC", "soc@example.com", "gone@example.com"))
			alertID := f.alert(t)
			process(t, f.mailDeliverer(mail))

			got := f.delivery(t, alertID, c.ID)
			if got.Status != tt.status || got.Attempts != 1 || got.LastError == nil || *got.LastError != tt.failure {
				t.Fatalf("delivery = %+v", got)
			}
			if (tt.code == 0) != (got.LastStatusCode == nil) || (tt.code != 0 && *got.LastStatusCode != tt.code) {
				t.Errorf("status code = %v, want %d", got.LastStatusCode, tt.code)
			}
			if len(s.Messages()) != 0 {
				t.Errorf("messages = %d, want none", len(s.Messages()))
			}
			// The password of the SMTP server never reaches the log, also
			// when the authentication fails.
			if logs := f.logs.String(); strings.Contains(logs, smtpPassword) || !strings.Contains(logs, `"failure":"`+string(tt.failure)+`"`) {
				t.Errorf("log = %s", logs)
			}
		})
	}
}

// A test of a channel of the type email sends a test message once, also
// while the channel is disabled.
func TestProcess_TestOfAnEmailChannel(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	s, mail := mailServer(t, nil)
	c := f.channel(t, Spec{Name: "SOC", Type: TypeEmail, Recipients: []string{"soc@example.com"}})
	test, err := RequestTest(t.Context(), f.console, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	process(t, f.mailDeliverer(mail))

	msgs := s.Messages()
	if len(msgs) != 1 || !strings.Contains(string(msgs[0].Data), "Subject: Nyktus: test message\r\n") ||
		!strings.Contains(string(msgs[0].Data), "Message-ID: <"+test.ID+"@example.com>\r\n") {
		t.Fatalf("messages = %+v", msgs)
	}
	if got, err := GetDelivery(t.Context(), f.owner, test.ID); err != nil || got.Status != StatusDelivered {
		t.Errorf("test = %+v, %v", got, err)
	}
}

func TestClassifyMail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err       error
		failure   Failure
		permanent bool
	}{
		{&smtp.ReplyError{Command: "RCPT", Code: 452}, FailureSMTPStatus, false},
		{&smtp.ReplyError{Command: "RCPT", Code: 550}, FailureSMTPStatus, true},
		{smtp.ErrInvalidAddress, FailureInvalidChannel, true},
		{smtp.ErrInvalidMessage, FailureInvalidChannel, true},
		{smtp.ErrNoAuth, FailureNotConfigured, true},
		{fmt.Errorf("smtp: %w", smtp.ErrNoSTARTTLS), FailureTLS, false},
		{fmt.Errorf("smtp: EHLO: %w", timeoutError{}), FailureTimeout, false},
		{errors.New("connection reset"), FailureNetwork, false},
	}
	for _, tt := range tests {
		o := classifyMail(tt.err)
		if o.delivered || o.failure != tt.failure || o.permanent != tt.permanent {
			t.Errorf("classifyMail(%v) = %+v, want %s, permanent %v", tt.err, o, tt.failure, tt.permanent)
		}
	}
	if o := classifyMail(nil); !o.delivered {
		t.Errorf("classifyMail(nil) = %+v", o)
	}
}
