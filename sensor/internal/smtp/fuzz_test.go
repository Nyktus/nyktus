// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package smtp

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"testing"
	"unicode/utf8"

	"nyktus.org/nyktus/sensor/internal/clock/clocktest"
	"nyktus.org/nyktus/sensor/internal/conntest"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/session"
	"nyktus.org/nyktus/sensor/internal/tlscert/tlscerttest"
)

// FuzzDialog plays scripts against the dialog in plain text and, because a
// pipe of the fuzzer cannot speak TLS, against the dialog as it is once TLS is
// on, where the logins are read.
func FuzzDialog(f *testing.F) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	f.Add([]byte("EHLO a\r\nAUTH PLAIN "+b64("\x00admin\x00pw")+"\r\nQUIT\r\n"), true)
	f.Add([]byte("EHLO a\r\nAUTH LOGIN\r\n"+b64("u")+"\r\n"+b64("p")+"\r\n"), true)
	f.Add([]byte("EHLO a\r\nAUTH LOGIN "+b64("u")+"\r\n*\r\nAUTH PLAIN\r\n=\r\n"), true)
	f.Add([]byte("EHLO a\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\n.\r\nRSET\r\n"), true)
	f.Add([]byte("EHLO a\r\nSTARTTLS\r\n\x16\x03\x01\x00\x05hello"), false)
	f.Add([]byte("HELO\nhelo x\nVRFY x\n\r\n"), false)
	f.Add([]byte("AUTH PLAIN "+string(make([]byte, 3000))+"\r\n"), true)

	// One certificate for every run: the dialog never uses it, and making one
	// each time would slow the fuzzer down.
	cert := tlscerttest.New(f, "mail.example.com")
	f.Fuzz(func(t *testing.T, script []byte, encrypted bool) {
		clk := clocktest.New()
		hp := &session.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: "smtp", Secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
		sess, err := session.Start(clk, hp, netip.MustParseAddrPort("203.0.113.9:51000"), netip.MustParseAddrPort("10.0.0.5:587"))
		if err != nil {
			t.Fatal(err)
		}
		svc := New(Config{Hostname: "mail.example.com", Mode: StartTLS, Certificate: cert}, clk)
		conn := conntest.New(script)
		d := svc.newDialog(conn, sess)
		d.encrypted = encrypted
		d.run(t.Context())
		sess.End()

		rep, ok := sess.Report(0)
		if !ok {
			t.Fatal("Report() = not ok")
		}
		if _, err := json.Marshal(rep); err != nil {
			t.Fatal(err)
		}
		if len(rep.Attempts) > session.MaxAttempts {
			t.Fatalf("%d attempts", len(rep.Attempts))
		}
		if !encrypted && len(rep.Attempts) != 0 {
			t.Fatalf("attempts in clear text: %+v", rep.Attempts)
		}
		for _, a := range rep.Attempts {
			if len(a.Username) > report.MaxUsername || !utf8.ValidString(a.Username) {
				t.Fatalf("username %q", a.Username)
			}
			if a.Password != nil && (len(*a.Password) > report.MaxPassword || !utf8.ValidString(*a.Password)) {
				t.Fatalf("password %q", *a.Password)
			}
		}
		if len(rep.ClientVersion) > report.MaxClientVersion || !utf8.ValidString(rep.ClientVersion) {
			t.Fatalf("client version %q", rep.ClientVersion)
		}
	})
}
