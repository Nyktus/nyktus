// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscert_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"testing"

	"nyktus.org/nyktus/sensor/internal/tlscert/tlscerttest"
)

func TestCertificate_NeverPrintsTheKey(t *testing.T) {
	t.Parallel()

	cert := tlscerttest.New(t, "db")
	held := struct{ Cert any }{*cert}
	for _, got := range []string{fmt.Sprint(*cert), fmt.Sprintf("%+v", *cert), fmt.Sprintf("%#v", *cert)} {
		if got != "[redacted]" {
			t.Errorf("printed = %q, want the placeholder", got)
		}
	}
	if got := fmt.Sprintf("%+v", held); got != "{Cert:[redacted]}" {
		t.Errorf("printed in a struct = %q, want the placeholder", got)
	}
	var log bytes.Buffer
	slog.New(slog.NewJSONHandler(&log, nil)).Info("test", "cert", *cert)
	if !bytes.Contains(log.Bytes(), []byte(`"cert":"[redacted]"`)) {
		t.Errorf("logged = %s, want the placeholder", log.Bytes())
	}
	if b, err := json.Marshal(held); err != nil || string(b) != `{"Cert":"[redacted]"}` {
		t.Errorf("json = %s, %v, want the placeholder", b, err)
	}
}

func TestServerConfig_RefusesVersionsBeforeTLS12(t *testing.T) {
	t.Parallel()

	cfg := tlscerttest.New(t, "db").ServerConfig("http/1.1")
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2", cfg.MinVersion)
	}
	if !slices.Equal(cfg.NextProtos, []string{"http/1.1"}) {
		t.Errorf("NextProtos = %v, want the protocols given", cfg.NextProtos)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("Certificates = %d, want the one given", len(cfg.Certificates))
	}
}
