// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeypot

import (
	"fmt"
	"strconv"
)

// sensorPorts are the ports under which the services are usually found. The
// console does not know where the sensor runs, so the entry it shows starts
// with the usual port and the operator changes it where the host needs another.
var sensorPorts = map[Service]string{
	ServiceSSH:      ":22",
	ServiceTelnet:   ":23",
	ServicePostgres: ":5432",
	ServiceLDAP:     ":389",
}

// SensorConfig returns the entry of this honeypot for the configuration file
// of the sensor: a list item of "honeypots". It holds the secret, so it is
// shown once, like the secret.
//
// Every value is quoted, so that none of them can end its line or start
// another entry. It holds neither the name nor the notes of the honeypot,
// which are inventory and have no place on the host of a sensor. The file of
// the sensor decodes it with the types of its own, and a test reads the same
// entry with the decoder of the sensor.
func (c Created) SensorConfig() string {
	return fmt.Sprintf(`- id: %s
  service: %s
  # Address and port to listen on. Ports below 1024 need CAP_NET_BIND_SERVICE.
  listen: %s
%s  secret: %s
`, strconv.Quote(c.ID), strconv.Quote(string(c.Service)), strconv.Quote(sensorPorts[c.Service]), c.serviceFields(), strconv.Quote(string(c.Secret)))
}

// serviceFields returns the lines that a service needs besides the common ones.
// A comment holds no value of the honeypot, and the value of a field is quoted.
func (c Created) serviceFields() string {
	if c.Service != ServiceSSH {
		return ""
	}
	// The name of the file has the identifier of the honeypot in it, so that the
	// entries of two honeypots in one file name two keys: a key that two
	// honeypots share would tie them together.
	return `  # The private key of the server. Create it once, without a passphrase, with
  # ssh-keygen -t ed25519 -N '' -f and the path below, and keep it: a host key
  # that changes would identify the honeypot, and one that two honeypots share
  # would tie them together. The path is relative to this file.
  host_key_file: ` + strconv.Quote("ssh_host_key_"+c.ID) + "\n"
}
