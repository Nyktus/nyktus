// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"maps"
	"strings"
	"testing"
)

// workerEnv is the least that a process with only the worker needs.
func workerEnv() map[string]string {
	return map[string]string{
		"NYKTUS_WORKER_DATABASE_URL": "postgres://worker@db/nyktus",
		"NYKTUS_CONSOLE_URL":         "https://nyktus.example.com",
		"NYKTUS_ENCRYPTION_KEYS":     testKeys,
	}
}

func TestLoadServe_WorkerDefaults(t *testing.T) {
	t.Parallel()

	env := workerEnv()
	delete(env, "NYKTUS_WORKER_DATABASE_URL")
	env["NYKTUS_WORKER_DATABASE_URL_FILE"] = "/run/secrets/worker"
	src := fakeSource{env: env, files: map[string]string{"/run/secrets/worker": "postgres://worker@db/nyktus\n"}}
	cfg, err := LoadServe(src.source(), []Role{RoleWorker})
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}
	want := Worker{
		DatabaseURL: "postgres://worker@db/nyktus", Concurrency: 4, DeliveryConcurrency: 4,
		ConsoleURL: "https://nyktus.example.com",
	}
	if cfg.Worker != want {
		t.Errorf("Worker = %+v, want %+v", cfg.Worker, want)
	}
	// The worker decrypts the secrets of alert channels.
	if cfg.EncryptionKeys == nil || cfg.EncryptionKeys.CurrentKeyID() != 1 {
		t.Errorf("EncryptionKeys = %v, want the keyring", cfg.EncryptionKeys)
	}
	if cfg.Has(RoleConsole) || cfg.Console.DatabaseURL != "" {
		t.Error("the worker alone read the settings of the console")
	}
}

// A process that runs the console and the worker reads the address of the
// console once.
func TestLoadServe_WorkerSharesTheConsoleURL(t *testing.T) {
	t.Parallel()

	env := workerEnv()
	env["NYKTUS_CONSOLE_DATABASE_URL"] = "postgres://console@db/nyktus"
	env["NYKTUS_TRIGGER_URL"] = "https://t.example.net"
	cfg, err := LoadServe(fakeSource{env: env}.source(), []Role{RoleConsole, RoleWorker})
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}
	if cfg.Worker.ConsoleURL != cfg.Console.URL || cfg.Console.URL != "https://nyktus.example.com" {
		t.Errorf("console URL of the worker %q, of the console %q", cfg.Worker.ConsoleURL, cfg.Console.URL)
	}

	delete(env, "NYKTUS_CONSOLE_URL")
	_, err = LoadServe(fakeSource{env: env}.source(), []Role{RoleConsole, RoleWorker})
	if err == nil || strings.Count(err.Error(), "NYKTUS_CONSOLE_URL") != 1 {
		t.Errorf("LoadServe() without the console URL error = %v, want it named once", err)
	}
}

func TestLoadServe_WorkerConcurrency(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"NYKTUS_WORKER_CONCURRENCY", "NYKTUS_WORKER_DELIVERY_CONCURRENCY"} {
		for value, want := range map[string]string{"1": "", "32": "", "0": name, "33": name, "x": name} {
			env := workerEnv()
			env[name] = value
			_, err := LoadServe(fakeSource{env: env}.source(), []Role{RoleWorker})
			switch {
			case want == "" && err != nil:
				t.Errorf("%s=%s: error = %v, want nil", name, value, err)
			case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
				t.Errorf("%s=%s: error = %v, want it to name %s", name, value, err, want)
			}
		}
	}
}

func TestLoadServe_WorkerReportsAllProblems(t *testing.T) {
	t.Parallel()

	src := fakeSource{env: map[string]string{"NYKTUS_WORKER_CONCURRENCY": "100", "NYKTUS_ALERTING_ALLOWED_NETWORKS": "x"}}
	_, err := LoadServe(src.source(), []Role{RoleWorker})
	if err == nil {
		t.Fatal("LoadServe() returned no error")
	}
	for _, want := range []string{
		"NYKTUS_WORKER_DATABASE_URL", "NYKTUS_WORKER_CONCURRENCY", "NYKTUS_ENCRYPTION_KEYS", "NYKTUS_CONSOLE_URL",
		"NYKTUS_ALERTING_ALLOWED_NETWORKS",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
	for _, unwanted := range []string{"NYKTUS_CONSOLE_DATABASE", "NYKTUS_TRIGGER", "NYKTUS_DNS"} {
		if strings.Contains(err.Error(), unwanted) {
			t.Errorf("error mentions %s, a setting of another role: %v", unwanted, err)
		}
	}
}

func TestLoadServe_WorkerAllowedNetworks(t *testing.T) {
	t.Parallel()

	env := maps.Clone(workerEnv())
	env["NYKTUS_ALERTING_ALLOWED_NETWORKS"] = "10.20.0.0/16"
	cfg, err := LoadServe(fakeSource{env: env}.source(), []Role{RoleWorker})
	if err != nil || len(cfg.AlertingAllowedNetworks) != 1 || cfg.AlertingAllowedNetworks[0].String() != "10.20.0.0/16" {
		t.Errorf("AlertingAllowedNetworks = %v, %v", cfg.AlertingAllowedNetworks, err)
	}
}
