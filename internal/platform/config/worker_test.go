// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
)

func TestLoadServe_WorkerDefaults(t *testing.T) {
	t.Parallel()

	src := fakeSource{
		env:   map[string]string{"NYKTUS_WORKER_DATABASE_URL_FILE": "/run/secrets/worker"},
		files: map[string]string{"/run/secrets/worker": "postgres://worker@db/nyktus\n"},
	}
	cfg, err := LoadServe(src.source(), []Role{RoleWorker})
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}
	if want := (Worker{DatabaseURL: "postgres://worker@db/nyktus", Concurrency: 4}); cfg.Worker != want {
		t.Errorf("Worker = %+v, want %+v", cfg.Worker, want)
	}
	if cfg.Has(RoleConsole) || cfg.EncryptionKeys != nil {
		t.Error("the worker alone read the settings of the console")
	}
}

func TestLoadServe_WorkerConcurrency(t *testing.T) {
	t.Parallel()

	for value, want := range map[string]string{"1": "", "32": "", "0": "NYKTUS_WORKER_CONCURRENCY", "33": "NYKTUS_WORKER_CONCURRENCY", "x": "NYKTUS_WORKER_CONCURRENCY"} {
		env := map[string]string{"NYKTUS_WORKER_DATABASE_URL": "postgres://worker@db/nyktus", "NYKTUS_WORKER_CONCURRENCY": value}
		_, err := LoadServe(fakeSource{env: env}.source(), []Role{RoleWorker})
		switch {
		case want == "" && err != nil:
			t.Errorf("NYKTUS_WORKER_CONCURRENCY=%s: error = %v, want nil", value, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("NYKTUS_WORKER_CONCURRENCY=%s: error = %v, want it to name %s", value, err, want)
		}
	}
}

func TestLoadServe_WorkerReportsAllProblems(t *testing.T) {
	t.Parallel()

	src := fakeSource{env: map[string]string{"NYKTUS_WORKER_CONCURRENCY": "100"}}
	_, err := LoadServe(src.source(), []Role{RoleWorker})
	if err == nil {
		t.Fatal("LoadServe() returned no error")
	}
	for _, want := range []string{"NYKTUS_WORKER_DATABASE_URL", "NYKTUS_WORKER_CONCURRENCY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
	for _, unwanted := range []string{"NYKTUS_CONSOLE", "NYKTUS_ENCRYPTION_KEYS", "NYKTUS_TRIGGER", "NYKTUS_DNS"} {
		if strings.Contains(err.Error(), unwanted) {
			t.Errorf("error mentions %s, a setting of another role: %v", unwanted, err)
		}
	}
}
