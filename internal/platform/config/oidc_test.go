// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"fmt"
	"maps"
	"reflect"
	"strings"
	"testing"
)

func consoleEnv(extra map[string]string) map[string]string {
	env := map[string]string{
		"NYKTUS_CONSOLE_DATABASE_URL": "postgres://console@db/nyktus",
		"NYKTUS_TRIGGER_URL":          "https://t.example.com",
		"NYKTUS_CONSOLE_URL":          "https://nyktus.example.com",
		"NYKTUS_ENCRYPTION_KEYS":      testKeys,
	}
	maps.Copy(env, extra)
	return env
}

func oidcEnv(extra map[string]string) map[string]string {
	env := consoleEnv(map[string]string{
		"NYKTUS_OIDC_ISSUER":        "https://idp.example.com/realms/nyktus",
		"NYKTUS_OIDC_CLIENT_ID":     "nyktus",
		"NYKTUS_OIDC_CLIENT_SECRET": "secret",
		"NYKTUS_OIDC_VIEWER_GROUPS": "nyktus-viewers",
	})
	maps.Copy(env, extra)
	return env
}

func TestLoadServe_WithoutOIDC(t *testing.T) {
	t.Parallel()

	cfg, err := LoadServe(fakeSource{env: consoleEnv(nil)}.source(), []Role{RoleConsole})
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}
	if cfg.Console.OIDC != nil || cfg.Console.LocalLogin != LocalLoginAll {
		t.Errorf("OIDC = %+v, LocalLogin = %q; want no provider and passwords for all", cfg.Console.OIDC, cfg.Console.LocalLogin)
	}
}

func TestLoadServe_OIDC(t *testing.T) {
	t.Parallel()

	src := fakeSource{
		env: oidcEnv(map[string]string{
			"NYKTUS_OIDC_CLIENT_SECRET":      "",
			"NYKTUS_OIDC_CLIENT_SECRET_FILE": "/run/secrets/oidc",
			"NYKTUS_OIDC_SCOPES":             "openid  email profile groups email",
			"NYKTUS_OIDC_GROUPS_CLAIM":       "roles",
			"NYKTUS_OIDC_ADMIN_GROUPS":       "Nyktus Admins, ops ,,Nyktus Admins",
			"NYKTUS_OIDC_USER_GROUPS":        "analysts",
		}),
		files: map[string]string{"/run/secrets/oidc": "file secret\n"},
	}
	cfg, err := LoadServe(src.source(), []Role{RoleConsole})
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}
	want := &OIDC{
		Issuer: "https://idp.example.com/realms/nyktus", ClientID: "nyktus", ClientSecret: "file secret",
		Scopes: []string{"email", "profile", "groups"}, GroupsClaim: "roles",
		AdminGroups: []string{"Nyktus Admins", "ops"}, UserGroups: []string{"analysts"}, ViewerGroups: []string{"nyktus-viewers"},
	}
	if !reflect.DeepEqual(cfg.Console.OIDC, want) {
		t.Errorf("OIDC = %+v, want %+v", cfg.Console.OIDC, want)
	}
	if cfg.Console.LocalLogin != LocalLoginAdmins {
		t.Errorf("LocalLogin = %q, want %q by default with a provider", cfg.Console.LocalLogin, LocalLoginAdmins)
	}
	if s := fmt.Sprintf("%v %+v %#v", cfg.Console.OIDC, cfg.Console.OIDC, cfg.Console.OIDC); strings.Contains(s, "file secret") {
		t.Errorf("formatted configuration contains the client secret: %s", s)
	}
}

func TestLoadServe_LocalLoginOff(t *testing.T) {
	t.Parallel()

	cfg, err := LoadServe(fakeSource{env: oidcEnv(map[string]string{"NYKTUS_LOCAL_LOGIN": "off"})}.source(), []Role{RoleConsole})
	if err != nil || cfg.Console.LocalLogin != LocalLoginOff {
		t.Errorf("LocalLogin = %q, %v; want %q", cfg.Console.LocalLogin, err, LocalLoginOff)
	}
}

func TestLoadServe_OIDCDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := LoadServe(fakeSource{env: oidcEnv(map[string]string{"NYKTUS_LOCAL_LOGIN": "all"})}.source(), []Role{RoleConsole})
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}
	if c := cfg.Console.OIDC; !reflect.DeepEqual(c.Scopes, []string{"email", "profile"}) || c.GroupsClaim != "groups" {
		t.Errorf("scopes = %q, groups claim = %q; want email and profile in addition to openid, and groups", c.Scopes, c.GroupsClaim)
	}
	if cfg.Console.LocalLogin != LocalLoginAll {
		t.Errorf("LocalLogin = %q, want %q", cfg.Console.LocalLogin, LocalLoginAll)
	}
}

func TestLoadServe_OIDCProblems(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
		err  string
	}{
		{
			name: "settings without issuer",
			env:  consoleEnv(map[string]string{"NYKTUS_OIDC_CLIENT_ID": "nyktus", "NYKTUS_OIDC_ADMIN_GROUPS": "a"}),
			err:  "NYKTUS_OIDC_ADMIN_GROUPS is set, but NYKTUS_OIDC_ISSUER is not",
		},
		{name: "plain HTTP", env: oidcEnv(map[string]string{"NYKTUS_OIDC_ISSUER": "http://idp.example.com"}), err: "NYKTUS_OIDC_ISSUER: must start with https://"},
		{name: "no host", env: oidcEnv(map[string]string{"NYKTUS_OIDC_ISSUER": "https:///realms"}), err: "NYKTUS_OIDC_ISSUER: must name a host"},
		{name: "query", env: oidcEnv(map[string]string{"NYKTUS_OIDC_ISSUER": "https://idp.example.com?tenant=1"}), err: "NYKTUS_OIDC_ISSUER: must not contain"},
		{name: "fragment", env: oidcEnv(map[string]string{"NYKTUS_OIDC_ISSUER": "https://idp.example.com#x"}), err: "NYKTUS_OIDC_ISSUER: must not contain"},
		{name: "user information", env: oidcEnv(map[string]string{"NYKTUS_OIDC_ISSUER": "https://a:b@idp.example.com"}), err: "NYKTUS_OIDC_ISSUER: must not contain"},
		{
			name: "issuer too long",
			env:  oidcEnv(map[string]string{"NYKTUS_OIDC_ISSUER": "https://idp.example.com/" + strings.Repeat("a", 2048)}),
			err:  "NYKTUS_OIDC_ISSUER: must not be longer than 2048 characters",
		},
		{name: "no client ID", env: oidcEnv(map[string]string{"NYKTUS_OIDC_CLIENT_ID": ""}), err: "NYKTUS_OIDC_CLIENT_ID is required"},
		{name: "no client secret", env: oidcEnv(map[string]string{"NYKTUS_OIDC_CLIENT_SECRET": ""}), err: "NYKTUS_OIDC_CLIENT_SECRET or NYKTUS_OIDC_CLIENT_SECRET_FILE is required"},
		{name: "no groups", env: oidcEnv(map[string]string{"NYKTUS_OIDC_VIEWER_GROUPS": " , "}), err: "without groups, nobody can sign in"},
		{name: "invalid scope", env: oidcEnv(map[string]string{"NYKTUS_OIDC_SCOPES": `email "profile"`}), err: `NYKTUS_OIDC_SCOPES: "\"profile\"" is not a scope`},
		{name: "unknown local login", env: oidcEnv(map[string]string{"NYKTUS_LOCAL_LOGIN": "none"}), err: `NYKTUS_LOCAL_LOGIN: must be "all", "admins" or "off"`},
		{name: "off without provider", env: consoleEnv(map[string]string{"NYKTUS_LOCAL_LOGIN": "off"}), err: "NYKTUS_LOCAL_LOGIN: \"off\" requires NYKTUS_OIDC_ISSUER"},
		{name: "admins without provider", env: consoleEnv(map[string]string{"NYKTUS_LOCAL_LOGIN": "admins"}), err: "NYKTUS_LOCAL_LOGIN: \"admins\" requires NYKTUS_OIDC_ISSUER"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := LoadServe(fakeSource{env: tt.env}.source(), []Role{RoleConsole})
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Errorf("LoadServe() error = %v, want it to contain %q", err, tt.err)
			}
		})
	}
}

// Plain HTTP is allowed in development, for a provider on the same machine.
func TestLoadServe_OIDCOverHTTPInDevelopment(t *testing.T) {
	t.Parallel()

	env := oidcEnv(map[string]string{"NYKTUS_ENV": "development", "NYKTUS_OIDC_ISSUER": "http://localhost:8081/realms/dev"})
	cfg, err := LoadServe(fakeSource{env: env}.source(), []Role{RoleConsole})
	if err != nil || cfg.Console.OIDC.Issuer != "http://localhost:8081/realms/dev" {
		t.Errorf("LoadServe() = %+v, %v; want the issuer unchanged", cfg.Console.OIDC, err)
	}
}
