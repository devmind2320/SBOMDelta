package config

import (
	"strings"
	"testing"
)

func TestLoadAPIGitHubDisable(t *testing.T) {
	tests := []struct {
		name        string
		env         string
		disabled    string
		credentials bool
		wantError   string
		wantDisable bool
	}{
		{name: "default requires credentials", env: "development", wantError: "GITHUB_APP_ID is required"},
		{name: "false requires credentials", env: "development", disabled: "false", wantError: "GITHUB_APP_ID is required"},
		{name: "explicit local mode", env: "development", disabled: "true", wantDisable: true},
		{name: "production rejects local mode", env: "production", disabled: "true", credentials: true, wantError: "only allowed when APP_ENV=development"},
		{name: "staging rejects local mode", env: "staging", disabled: "true", credentials: true, wantError: "only allowed when APP_ENV=development"},
		{name: "invalid flag rejected", env: "development", disabled: "invalid", credentials: true, wantError: "GITHUB_DISABLED must be true or false"},
		{name: "production credentials still work", env: "production", credentials: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setConfigEnvironment(t)
			t.Setenv("APP_ENV", tt.env)
			t.Setenv("GITHUB_DISABLED", tt.disabled)
			if tt.credentials {
				setCredentialFixtures(t)
			}
			cfg, err := LoadAPI()
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("LoadAPI() error = %v, want %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadAPI() error = %v", err)
			}
			if cfg.GitHub.Disabled != tt.wantDisable {
				t.Fatalf("GitHub.Disabled = %v, want %v", cfg.GitHub.Disabled, tt.wantDisable)
			}
		})
	}
}

func TestLoadAPIWithGitHubDisabledSkipsUnusedCredentials(t *testing.T) {
	setConfigEnvironment(t)
	t.Setenv("GITHUB_DISABLED", "true")
	t.Setenv("GITHUB_APP_ID", "not-a-number")
	t.Setenv("GITHUB_PRIVATE_KEY_PATH", "/missing/config-test-key.pem")
	if _, err := LoadAPI(); err != nil {
		t.Fatalf("disabled integration must not read unused credentials: %v", err)
	}
}

func TestWorkerLoadRemainsStrictWithGitHubDisabled(t *testing.T) {
	setConfigEnvironment(t)
	t.Setenv("GITHUB_DISABLED", "true")
	_, err := Load()
	if err == nil {
		t.Fatal("Load() accepted a worker without GitHub credentials")
	}
	for _, requirement := range []string{"GITHUB_APP_ID", "GITHUB_PRIVATE_KEY", "GITHUB_WEBHOOK_SECRET"} {
		if !strings.Contains(err.Error(), requirement) {
			t.Errorf("Load() error = %v, missing requirement %q", err, requirement)
		}
	}

	setCredentialFixtures(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() with credentials error = %v", err)
	}
	if cfg.GitHub.Disabled {
		t.Fatal("Load() disabled GitHub integration for a worker")
	}
}

func setConfigEnvironment(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"APP_ENV":                 "development",
		"GITHUB_DISABLED":         "",
		"GITHUB_APP_ID":           "",
		"GITHUB_PRIVATE_KEY":      "",
		"GITHUB_PRIVATE_KEY_PATH": "",
		"GITHUB_WEBHOOK_SECRET":   "",
		"WORKER_CONCURRENCY":      "4",
	} {
		t.Setenv(key, value)
	}
}

func setCredentialFixtures(t *testing.T) {
	t.Helper()
	t.Setenv("GITHUB_APP_ID", "123")
	t.Setenv("GITHUB_PRIVATE_KEY", "configuration-test-key")
	t.Setenv("GITHUB_WEBHOOK_SECRET", "configuration-test-secret")
}
