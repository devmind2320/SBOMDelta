package config

import (
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
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
			setAuthFixtures(t)
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
	setAuthFixtures(t)
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
		"APP_ENV":                   "development",
		"GITHUB_DISABLED":           "",
		"GITHUB_APP_ID":             "",
		"GITHUB_PRIVATE_KEY":        "",
		"GITHUB_PRIVATE_KEY_PATH":   "",
		"GITHUB_WEBHOOK_SECRET":     "",
		"WORKER_CONCURRENCY":        "4",
		"AUTH_DISABLED":             "",
		"GITHUB_CLIENT_ID":          "",
		"GITHUB_CLIENT_SECRET":      "",
		"GITHUB_CLIENT_SECRET_PATH": "",
		"PUBLIC_URL":                "",
		"ALLOWED_GITHUB_LOGINS":     "",
		"SESSION_TTL":               "",
		"GITHUB_WEB_BASE_URL":       "",
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

func setAuthFixtures(t *testing.T) {
	t.Helper()
	t.Setenv("GITHUB_CLIENT_ID", "Iv1.configtest")
	t.Setenv("GITHUB_CLIENT_SECRET", "configuration-test-client-secret")
	t.Setenv("PUBLIC_URL", "https://sbomdelta.example")
	t.Setenv("ALLOWED_GITHUB_LOGINS", "devmind2320")
}

// Sign-in has no defaults that could open the dashboard: every setting is
// required, and each problem is reported at once.
func TestLoadAPIRequiresSignInSettings(t *testing.T) {
	setConfigEnvironment(t)
	setCredentialFixtures(t)
	_, err := LoadAPI()
	if err == nil {
		t.Fatal("LoadAPI() accepted a server with no sign-in settings")
	}
	for _, requirement := range []string{"GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "PUBLIC_URL", "ALLOWED_GITHUB_LOGINS"} {
		if !strings.Contains(err.Error(), requirement) {
			t.Errorf("LoadAPI() error = %v, missing requirement %q", err, requirement)
		}
	}
}

func TestLoadAPISignInValidation(t *testing.T) {
	tests := []struct {
		name      string
		env       string
		set       map[string]string
		wantError string
	}{
		{name: "valid", env: "production"},
		{name: "public url with a path", env: "production", set: map[string]string{"PUBLIC_URL": "https://sbomdelta.example/app"}, wantError: "bare origin"},
		{name: "public url without scheme", env: "production", set: map[string]string{"PUBLIC_URL": "sbomdelta.example"}, wantError: "bare origin"},
		{name: "plain http outside development", env: "production", set: map[string]string{"PUBLIC_URL": "http://sbomdelta.example"}, wantError: "must use https"},
		{name: "plain http in development", env: "development", set: map[string]string{"PUBLIC_URL": "http://localhost:5173"}},
		{name: "public url with a trailing slash", env: "production", set: map[string]string{"PUBLIC_URL": "https://sbomdelta.example/"}},
		{name: "public url with a non-default port", env: "production", set: map[string]string{"PUBLIC_URL": "https://sbomdelta.example:8443"}},
		{name: "public url with an uppercase host", env: "production", set: map[string]string{"PUBLIC_URL": "https://SBOMDelta.example"}, wantError: `use "https://sbomdelta.example"`},
		{name: "public url with an uppercase scheme", env: "production", set: map[string]string{"PUBLIC_URL": "HTTPS://sbomdelta.example"}, wantError: `use "https://sbomdelta.example"`},
		{name: "public url with the default https port", env: "production", set: map[string]string{"PUBLIC_URL": "https://sbomdelta.example:443"}, wantError: `use "https://sbomdelta.example"`},
		{name: "public url with the default http port", env: "development", set: map[string]string{"PUBLIC_URL": "http://localhost:80"}, wantError: `use "http://localhost"`},
		{name: "public url with an empty port", env: "production", set: map[string]string{"PUBLIC_URL": "https://sbomdelta.example:"}, wantError: `use "https://sbomdelta.example"`},
		{name: "public url with uppercase and the default port", env: "production", set: map[string]string{"PUBLIC_URL": "https://SBOMDelta.Example:443/"}, wantError: `use "https://sbomdelta.example"`},
		{name: "blank allowlist", env: "production", set: map[string]string{"ALLOWED_GITHUB_LOGINS": " , "}, wantError: "ALLOWED_GITHUB_LOGINS is required"},
		{name: "not a login", env: "production", set: map[string]string{"ALLOWED_GITHUB_LOGINS": "devmind2320,bad login"}, wantError: "not a GitHub login"},
		{name: "wildcard is not a login", env: "production", set: map[string]string{"ALLOWED_GITHUB_LOGINS": "*"}, wantError: "not a GitHub login"},
		{name: "session too short", env: "production", set: map[string]string{"SESSION_TTL": "1m"}, wantError: "SESSION_TTL"},
		{name: "sign-in disabled outside development", env: "production", set: map[string]string{"AUTH_DISABLED": "true"}, wantError: "AUTH_DISABLED is only allowed"},
		{name: "invalid disable flag", env: "development", set: map[string]string{"AUTH_DISABLED": "maybe"}, wantError: "AUTH_DISABLED must be true or false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setConfigEnvironment(t)
			setCredentialFixtures(t)
			setAuthFixtures(t)
			t.Setenv("APP_ENV", tt.env)
			for key, value := range tt.set {
				t.Setenv(key, value)
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
			if cfg.Auth.Disabled || len(cfg.Auth.AllowedLogins) == 0 || cfg.Auth.PublicURL == nil {
				t.Fatalf("Auth = %+v, want sign-in enabled with an allowlist and public URL", cfg.Auth)
			}
		})
	}
}

func TestLoadAPISignInDetails(t *testing.T) {
	setConfigEnvironment(t)
	setCredentialFixtures(t)
	setAuthFixtures(t)
	t.Setenv("ALLOWED_GITHUB_LOGINS", " DevMind2320 , other-user ")
	t.Setenv("PUBLIC_URL", "https://sbomdelta.example/")
	t.Setenv("GITHUB_CLIENT_SECRET", "")
	path := t.TempDir() + "/client-secret"
	if err := os.WriteFile(path, []byte("file-client-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_CLIENT_SECRET_PATH", path)

	cfg, err := LoadAPI()
	if err != nil {
		t.Fatalf("LoadAPI() error = %v", err)
	}
	if got := strings.Join(cfg.Auth.AllowedLogins, ","); got != "devmind2320,other-user" {
		t.Errorf("AllowedLogins = %q, want trimmed and lowercased", got)
	}
	if got := cfg.Auth.PublicURL.String(); got != "https://sbomdelta.example" {
		t.Errorf("PublicURL = %q, want the bare origin", got)
	}
	if cfg.Auth.ClientSecret != "file-client-secret" {
		t.Error("ClientSecret was not read from GITHUB_CLIENT_SECRET_PATH and trimmed")
	}
	if !cfg.Auth.SecureCookies() {
		t.Error("SecureCookies() = false for an https PUBLIC_URL")
	}
	if cfg.Auth.SessionTTL != 12*time.Hour {
		t.Errorf("SessionTTL = %v, want the 12h default", cfg.Auth.SessionTTL)
	}
}

// Sign-in is the API server's concern; the worker must start without it.
func TestWorkerIgnoresSignInSettings(t *testing.T) {
	setConfigEnvironment(t)
	setCredentialFixtures(t)
	if _, err := LoadWorker(); err != nil {
		t.Fatalf("LoadWorker() error = %v, want no sign-in requirement", err)
	}
}

func TestLoadAPIWithSignInDisabledInDevelopment(t *testing.T) {
	setConfigEnvironment(t)
	setCredentialFixtures(t)
	t.Setenv("AUTH_DISABLED", "true")
	cfg, err := LoadAPI()
	if err != nil {
		t.Fatalf("LoadAPI() error = %v", err)
	}
	if !cfg.Auth.Disabled {
		t.Fatal("Auth.Disabled = false, want true")
	}
}

// The configured origin is compared byte for byte with the Origin header and
// sent to GitHub as the callback's origin, so only the browser's own spelling
// is accepted, and it is used as written.
func TestCanonicalOrigin(t *testing.T) {
	tests := map[string]string{
		"https://sbomdelta.example":      "https://sbomdelta.example",
		"https://SBOMDelta.Example":      "https://sbomdelta.example",
		"HTTPS://sbomdelta.example":      "https://sbomdelta.example",
		"https://sbomdelta.example:443":  "https://sbomdelta.example",
		"http://localhost:80":            "http://localhost",
		"http://localhost:5173":          "http://localhost:5173",
		"https://sbomdelta.example:8443": "https://sbomdelta.example:8443",
		"http://localhost:443":           "http://localhost:443",
		"https://[::1]:8443":             "https://[::1]:8443",
		"https://sbomdelta.example:":     "https://sbomdelta.example",
	}
	for raw, want := range tests {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", raw, err)
		}
		if got := canonicalOrigin(parsed); got != want {
			t.Errorf("canonicalOrigin(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestLoadAPIKeepsCanonicalPublicURL(t *testing.T) {
	setConfigEnvironment(t)
	setCredentialFixtures(t)
	setAuthFixtures(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("PUBLIC_URL", "https://sbomdelta.example:8443/")
	cfg, err := LoadAPI()
	if err != nil {
		t.Fatalf("LoadAPI() error = %v", err)
	}
	if got := cfg.Auth.PublicURL.String(); got != "https://sbomdelta.example:8443" {
		t.Errorf("PublicURL = %q, want the origin without the trailing slash", got)
	}
}
