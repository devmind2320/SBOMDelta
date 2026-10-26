// Package config loads runtime configuration from the environment.
//
// Configuration is validated once at startup and then passed down explicitly;
// nothing below this package reads os.Getenv.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env      string
	HTTPAddr string
	// DatabaseURL is a libpq-style connection string.
	DatabaseURL string
	GitHub      GitHub
	// Auth is loaded and validated only for the API server.
	Auth    Auth
	Blob    Blob
	Scanner Scanner
	Worker  Worker
}

type GitHub struct {
	// Disabled turns off GitHub integration for local development. The API
	// then refuses webhooks and the worker handles only manual scans of
	// repositories that carry their own clone URL.
	Disabled bool
	AppID    int64
	// PrivateKey is the PEM-encoded RSA key downloaded when the GitHub App was
	// created. It signs the app JWT used to mint installation tokens.
	PrivateKey    []byte
	WebhookSecret string
	APIBaseURL    string
	// AppSlug is used to build human-facing links back to the app.
	AppSlug string
	// AllowedInstallationAccounts are the GitHub numeric account IDs whose
	// installations may queue work: reconciliation, initial scans, push and
	// pull request scans. Anyone can install a public App; an installation
	// on any other account is recorded and otherwise ignored.
	AllowedInstallationAccounts []int64
}

// Auth configures dashboard sign-in through the GitHub App's user
// authorization flow.
type Auth struct {
	// Disabled serves the dashboard without sign-in, as a fixed development
	// user. Like GitHub.Disabled it is refused outside APP_ENV=development.
	Disabled bool
	// ClientID and ClientSecret are the GitHub App's own OAuth credentials,
	// from its settings page. They identify users; they never grant access to
	// repositories, which still comes from installation tokens.
	ClientID     string
	ClientSecret string
	// PublicURL is the origin browsers use to reach the dashboard, such as
	// https://sbomdelta.example. The OAuth callback is built from it and
	// state-changing requests must come from it.
	PublicURL *url.URL
	// WebBaseURL is where GitHub's OAuth pages live: github.com, or a GitHub
	// Enterprise Server host.
	WebBaseURL string
	// AllowedLogins is who may sign in, lowercased. Everyone else is refused.
	AllowedLogins []string
	// SessionTTL is how long a sign-in lasts before it must be repeated.
	SessionTTL time.Duration
}

// SecureCookies reports whether session cookies must carry the Secure
// attribute: always, unless the dashboard is served over plain HTTP, which
// only local development does.
func (a Auth) SecureCookies() bool {
	return a.PublicURL == nil || a.PublicURL.Scheme != "http"
}

type Blob struct {
	Endpoint  string
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	UseSSL    bool
	// PathStyle is required by MinIO and by S3-compatible stores that do not
	// support virtual-host addressing.
	PathStyle bool
}

type Scanner struct {
	// SyftPath is the syft binary to shell out to for SBOM generation.
	SyftPath string
	// GitPath is the git binary used for cloning and ref resolution. It is
	// configurable because a stale git earlier on PATH is a common and
	// confusing failure: partial clone needs 2.19 or newer.
	GitPath string
	// WorkDir holds clone directories; each scan gets a subdirectory that is
	// removed when the scan finishes.
	WorkDir string
	// CloneTimeout and SBOMTimeout bound the two operations that touch the
	// network and the filesystem hardest.
	CloneTimeout time.Duration
	SBOMTimeout  time.Duration
	// MaxRepoSizeMB rejects repositories large enough to exhaust worker disk.
	MaxRepoSizeMB int64
}

type Worker struct {
	// Concurrency is how many jobs one worker process runs at once.
	Concurrency int
	// PollInterval is how long an idle worker waits before asking for work
	// again. Postgres LISTEN/NOTIFY could replace this later.
	PollInterval time.Duration
	// LockTimeout is how long a job may stay locked before another worker
	// treats it as abandoned and reclaims it.
	LockTimeout time.Duration
	// OSVBaseURL is the OSV.dev API the worker checks components against.
	// It is public and needs no credentials.
	OSVBaseURL string
	// OSVDisabled turns vulnerability analysis off, for offline development.
	// Scans then record that their components were not checked.
	OSVDisabled bool
}

// Load reads configuration from the environment, applying defaults suited to
// local development. It returns every validation problem at once rather than
// failing on the first, so a misconfigured deployment needs one round trip.
func Load() (*Config, error) {
	return load(false, false)
}

// LoadAPI permits explicitly disabling GitHub integration for local dashboard
// development. Other environments retain the credential checks. It also loads
// the sign-in settings, which only the API server uses.
func LoadAPI() (*Config, error) {
	return load(true, true)
}

// LoadWorker permits the same opt-out as LoadAPI. A worker with GitHub
// disabled can still run manual scans of repositories registered by hand; it
// refuses only the scans that genuinely need an installation token.
func LoadWorker() (*Config, error) {
	return load(true, false)
}

func load(allowGitHubDisable, loadAuth bool) (*Config, error) {
	cfg := &Config{
		Env:         env("APP_ENV", "development"),
		HTTPAddr:    env("HTTP_ADDR", ":8080"),
		DatabaseURL: env("DATABASE_URL", "postgres://sbomdelta:sbomdelta@localhost:5432/sbomdelta?sslmode=disable"),
		GitHub: GitHub{
			WebhookSecret: os.Getenv("GITHUB_WEBHOOK_SECRET"),
			APIBaseURL:    env("GITHUB_API_BASE_URL", "https://api.github.com/"),
			AppSlug:       os.Getenv("GITHUB_APP_SLUG"),
		},
		Blob: Blob{
			Endpoint:  env("BLOB_ENDPOINT", "localhost:9000"),
			Region:    env("BLOB_REGION", "us-east-1"),
			Bucket:    env("BLOB_BUCKET", "sbomdelta"),
			AccessKey: env("BLOB_ACCESS_KEY", "minioadmin"),
			SecretKey: env("BLOB_SECRET_KEY", "minioadmin"),
			UseSSL:    boolEnv("BLOB_USE_SSL", false),
			PathStyle: boolEnv("BLOB_PATH_STYLE", true),
		},
		Scanner: Scanner{
			SyftPath:      env("SYFT_PATH", "syft"),
			GitPath:       env("GIT_PATH", "git"),
			WorkDir:       env("SCANNER_WORK_DIR", os.TempDir()),
			CloneTimeout:  durationEnv("SCANNER_CLONE_TIMEOUT", 5*time.Minute),
			SBOMTimeout:   durationEnv("SCANNER_SBOM_TIMEOUT", 10*time.Minute),
			MaxRepoSizeMB: intEnv("SCANNER_MAX_REPO_SIZE_MB", 2048),
		},
		Worker: Worker{
			Concurrency:  int(intEnv("WORKER_CONCURRENCY", 4)),
			PollInterval: durationEnv("WORKER_POLL_INTERVAL", 2*time.Second),
			LockTimeout:  durationEnv("WORKER_LOCK_TIMEOUT", 15*time.Minute),
			OSVBaseURL:   env("OSV_API_BASE_URL", "https://api.osv.dev"),
			OSVDisabled:  boolEnv("OSV_DISABLED", false),
		},
	}

	var problems []error

	if allowGitHubDisable {
		if value := os.Getenv("GITHUB_DISABLED"); value != "" {
			disabled, err := strconv.ParseBool(value)
			if err != nil {
				problems = append(problems, errors.New("GITHUB_DISABLED must be true or false"))
			}
			cfg.GitHub.Disabled = disabled
		}
	}
	if cfg.GitHub.Disabled && cfg.Env != "development" {
		problems = append(problems, errors.New("GITHUB_DISABLED is only allowed when APP_ENV=development"))
	}

	if !cfg.GitHub.Disabled {
		appID := os.Getenv("GITHUB_APP_ID")
		if appID == "" {
			problems = append(problems, errors.New("GITHUB_APP_ID is required"))
		} else {
			parsed, err := strconv.ParseInt(appID, 10, 64)
			if err != nil {
				problems = append(problems, fmt.Errorf("GITHUB_APP_ID %q is not a number", appID))
			}
			cfg.GitHub.AppID = parsed
		}

		key, err := loadPrivateKey()
		if err != nil {
			problems = append(problems, err)
		}
		cfg.GitHub.PrivateKey = key

		if cfg.GitHub.WebhookSecret == "" {
			problems = append(problems, errors.New("GITHUB_WEBHOOK_SECRET is required; without it webhook signatures cannot be verified"))
		}

		cfg.GitHub.AllowedInstallationAccounts, problems = loadInstallationAccounts(problems)
	}
	if cfg.Worker.Concurrency < 1 {
		problems = append(problems, errors.New("WORKER_CONCURRENCY must be at least 1"))
	}
	if osvURL, err := url.Parse(cfg.Worker.OSVBaseURL); err != nil || osvURL.Host == "" ||
		(osvURL.Scheme != "https" && !(osvURL.Scheme == "http" && cfg.Env == "development")) {
		problems = append(problems, fmt.Errorf("OSV_API_BASE_URL %q must be an https URL", cfg.Worker.OSVBaseURL))
	}
	if loadAuth {
		cfg.Auth, problems = loadAuthConfig(cfg.Env, problems)
	}

	if len(problems) > 0 {
		return nil, errors.Join(problems...)
	}
	return cfg, nil
}

// loadInstallationAccounts reads ALLOWED_INSTALLATION_ACCOUNTS: GitHub's
// numeric account IDs, never logins, because a login can be renamed and then
// claimed by someone else. Like ALLOWED_GITHUB_LOGINS it has no default, and
// an empty list is an error rather than "allow every installation".
func loadInstallationAccounts(problems []error) ([]int64, []error) {
	var accounts []int64
	for _, raw := range strings.Split(os.Getenv("ALLOWED_INSTALLATION_ACCOUNTS"), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id <= 0 {
			problems = append(problems, fmt.Errorf("ALLOWED_INSTALLATION_ACCOUNTS contains %q, which is not a GitHub numeric account ID", raw))
			continue
		}
		accounts = append(accounts, id)
	}
	if len(accounts) == 0 {
		problems = append(problems, errors.New("ALLOWED_INSTALLATION_ACCOUNTS is required: a comma-separated list of the GitHub numeric account IDs whose installations may be scanned"))
	}
	return accounts, problems
}

// githubLogin matches GitHub's username rules: letters, digits and single
// hyphens, not at either end, at most 39 characters.
var githubLogin = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9]|-[a-z0-9]){0,38}$`)

// loadAuthConfig reads the sign-in settings. Nothing here has a usable
// default: an empty allowlist or a missing secret is an error, never "allow
// everyone".
func loadAuthConfig(appEnv string, problems []error) (Auth, []error) {
	auth := Auth{
		ClientID:   os.Getenv("GITHUB_CLIENT_ID"),
		WebBaseURL: strings.TrimRight(env("GITHUB_WEB_BASE_URL", "https://github.com"), "/"),
		SessionTTL: durationEnv("SESSION_TTL", 12*time.Hour),
	}

	if value := os.Getenv("AUTH_DISABLED"); value != "" {
		disabled, err := strconv.ParseBool(value)
		if err != nil {
			problems = append(problems, errors.New("AUTH_DISABLED must be true or false"))
		}
		auth.Disabled = disabled
	}
	if auth.Disabled {
		if appEnv != "development" {
			problems = append(problems, errors.New("AUTH_DISABLED is only allowed when APP_ENV=development"))
		}
		return auth, problems
	}

	if auth.ClientID == "" {
		problems = append(problems, errors.New("GITHUB_CLIENT_ID is required (the GitHub App's Client ID)"))
	}
	secret, err := loadClientSecret()
	if err != nil {
		problems = append(problems, err)
	}
	auth.ClientSecret = secret

	raw := os.Getenv("PUBLIC_URL")
	switch parsed, err := url.Parse(raw); {
	case raw == "":
		problems = append(problems, errors.New("PUBLIC_URL is required, e.g. https://sbomdelta.example"))
	case err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil:
		problems = append(problems, fmt.Errorf("PUBLIC_URL %q must be a bare origin such as https://sbomdelta.example", raw))
	case parsed.Scheme == "http" && appEnv != "development":
		problems = append(problems, errors.New("PUBLIC_URL must use https outside APP_ENV=development"))
	case strings.TrimSuffix(raw, "/") != canonicalOrigin(parsed):
		// Browsers send the Origin header, and GitHub compares the callback
		// URL, in exactly one spelling. Any other would refuse every sign-out
		// and every sign-in, so it is an error here rather than at runtime.
		problems = append(problems, fmt.Errorf("PUBLIC_URL %q is not written the way browsers send it; use %q (lowercase, no default port)",
			raw, canonicalOrigin(parsed)))
	default:
		auth.PublicURL = &url.URL{Scheme: parsed.Scheme, Host: parsed.Host}
	}

	for _, login := range strings.Split(os.Getenv("ALLOWED_GITHUB_LOGINS"), ",") {
		login = strings.ToLower(strings.TrimSpace(login))
		if login == "" {
			continue
		}
		if !githubLogin.MatchString(login) {
			problems = append(problems, fmt.Errorf("ALLOWED_GITHUB_LOGINS contains %q, which is not a GitHub login", login))
			continue
		}
		auth.AllowedLogins = append(auth.AllowedLogins, login)
	}
	if len(auth.AllowedLogins) == 0 {
		problems = append(problems, errors.New("ALLOWED_GITHUB_LOGINS is required: a comma-separated list of GitHub logins that may sign in"))
	}

	if auth.SessionTTL < 5*time.Minute || auth.SessionTTL > 30*24*time.Hour {
		problems = append(problems, errors.New("SESSION_TTL must be between 5m and 720h"))
	}
	return auth, problems
}

// canonicalOrigin is the serialization browsers use for an origin: lowercase
// scheme and host, and no port when it is the scheme's default.
func canonicalOrigin(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" && !(u.Scheme == "https" && port == "443") && !(u.Scheme == "http" && port == "80") {
		host += ":" + port
	}
	return strings.ToLower(u.Scheme) + "://" + host
}

// loadClientSecret follows loadPrivateKey: inline for container platforms, a
// file for everything else, so the secret need not sit in an environment
// file.
func loadClientSecret() (string, error) {
	if inline := os.Getenv("GITHUB_CLIENT_SECRET"); inline != "" {
		return inline, nil
	}
	path := os.Getenv("GITHUB_CLIENT_SECRET_PATH")
	if path == "" {
		return "", errors.New("one of GITHUB_CLIENT_SECRET or GITHUB_CLIENT_SECRET_PATH is required (a client secret generated on the GitHub App's settings page)")
	}
	secret, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read GITHUB_CLIENT_SECRET_PATH: %w", err)
	}
	value := strings.TrimSpace(string(secret))
	if value == "" {
		return "", errors.New("GITHUB_CLIENT_SECRET_PATH points at an empty file")
	}
	return value, nil
}

// loadPrivateKey accepts the key either as a file path or inline. Inline is
// what container platforms make easy; a path is what local development makes
// easy.
func loadPrivateKey() ([]byte, error) {
	if inline := os.Getenv("GITHUB_PRIVATE_KEY"); inline != "" {
		// Env vars cannot carry real newlines in every deployment system, so
		// accept the escaped form too.
		return []byte(strings.ReplaceAll(inline, `\n`, "\n")), nil
	}
	path := os.Getenv("GITHUB_PRIVATE_KEY_PATH")
	if path == "" {
		return nil, errors.New("one of GITHUB_PRIVATE_KEY or GITHUB_PRIVATE_KEY_PATH is required")
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read GITHUB_PRIVATE_KEY_PATH: %w", err)
	}
	return key, nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func boolEnv(key string, fallback bool) bool {
	value, err := strconv.ParseBool(os.Getenv(key))
	if err != nil {
		return fallback
	}
	return value
}

func intEnv(key string, fallback int64) int64 {
	value, err := strconv.ParseInt(os.Getenv(key), 10, 64)
	if err != nil {
		return fallback
	}
	return value
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(os.Getenv(key))
	if err != nil {
		return fallback
	}
	return value
}
