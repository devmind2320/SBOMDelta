// Package config loads runtime configuration from the environment.
//
// Configuration is validated once at startup and then passed down explicitly;
// nothing below this package reads os.Getenv.
package config

import (
	"errors"
	"fmt"
	"os"
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
	Blob        Blob
	Scanner     Scanner
	Worker      Worker
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
}

// Load reads configuration from the environment, applying defaults suited to
// local development. It returns every validation problem at once rather than
// failing on the first, so a misconfigured deployment needs one round trip.
func Load() (*Config, error) {
	return load(false)
}

// LoadAPI permits explicitly disabling GitHub integration for local dashboard
// development. Other environments retain the credential checks.
func LoadAPI() (*Config, error) {
	return load(true)
}

// LoadWorker permits the same opt-out as LoadAPI. A worker with GitHub
// disabled can still run manual scans of repositories registered by hand; it
// refuses only the scans that genuinely need an installation token.
func LoadWorker() (*Config, error) {
	return load(true)
}

func load(allowGitHubDisable bool) (*Config, error) {
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
	}
	if cfg.Worker.Concurrency < 1 {
		problems = append(problems, errors.New("WORKER_CONCURRENCY must be at least 1"))
	}

	if len(problems) > 0 {
		return nil, errors.Join(problems...)
	}
	return cfg, nil
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
