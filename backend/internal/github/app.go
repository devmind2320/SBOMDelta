// Package github wraps everything SBOMDelta needs from the GitHub App API:
// installation authentication, webhook verification, and check runs.
package github

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	gh "github.com/google/go-github/v66/github"

	"sbomdelta/internal/config"
)

// App mints per-installation GitHub clients.
//
// A GitHub App never holds a user's credentials. It signs a short-lived JWT
// with its private key, exchanges that for an installation access token scoped
// to exactly the repositories the installer granted, and uses that token for
// API calls. Tokens expire after an hour; ghinstallation refreshes them
// transparently, so clients are cached per installation and reused.
type App struct {
	cfg        config.GitHub
	httpClient *http.Client

	mu      sync.Mutex
	clients map[int64]*gh.Client
}

func NewApp(cfg config.GitHub) *App {
	return &App{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		clients:    make(map[int64]*gh.Client),
	}
}

// InstallationClient returns an API client authenticated as the given
// installation.
func (a *App) InstallationClient(installationID int64) (*gh.Client, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if client, ok := a.clients[installationID]; ok {
		return client, nil
	}

	transport, err := ghinstallation.New(a.httpClient.Transport, a.cfg.AppID, installationID, a.cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("build installation transport: %w", err)
	}
	if base := a.cfg.APIBaseURL; base != "" && base != "https://api.github.com/" {
		transport.BaseURL = trimTrailingSlash(base)
	}

	client := gh.NewClient(&http.Client{Transport: transport, Timeout: 30 * time.Second})
	if a.cfg.APIBaseURL != "" && a.cfg.APIBaseURL != "https://api.github.com/" {
		parsed, err := url.Parse(a.cfg.APIBaseURL)
		if err != nil {
			return nil, fmt.Errorf("parse github api base url: %w", err)
		}
		client.BaseURL = parsed
	}

	a.clients[installationID] = client
	return client, nil
}

// InstallationToken returns a raw access token for an installation. The worker
// needs one to clone private repositories over HTTPS, where a *gh.Client is no
// help because git is a separate process.
func (a *App) InstallationToken(ctx context.Context, installationID int64) (string, error) {
	transport, err := ghinstallation.New(a.httpClient.Transport, a.cfg.AppID, installationID, a.cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("build installation transport: %w", err)
	}
	if base := a.cfg.APIBaseURL; base != "" && base != "https://api.github.com/" {
		transport.BaseURL = trimTrailingSlash(base)
	}

	token, err := transport.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("mint installation token: %w", err)
	}
	return token, nil
}

// CloneURL builds an authenticated HTTPS clone URL. The token is embedded in
// userinfo, so it must never be logged: callers log repo.FullName() instead.
func CloneURL(owner, name, token string) string {
	return fmt.Sprintf("https://x-access-token:%s@github.com/%s/%s.git", token, owner, name)
}

func trimTrailingSlash(value string) string {
	for len(value) > 0 && value[len(value)-1] == '/' {
		value = value[:len(value)-1]
	}
	return value
}
