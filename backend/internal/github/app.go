// Package github wraps everything SBOMDelta needs from the GitHub App API:
// installation authentication, webhook verification, and check runs.
package github

import (
	"context"
	"errors"
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
		cfg: cfg,
		// Transport is set explicitly because ghinstallation uses it as-is:
		// a nil RoundTripper is not defaulted and panics on the first token
		// exchange.
		httpClient: &http.Client{Timeout: 30 * time.Second, Transport: http.DefaultTransport},
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

// InstallationAccountID asks GitHub which account an installation belongs to,
// as GitHub's numeric account ID. GET /app/installations/{id} authenticates as
// the App itself, with its JWT, rather than as the installation.
func (a *App) InstallationAccountID(ctx context.Context, installationID int64) (int64, error) {
	transport, err := ghinstallation.NewAppsTransport(a.httpClient.Transport, a.cfg.AppID, a.cfg.PrivateKey)
	if err != nil {
		return 0, fmt.Errorf("build app transport: %w", err)
	}
	if base := a.cfg.APIBaseURL; base != "" && base != "https://api.github.com/" {
		transport.BaseURL = trimTrailingSlash(base)
	}
	client := gh.NewClient(&http.Client{Transport: transport, Timeout: 30 * time.Second})
	if a.cfg.APIBaseURL != "" && a.cfg.APIBaseURL != "https://api.github.com/" {
		parsed, err := url.Parse(a.cfg.APIBaseURL)
		if err != nil {
			return 0, fmt.Errorf("parse github api base url: %w", err)
		}
		client.BaseURL = parsed
	}

	installation, _, err := client.Apps.GetInstallation(ctx, installationID)
	if err != nil {
		return 0, fmt.Errorf("get installation %d: %w", installationID, err)
	}
	id := installation.GetAccount().GetID()
	if id == 0 {
		return 0, fmt.Errorf("installation %d has no account ID", installationID)
	}
	return id, nil
}

// ListInstallationRepositories returns every repository the installation can
// currently access, following pagination.
//
// GET /installation/repositories needs only the installation token: GitHub
// grants every App the metadata permission it requires, so no additional App
// permission has to be requested for reconciliation to work.
func (a *App) ListInstallationRepositories(ctx context.Context, installationID int64) ([]*gh.Repository, error) {
	client, err := a.InstallationClient(installationID)
	if err != nil {
		return nil, err
	}

	// The listing is offset-paginated, so a repository added to or removed
	// from the installation between two page fetches shifts every later page:
	// one repository is skipped or seen twice. A skipped repository would be
	// revoked by reconciliation. Every page reports the installation's total,
	// so a total that moves, or a count that does not add up, means the list
	// changed mid-read and is rejected rather than trusted.
	var repos []*gh.Repository
	seen := make(map[int64]struct{})
	total := -1
	opts := &gh.ListOptions{PerPage: 100}
	for {
		page, resp, err := client.Apps.ListRepos(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("list repositories for installation %d: %w", installationID, err)
		}
		if total == -1 {
			total = page.GetTotalCount()
		} else if page.GetTotalCount() != total {
			return nil, fmt.Errorf("repositories for installation %d changed while listing (%d, then %d); retry",
				installationID, total, page.GetTotalCount())
		}
		for _, repo := range page.Repositories {
			if _, dup := seen[repo.GetID()]; dup {
				continue
			}
			seen[repo.GetID()] = struct{}{}
			repos = append(repos, repo)
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	if len(repos) != total {
		return nil, fmt.Errorf("listed %d repositories for installation %d but GitHub reported %d; retry",
			len(repos), installationID, total)
	}
	return repos, nil
}

// ErrNoBranchHead means GitHub answered definitively that a repository has no
// default branch commit to scan: it is empty, or the installation can no
// longer see it. Retrying will not change the answer, unlike a network error,
// a rate limit or a 5xx.
var ErrNoBranchHead = errors.New("repository has no default branch head")

// BranchHead is the commit a repository's default branch points at, and the
// repository's name as GitHub reported it alongside.
type BranchHead struct {
	Owner  string
	Name   string
	Branch string
	SHA    string
}

// FullName is the owner/name GitHub currently uses for the repository.
func (h BranchHead) FullName() string { return h.Owner + "/" + h.Name }

// DefaultBranchHead asks GitHub, as the installation, which commit the
// repository's default branch points at right now.
//
// The repository is looked up by its numeric GitHub ID, which survives
// renames and transfers, so the answer is about exactly the repository that
// was granted -- never another one that has since taken its old name. The
// default branch is likewise read from GitHub rather than from the stored
// row. The calls need metadata and contents read access, which the worker
// already relies on to clone the repository.
func (a *App) DefaultBranchHead(ctx context.Context, installationID, githubRepoID int64) (BranchHead, error) {
	client, err := a.InstallationClient(installationID)
	if err != nil {
		return BranchHead{}, err
	}

	label := fmt.Sprintf("repository %d", githubRepoID)
	repo, resp, err := client.Repositories.GetByID(ctx, githubRepoID)
	if err != nil {
		return BranchHead{}, headError(label, "read repository", resp, err)
	}
	owner, name := repo.GetOwner().GetLogin(), repo.GetName()
	if repo.GetID() != githubRepoID || owner == "" || name == "" {
		return BranchHead{}, fmt.Errorf("%s: GitHub returned repository %d %q/%q", label, repo.GetID(), owner, name)
	}
	branch := repo.GetDefaultBranch()
	if branch == "" {
		return BranchHead{}, fmt.Errorf("%s/%s reports no default branch: %w", owner, name, ErrNoBranchHead)
	}

	ref, resp, err := client.Repositories.GetBranch(ctx, owner, name, branch, 1)
	if err != nil {
		return BranchHead{}, headError(owner+"/"+name, "read branch "+branch, resp, err)
	}
	sha := ref.GetCommit().GetSHA()
	if !isCommitSHA(sha) {
		return BranchHead{}, fmt.Errorf("%s/%s branch %s returned malformed commit %q", owner, name, branch, sha)
	}
	return BranchHead{Owner: owner, Name: name, Branch: branch, SHA: sha}, nil
}

// headError classifies a failed head lookup by HTTP status. 404 (no access,
// or an empty repository's missing branch) and 409 (empty repository) are
// definitive; everything else, including no response at all, is left
// retryable. The status is read from the response rather than the error
// because GetBranch reports failures as an untyped error.
func headError(label, action string, resp *gh.Response, err error) error {
	if resp != nil && resp.Response != nil {
		switch resp.StatusCode {
		case http.StatusNotFound, http.StatusConflict:
			return fmt.Errorf("%s: %s: %w (%v)", label, action, ErrNoBranchHead, err)
		}
	}
	return fmt.Errorf("%s: %s: %w", label, action, err)
}

// isCommitSHA accepts full SHA-1 and SHA-256 object names only.
func isCommitSHA(sha string) bool {
	if len(sha) != 40 && len(sha) != 64 {
		return false
	}
	for _, c := range sha {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
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
