package github

import (
	"context"
	"log/slog"
	"slices"

	"sbomdelta/internal/models"
	"sbomdelta/internal/storage"
)

// Reasons the installation gate refuses work, as logged.
const (
	refusedNotConnected = "no SBOMDelta user has connected this installation"
	refusedAccount      = "the account is not in ALLOWED_INSTALLATION_ACCOUNTS"
)

// installationGate decides which installations may queue work:
// reconciliation, initial scans, push and pull request scans.
//
// Anyone can install a public App, so an installation qualifies only once it
// is connected: the GitHub listing read at some SBOMDelta user's sign-in
// includes it. GitHub produces that listing for the user's own token, so it
// names only installations the user can reach on GitHub. An installation no
// one has signed in to use is recorded and otherwise ignored.
//
// An operator can narrow this further with allowedAccounts
// (ALLOWED_INSTALLATION_ACCOUNTS), by GitHub's numeric account ID; with it
// set, an installation whose account is not yet known never qualifies.
type installationGate struct {
	allowedAccounts []int64
	db              *storage.DB
}

// refusal returns why the installation may not queue work, or "" if it may.
func (g installationGate) refusal(ctx context.Context, installation models.Installation) (string, error) {
	connected, err := g.db.InstallationHasUsers(ctx, installation.GitHubInstallationID)
	if err != nil {
		return "", err
	}
	if !connected {
		return refusedNotConnected, nil
	}
	if !g.accountAllowed(installation) {
		return refusedAccount, nil
	}
	return "", nil
}

func (g installationGate) accountAllowed(installation models.Installation) bool {
	if len(g.allowedAccounts) == 0 {
		return true
	}
	return installation.AccountID != 0 && slices.Contains(g.allowedAccounts, installation.AccountID)
}

// logRefused is the audit record of work refused for an installation.
func logRefused(logger *slog.Logger, installation models.Installation, trigger, reason string) {
	logger.Info("ignoring installation; nothing queued",
		"reason", reason, "trigger", trigger, "installation", installation.GitHubInstallationID,
		"account", installation.AccountLogin, "account_id", installation.AccountID)
}
