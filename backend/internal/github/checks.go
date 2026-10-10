package github

import (
	"context"
	"fmt"
	"strings"
	"time"

	gh "github.com/google/go-github/v66/github"

	"sbomdelta/internal/diff"
	"sbomdelta/internal/models"
)

// Check run conclusions GitHub understands. "neutral" is used for informational
// drift so that a dependency change never blocks a merge until the risk engine
// (Phase 5) is there to justify blocking it.
const (
	conclusionSuccess = "success"
	conclusionNeutral = "neutral"
	conclusionFailure = "failure"
)

// StartCheckRun opens an in-progress check on a commit, so the PR shows that
// SBOMDelta is working before the scan finishes.
func (a *App) StartCheckRun(ctx context.Context, installationID int64, repo models.Repository, commitSHA string) (int64, error) {
	client, err := a.InstallationClient(installationID)
	if err != nil {
		return 0, err
	}

	run, _, err := client.Checks.CreateCheckRun(ctx, repo.Owner, repo.Name, gh.CreateCheckRunOptions{
		Name:      "SBOMDelta",
		HeadSHA:   commitSHA,
		Status:    gh.String("in_progress"),
		StartedAt: &gh.Timestamp{Time: time.Now()},
		Output: &gh.CheckRunOutput{
			Title:   gh.String("Analyzing dependencies"),
			Summary: gh.String("Generating an SBOM and comparing it against the previous scan."),
		},
	})
	if err != nil {
		return 0, fmt.Errorf("create check run: %w", err)
	}
	return run.GetID(), nil
}

// CompleteCheckRun writes the diff result back onto the commit.
func (a *App) CompleteCheckRun(ctx context.Context, installationID, checkRunID int64, repo models.Repository, result *diff.Result, baseline bool) error {
	client, err := a.InstallationClient(installationID)
	if err != nil {
		return err
	}

	title, summary, text := renderCheckOutput(result, baseline)
	conclusion := conclusionSuccess
	if result.HasDrift() {
		conclusion = conclusionNeutral
	}

	_, _, err = client.Checks.UpdateCheckRun(ctx, repo.Owner, repo.Name, checkRunID, gh.UpdateCheckRunOptions{
		Name:        "SBOMDelta",
		Status:      gh.String("completed"),
		Conclusion:  gh.String(conclusion),
		CompletedAt: &gh.Timestamp{Time: time.Now()},
		Output: &gh.CheckRunOutput{
			Title:   gh.String(title),
			Summary: gh.String(summary),
			Text:    gh.String(text),
		},
	})
	if err != nil {
		return fmt.Errorf("complete check run: %w", err)
	}
	return nil
}

// FailCheckRun reports that the scan itself broke, as distinct from the scan
// finding a problem. Conflating the two teaches people to ignore the check.
func (a *App) FailCheckRun(ctx context.Context, installationID, checkRunID int64, repo models.Repository, cause string) error {
	client, err := a.InstallationClient(installationID)
	if err != nil {
		return err
	}

	_, _, err = client.Checks.UpdateCheckRun(ctx, repo.Owner, repo.Name, checkRunID, gh.UpdateCheckRunOptions{
		Name:        "SBOMDelta",
		Status:      gh.String("completed"),
		Conclusion:  gh.String(conclusionFailure),
		CompletedAt: &gh.Timestamp{Time: time.Now()},
		Output: &gh.CheckRunOutput{
			Title:   gh.String("Scan failed"),
			Summary: gh.String("SBOMDelta could not analyze this commit."),
			Text:    gh.String("```\n" + truncate(cause, 60_000) + "\n```"),
		},
	})
	if err != nil {
		return fmt.Errorf("fail check run: %w", err)
	}
	return nil
}

// renderCheckOutput turns a diff into the three fields GitHub shows on a check.
func renderCheckOutput(result *diff.Result, baseline bool) (title, summary, text string) {
	if baseline {
		return "Baseline recorded",
			fmt.Sprintf("Recorded %d components as the baseline for this repository. Future commits will be compared against it.", len(result.Unchanged)),
			""
	}
	if !result.HasDrift() {
		return "No dependency changes",
			fmt.Sprintf("The dependency set is unchanged (%d components).", len(result.Unchanged)),
			""
	}

	title = fmt.Sprintf("%d dependency change%s", len(result.Changes()), plural(len(result.Changes())))
	summary = fmt.Sprintf("**%d added** · **%d updated** · **%d removed** — out of %d components total.",
		len(result.Added), len(result.Updated), len(result.Removed),
		len(result.Added)+len(result.Updated)+len(result.Unchanged))

	var body strings.Builder
	writeSection(&body, "Added", result.Added, func(change diff.Change) string {
		return fmt.Sprintf("`%s` **%s** %s", change.Ecosystem, change.Name, change.NewVersion)
	})
	writeSection(&body, "Updated", result.Updated, func(change diff.Change) string {
		arrow := "→"
		if change.Direction == diff.DirectionDowngrade {
			arrow = "↓"
		}
		return fmt.Sprintf("`%s` **%s** %s %s %s", change.Ecosystem, change.Name, change.OldVersion, arrow, change.NewVersion)
	})
	writeSection(&body, "Removed", result.Removed, func(change diff.Change) string {
		return fmt.Sprintf("`%s` **%s** %s", change.Ecosystem, change.Name, change.OldVersion)
	})

	return title, summary, body.String()
}

// maxListedChanges keeps a huge lockfile refresh from blowing past GitHub's
// 65535-character limit on check output text.
const maxListedChanges = 50

func writeSection(body *strings.Builder, heading string, changes []diff.Change, render func(diff.Change) string) {
	if len(changes) == 0 {
		return
	}
	fmt.Fprintf(body, "### %s (%d)\n\n", heading, len(changes))
	for i, change := range changes {
		if i == maxListedChanges {
			fmt.Fprintf(body, "\n_…and %d more._\n", len(changes)-maxListedChanges)
			break
		}
		fmt.Fprintf(body, "- %s\n", render(change))
	}
	body.WriteString("\n")
}

func plural(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "\n… truncated"
}

func timePtr(timestamp *gh.Timestamp) *time.Time {
	if timestamp == nil || timestamp.Time.IsZero() {
		return nil
	}
	moment := timestamp.Time
	return &moment
}
