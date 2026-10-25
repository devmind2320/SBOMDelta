package github

import (
	"context"
	"fmt"
	"strings"
	"time"

	gh "github.com/google/go-github/v66/github"

	"sbomdelta/internal/diff"
	"sbomdelta/internal/models"
	"sbomdelta/internal/risk"
)

// Check run conclusions GitHub understands. The policy (see Conclusion):
//
//   - failure: the change introduces a critical- or high-severity
//     vulnerability, or the scan itself broke (FailCheckRun);
//   - neutral: dependencies changed, lower-severity vulnerabilities were
//     introduced, or vulnerability data is unavailable -- worth a look, not
//     a reason to block;
//   - success: nothing changed and nothing new is vulnerable.
//
// A failing check blocks a merge only where branch protection requires it.
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

// CheckReport is everything a finished scan reports on its commit, built
// from what the scan stored.
type CheckReport struct {
	// Baseline is a scan with nothing to compare against.
	Baseline   bool
	Added      []diff.Change
	Updated    []diff.Change
	Removed    []diff.Change
	Components int
	Vulns      VulnerabilityReport
}

// VulnerabilityReport is the vulnerability half of a check.
type VulnerabilityReport struct {
	// Available is false until the scan's components have been checked;
	// Reason then says why they have not.
	Available  bool
	Reason     string
	Assessment risk.Assessment
	// Comparison is set when the base scan was checked too.
	Comparison *risk.Comparison
}

func (r CheckReport) hasDrift() bool {
	return len(r.Added)+len(r.Updated)+len(r.Removed) > 0
}

// Conclusion applies the policy above.
func (r CheckReport) Conclusion() string {
	if r.Vulns.Available && r.Vulns.Comparison != nil {
		if risk.Blocking(r.Vulns.Comparison.Introduced) > 0 {
			return conclusionFailure
		}
		if len(r.Vulns.Comparison.Introduced) > 0 {
			return conclusionNeutral
		}
	}
	if r.hasDrift() || !r.Vulns.Available {
		return conclusionNeutral
	}
	if r.Baseline && r.Vulns.Assessment.Total > 0 {
		return conclusionNeutral
	}
	return conclusionSuccess
}

// PublishCheckRun completes (or updates) a check run with a scan's report.
// Updating a completed run is allowed, which is how a vulnerability lookup
// that succeeds on retry corrects a check first published without it.
func (a *App) PublishCheckRun(ctx context.Context, installationID, checkRunID int64, repo models.Repository, report CheckReport) error {
	client, err := a.InstallationClient(installationID)
	if err != nil {
		return err
	}

	title, summary, text := RenderCheck(report)
	_, _, err = client.Checks.UpdateCheckRun(ctx, repo.Owner, repo.Name, checkRunID, gh.UpdateCheckRunOptions{
		Name:        "SBOMDelta",
		Status:      gh.String("completed"),
		Conclusion:  gh.String(report.Conclusion()),
		CompletedAt: &gh.Timestamp{Time: time.Now()},
		Output: &gh.CheckRunOutput{
			Title:   gh.String(title),
			Summary: gh.String(summary),
			Text:    gh.String(truncate(text, 60_000)),
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

// RenderCheck turns a report into the three fields GitHub shows on a check.
func RenderCheck(r CheckReport) (title, summary, text string) {
	var lines []string
	var body strings.Builder

	switch {
	case r.Baseline:
		title = "Baseline recorded"
		lines = append(lines, fmt.Sprintf("Recorded %d components as the baseline. Future commits are compared against it.", r.Components))
	case !r.hasDrift():
		title = "No dependency changes"
		lines = append(lines, fmt.Sprintf("The dependency set is unchanged (%d components).", r.Components))
	default:
		changes := len(r.Added) + len(r.Updated) + len(r.Removed)
		title = fmt.Sprintf("%d dependency change%s", changes, plural(changes))
		lines = append(lines, fmt.Sprintf("**%d added** · **%d updated** · **%d removed** — out of %d components total.",
			len(r.Added), len(r.Updated), len(r.Removed), r.Components))
	}

	vulnTitle, vulnLines := renderVulnerabilities(r)
	if vulnTitle != "" {
		title = vulnTitle
	}
	lines = append(lines, vulnLines...)
	summary = strings.Join(lines, "\n\n")

	if r.Vulns.Available && r.Vulns.Comparison != nil {
		writeFindings(&body, "Vulnerabilities introduced", r.Vulns.Comparison.Introduced)
		writeFindings(&body, "Vulnerabilities resolved", r.Vulns.Comparison.Resolved)
	} else if r.Vulns.Available && r.Baseline {
		top := make([]risk.Finding, 0, len(r.Vulns.Assessment.Top))
		for _, c := range r.Vulns.Assessment.Top {
			top = append(top, c.Finding)
		}
		writeFindings(&body, "Highest-scoring vulnerabilities", top)
	}

	writeSection(&body, "Added", r.Added, func(change diff.Change) string {
		return fmt.Sprintf("`%s` **%s** %s", change.Ecosystem, change.Name, change.NewVersion)
	})
	writeSection(&body, "Updated", r.Updated, func(change diff.Change) string {
		arrow := "→"
		if change.Direction == diff.DirectionDowngrade {
			arrow = "↓"
		}
		return fmt.Sprintf("`%s` **%s** %s %s %s", change.Ecosystem, change.Name, change.OldVersion, arrow, change.NewVersion)
	})
	writeSection(&body, "Removed", r.Removed, func(change diff.Change) string {
		return fmt.Sprintf("`%s` **%s** %s", change.Ecosystem, change.Name, change.OldVersion)
	})
	if r.Vulns.Available {
		body.WriteString("---\n_Risk score: " + risk.Method + "_\n")
	}
	return title, summary, body.String()
}

// renderVulnerabilities summarizes the vulnerability picture, and returns a
// title when it should lead the check.
func renderVulnerabilities(r CheckReport) (string, []string) {
	v := r.Vulns
	if !v.Available {
		reason := v.Reason
		if reason == "" {
			reason = "the lookup has not completed"
		}
		return "", []string{"Vulnerability data is unavailable for this commit: " + reason +
			". The dependency comparison above is complete; the vulnerability check is retried automatically."}
	}
	score := fmt.Sprintf("Risk score **%s** (%s) from %d known vulnerabilit%s, %d with a published fix.",
		trimScore(v.Assessment.Score), v.Assessment.Level, v.Assessment.Total, yPlural(v.Assessment.Total), v.Assessment.Fixable)
	if v.Comparison == nil {
		return "", []string{score}
	}
	introduced, resolved := len(v.Comparison.Introduced), len(v.Comparison.Resolved)
	line := fmt.Sprintf("**%d vulnerabilit%s introduced** · %d resolved · %d unchanged compared with the base.",
		introduced, yPlural(introduced), resolved, v.Comparison.Unchanged)
	title := ""
	switch blocking := risk.Blocking(v.Comparison.Introduced); {
	case blocking > 0:
		title = fmt.Sprintf("%d critical/high vulnerabilit%s introduced", blocking, yPlural(blocking))
	case introduced > 0:
		title = fmt.Sprintf("%d vulnerabilit%s introduced", introduced, yPlural(introduced))
	case resolved > 0 && !r.hasDrift():
		title = fmt.Sprintf("%d vulnerabilit%s resolved", resolved, yPlural(resolved))
	}
	return title, []string{line, score}
}

func writeFindings(body *strings.Builder, heading string, findings []risk.Finding) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintf(body, "### %s (%d)\n\n", heading, len(findings))
	for i, f := range findings {
		if i == maxListedChanges {
			fmt.Fprintf(body, "\n_…and %d more._\n", len(findings)-maxListedChanges)
			break
		}
		severity := strings.ToLower(f.Severity)
		if severity == "" {
			severity = "unrated"
		}
		fix := "no fix published"
		if f.FixedVersion != "" {
			fix = "fixed in " + f.FixedVersion
		}
		fmt.Fprintf(body, "- **%s** [%s](https://osv.dev/vulnerability/%s) in `%s` %s — %s\n",
			severity, f.OSVID, f.OSVID, f.Package, f.Version, fix)
	}
	body.WriteString("\n")
}

func trimScore(score float64) string {
	return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%.1f", score), "0"), ".")
}

func yPlural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
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
