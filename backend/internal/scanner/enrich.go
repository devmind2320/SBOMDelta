package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"sbomdelta/internal/diff"
	ghapp "sbomdelta/internal/github"
	"sbomdelta/internal/models"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/risk"
	"sbomdelta/internal/storage"
)

// ErrVulnerabilityAnalysisDisabled is recorded on scans when the worker
// runs with OSV_DISABLED.
var ErrVulnerabilityAnalysisDisabled = errors.New("vulnerability analysis is turned off on this worker (OSV_DISABLED)")

// enrichRetryDelay gives a struggling OSV a moment before the first retry;
// the queue's own backoff takes over from there.
const enrichRetryDelay = 2 * time.Minute

// enrichAfterScan runs the vulnerability lookup for a scan that just
// finished, and queues a retry if it fails for a reason a retry could fix.
func (s *Scanner) enrichAfterScan(ctx context.Context, logger *slog.Logger, scanID int64) {
	err := s.enrich(ctx, logger, scanID)
	switch {
	case err == nil:
	case errors.Is(err, ErrVulnerabilityAnalysisDisabled):
		logger.Info("vulnerability analysis is disabled; scan recorded without it")
	default:
		logger.Warn("vulnerability lookup failed; queueing a retry", "error", err)
		if s.jobs == nil {
			return
		}
		if _, err := s.jobs.EnqueueAfter(context.WithoutCancel(ctx), queue.KindEnrich,
			queue.EnrichPayload{ScanID: scanID}, queue.EnrichDedupeKey(scanID), enrichRetryDelay); err != nil {
			logger.Error("could not queue vulnerability lookup retry", "error", err)
		}
	}
}

// Enrich checks a completed scan's components for vulnerabilities and
// scores it, then refreshes its check run on GitHub if it has one. It is
// the KindEnrich job; an error makes the queue retry it.
func (s *Scanner) Enrich(ctx context.Context, scanID int64) error {
	scan, err := s.db.GetScan(ctx, scanID)
	if err != nil {
		return fmt.Errorf("load scan %d: %w", scanID, err)
	}
	if scan.Status != models.ScanCompleted {
		// Only completed scans have components; a scan that is still
		// running enriches itself when it finishes.
		return nil
	}
	logger := s.logger.With("scan", scanID)
	if err := s.enrich(ctx, logger, scanID); err != nil {
		if errors.Is(err, ErrVulnerabilityAnalysisDisabled) {
			return nil
		}
		return err
	}
	if scan.GitHubCheckRunID == nil || s.app == nil {
		return nil
	}
	repo, err := s.db.GetRepository(ctx, scan.RepositoryID)
	if err != nil {
		return err
	}
	installationID, err := s.db.GetInstallationIDForRepo(ctx, repo.ID)
	if err != nil {
		// No installation to post as any more; the dashboard has the result.
		logger.Info("not refreshing check run: repository has no usable installation", "error", err)
		return nil
	}
	if err := s.publishCheck(ctx, scanID, repo, installationID, *scan.GitHubCheckRunID); err != nil {
		logger.Warn("could not refresh check run after vulnerability lookup", "error", err)
	}
	return nil
}

// enrich looks the scan up, after making sure its base scan has been looked
// up too (once, not recursively): the comparison and the risk delta are
// only meaningful against an analyzed base.
func (s *Scanner) enrich(ctx context.Context, logger *slog.Logger, scanID int64) error {
	scan, err := s.db.GetScan(ctx, scanID)
	if err != nil {
		return fmt.Errorf("load scan %d: %w", scanID, err)
	}
	if s.vulns == nil {
		if err := s.db.RecordEnrichmentFailure(ctx, scanID, ErrVulnerabilityAnalysisDisabled.Error()); err != nil {
			return err
		}
		return ErrVulnerabilityAnalysisDisabled
	}
	if scan.BaseScanID != nil {
		base, err := s.db.GetScan(ctx, *scan.BaseScanID)
		if err == nil && base.Status == models.ScanCompleted && base.EnrichedAt == nil {
			if err := s.enrichOne(ctx, base); err != nil {
				logger.Warn("could not analyze the base scan; comparing without it", "base", base.ID, "error", err)
			}
		}
	}
	return s.enrichOne(ctx, scan)
}

func (s *Scanner) enrichOne(ctx context.Context, scan models.Scan) error {
	components, err := s.db.ListComponents(ctx, scan.ID)
	if err != nil {
		return err
	}
	report, err := s.vulns.Check(ctx, components)
	if err != nil {
		if recordErr := s.db.RecordEnrichmentFailure(context.WithoutCancel(ctx), scan.ID, err.Error()); recordErr != nil {
			return errors.Join(err, recordErr)
		}
		return err
	}

	byPURL := make(map[string]int, len(components))
	for i, c := range components {
		byPURL[c.PURL] = i
	}
	findings := make([]risk.Finding, 0, len(report.Findings))
	for _, f := range report.Findings {
		c := components[byPURL[f.PURL]]
		findings = append(findings, risk.Finding{
			OSVID: f.OSVID, Package: c.Name, Version: c.Version, Identity: f.Identity, PURL: f.PURL,
			Severity: f.Severity, Direct: c.Direct, FixedVersion: f.FixedVersion,
		})
	}
	assessment := risk.Assess(findings)

	result := storage.EnrichmentResult{
		ScanID: scan.ID, Findings: report.Findings, Checked: report.Checked, Skipped: report.Skipped,
		Assessment: assessment,
	}
	if scan.BaseScanID != nil {
		base, err := s.db.GetScan(ctx, *scan.BaseScanID)
		if err == nil && base.EnrichedAt != nil && base.RiskScore != nil {
			delta := math.Round((assessment.Score-*base.RiskScore)*10) / 10
			result.RiskDelta = &delta
			baseFindings, err := s.db.ScanFindings(ctx, base.ID)
			if err != nil {
				return err
			}
			events, err := s.db.ListDriftEvents(ctx, scan.ID)
			if err != nil {
				return err
			}
			result.DriftRisk = DriftRisk(events, baseFindings, findings)
		}
	}
	return s.db.SaveEnrichment(ctx, result)
}

// DriftRisk attributes score changes to dependency changes: an added
// package brings its findings' points, a removed one takes its points away,
// and an updated one swaps the old version's points for the new one's.
// When one package has several drift events (several versions), the change
// is attributed to the first so it is counted once.
func DriftRisk(events []models.DriftEvent, base, head []risk.Finding) map[int64]float64 {
	points := func(findings []risk.Finding) map[string]float64 {
		out := map[string]float64{}
		for _, f := range findings {
			out[f.Identity] += risk.Points(f)
		}
		return out
	}
	before, after := points(base), points(head)
	out := map[int64]float64{}
	done := map[string]bool{}
	for _, e := range events {
		if done[e.Identity] {
			continue
		}
		done[e.Identity] = true
		var delta float64
		switch e.ChangeType {
		case string(diff.Added):
			delta = after[e.Identity]
		case string(diff.Removed):
			delta = -before[e.Identity]
		case string(diff.Updated):
			delta = after[e.Identity] - before[e.Identity]
		}
		if delta != 0 {
			out[e.ID] = math.Round(delta*10) / 10
		}
	}
	return out
}

// publishCheck builds a scan's check report from what it stored and posts it.
func (s *Scanner) publishCheck(ctx context.Context, scanID int64, repo models.Repository, installationID, checkRunID int64) error {
	report, err := BuildCheckReport(ctx, s.db, scanID)
	if err != nil {
		return err
	}
	return s.app.PublishCheckRun(ctx, installationID, checkRunID, repo, report)
}

// BuildCheckReport reads a completed scan's drift and vulnerabilities into
// a check report.
func BuildCheckReport(ctx context.Context, db *storage.DB, scanID int64) (ghapp.CheckReport, error) {
	scan, err := db.GetScan(ctx, scanID)
	if err != nil {
		return ghapp.CheckReport{}, err
	}
	events, err := db.ListDriftEvents(ctx, scanID)
	if err != nil {
		return ghapp.CheckReport{}, err
	}
	report := ghapp.CheckReport{Baseline: scan.BaseScanID == nil, Components: scan.ComponentCount}
	for _, e := range events {
		change := diff.Change{
			Type: diff.ChangeType(e.ChangeType), Identity: e.Identity, Name: e.Name, Ecosystem: e.Ecosystem,
			PURL: e.PURL, OldVersion: e.OldVersion, NewVersion: e.NewVersion, Direction: diff.Direction(e.Direction),
		}
		switch change.Type {
		case diff.Added:
			report.Added = append(report.Added, change)
		case diff.Updated:
			report.Updated = append(report.Updated, change)
		case diff.Removed:
			report.Removed = append(report.Removed, change)
		}
	}

	if scan.EnrichedAt == nil {
		report.Vulns = ghapp.VulnerabilityReport{Reason: scan.EnrichmentError}
		if report.Vulns.Reason == "" {
			report.Vulns.Reason = "the lookup has not completed yet"
		}
		return report, nil
	}
	findings, err := db.ScanFindings(ctx, scanID)
	if err != nil {
		return ghapp.CheckReport{}, err
	}
	report.Vulns = ghapp.VulnerabilityReport{Available: true, Assessment: risk.Assess(findings)}
	if scan.BaseScanID != nil {
		base, err := db.GetScan(ctx, *scan.BaseScanID)
		if err == nil && base.EnrichedAt != nil {
			baseFindings, err := db.ScanFindings(ctx, base.ID)
			if err != nil {
				return ghapp.CheckReport{}, err
			}
			comparison := risk.Compare(baseFindings, findings)
			report.Vulns.Comparison = &comparison
		}
	}
	return report, nil
}
