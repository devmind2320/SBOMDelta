package storage

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"sbomdelta/internal/models"
	"sbomdelta/internal/osv"
	"sbomdelta/internal/risk"
)

// secretPatterns match credentials that must never reach the dashboard, even
// if a tool echoes one into an error message: tokens embedded in clone URLs,
// GitHub token formats, and bearer headers.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(https?://)[^/\s:@]+:[^/\s@]+@`),
	regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`),
	regexp.MustCompile(`(?i)(bearer|token)\s+[A-Za-z0-9._\-]{20,}`),
}

// maxErrorLength keeps a runaway tool's output from flooding a list view.
const maxErrorLength = 2000

// RedactSecrets removes credentials from error text read back for display,
// and bounds its length. Errors are redacted where they are produced too;
// this is the second line of defence.
func RedactSecrets(text string) string {
	if text == "" {
		return text
	}
	text = secretPatterns[0].ReplaceAllString(text, "${1}[redacted]@")
	text = secretPatterns[1].ReplaceAllString(text, "[redacted]")
	text = secretPatterns[2].ReplaceAllString(text, "${1} [redacted]")
	if len(text) > maxErrorLength {
		text = text[:maxErrorLength] + "…"
	}
	return text
}

// EnrichmentResult is everything one vulnerability lookup produces for a
// scan, written in one transaction.
type EnrichmentResult struct {
	ScanID     int64
	Findings   []osv.Finding
	Checked    int
	Skipped    int
	Assessment risk.Assessment
	// RiskDelta is the change from the base scan's score; nil when the base
	// scan has no score to compare with.
	RiskDelta *float64
	// DriftRisk is the score change attributed to each drift event, by id.
	DriftRisk map[int64]float64
}

// SaveEnrichment replaces a scan's findings and records its score. A
// finding for a component the scan does not have is an error: findings are
// derived from the scan's own components.
func (db *DB) SaveEnrichment(ctx context.Context, result EnrichmentResult) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin enrichment tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	componentIDs := map[string]int64{}
	rows, err := tx.Query(ctx, `SELECT id, purl FROM components WHERE scan_id = $1`, result.ScanID)
	if err != nil {
		return fmt.Errorf("load components for enrichment: %w", err)
	}
	for rows.Next() {
		var id int64
		var purl string
		if err := rows.Scan(&id, &purl); err != nil {
			rows.Close()
			return fmt.Errorf("scan component id: %w", err)
		}
		componentIDs[purl] = id
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate components: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		DELETE FROM vulnerabilities v USING components c
		WHERE v.component_id = c.id AND c.scan_id = $1`, result.ScanID); err != nil {
		return fmt.Errorf("clear vulnerabilities: %w", err)
	}

	if len(result.Findings) > 0 {
		copyRows := make([][]any, 0, len(result.Findings))
		seen := map[[2]any]bool{}
		for _, f := range result.Findings {
			componentID, ok := componentIDs[f.PURL]
			if !ok {
				return fmt.Errorf("finding %s names component %s, which scan %d does not have", f.OSVID, f.PURL, result.ScanID)
			}
			key := [2]any{componentID, f.OSVID}
			if seen[key] {
				continue
			}
			seen[key] = true
			aliases := f.Aliases
			if aliases == nil {
				aliases = []string{}
			}
			fixed := f.FixedVersions
			if fixed == nil {
				fixed = []string{}
			}
			copyRows = append(copyRows, []any{
				componentID, f.OSVID, aliases, nullIfEmpty(f.Severity), f.CVSSScore, nullIfEmpty(f.CVSSVector),
				nullIfEmpty(f.Summary), nullIfEmpty(f.FixedVersion), f.Published, f.Identity, fixed,
				nullIfEmpty(f.SeveritySource), nullIfEmpty(f.AdvisoryURL), f.Modified,
			})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"vulnerabilities"},
			[]string{"component_id", "osv_id", "aliases", "severity", "cvss_score", "cvss_vector", "summary",
				"fixed_version", "published_at", "package_identity", "fixed_versions", "severity_source",
				"advisory_url", "modified_at"},
			pgx.CopyFromRows(copyRows)); err != nil {
			return fmt.Errorf("copy vulnerabilities: %w", err)
		}
	}

	if _, err := tx.Exec(ctx, `UPDATE drift_events SET risk_delta = 0 WHERE scan_id = $1`, result.ScanID); err != nil {
		return fmt.Errorf("reset drift risk: %w", err)
	}
	for id, delta := range result.DriftRisk {
		if _, err := tx.Exec(ctx, `UPDATE drift_events SET risk_delta = $3 WHERE id = $1 AND scan_id = $2`,
			id, result.ScanID, delta); err != nil {
			return fmt.Errorf("record drift risk: %w", err)
		}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE scans
		SET enriched_at = now(), enrichment_attempted_at = now(), enrichment_error = NULL,
		    vuln_components_checked = $2, vuln_components_skipped = $3,
		    risk_score = $4, risk_level = $5, risk_delta = $6
		WHERE id = $1`,
		result.ScanID, result.Checked, result.Skipped, result.Assessment.Score, result.Assessment.Level,
		result.RiskDelta); err != nil {
		return fmt.Errorf("record enrichment: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit enrichment: %w", err)
	}
	return nil
}

// RecordEnrichmentFailure notes why a lookup failed. Findings from an
// earlier successful lookup, if any, are kept.
func (db *DB) RecordEnrichmentFailure(ctx context.Context, scanID int64, cause string) error {
	if _, err := db.pool.Exec(ctx, `
		UPDATE scans SET enrichment_error = $2, enrichment_attempted_at = now() WHERE id = $1`,
		scanID, RedactSecrets(cause)); err != nil {
		return fmt.Errorf("record enrichment failure: %w", err)
	}
	return nil
}

// ScansNeedingEnrichment returns completed scans never enriched, newest
// first. Backfilled base scans are included: a pull request's comparison
// needs its base enriched too.
func (db *DB) ScansNeedingEnrichment(ctx context.Context, limit int) ([]int64, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id FROM scans
		WHERE status = 'completed' AND enriched_at IS NULL
		ORDER BY created_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list scans needing enrichment: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// ScanFindings returns a scan's findings in the shape the risk model reads.
func (db *DB) ScanFindings(ctx context.Context, scanID int64) ([]risk.Finding, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT v.osv_id, c.name, c.version, v.package_identity, COALESCE(v.severity, ''), c.direct,
		       COALESCE(v.fixed_version, ''), c.purl
		FROM vulnerabilities v JOIN components c ON c.id = v.component_id
		WHERE c.scan_id = $1
		ORDER BY c.purl, v.osv_id`, scanID)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()
	out := make([]risk.Finding, 0)
	for rows.Next() {
		var f risk.Finding
		if err := rows.Scan(&f.OSVID, &f.Package, &f.Version, &f.Identity, &f.Severity, &f.Direct,
			&f.FixedVersion, &f.PURL); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListVulnerabilities returns the advisories affecting a scan's components,
// most severe first.
func (db *DB) ListVulnerabilities(ctx context.Context, scanID int64) ([]models.Vulnerability, error) {
	const query = `
		SELECT v.id, v.component_id, v.osv_id, v.aliases, COALESCE(v.severity, ''), v.cvss_score,
		       COALESCE(v.cvss_vector, ''), COALESCE(v.summary, ''), COALESCE(v.fixed_version, ''),
		       v.published_at, v.fixed_versions, COALESCE(v.severity_source, ''), COALESCE(v.advisory_url, ''),
		       v.modified_at, v.package_identity, c.purl, c.name, c.version, c.ecosystem, c.direct
		FROM vulnerabilities v
		JOIN components c ON c.id = v.component_id
		WHERE c.scan_id = $1
		ORDER BY CASE upper(COALESCE(v.severity, ''))
		             WHEN 'CRITICAL' THEN 1
		             WHEN 'HIGH'     THEN 2
		             WHEN 'MODERATE' THEN 3
		             WHEN 'MEDIUM'   THEN 3
		             WHEN 'LOW'      THEN 4
		             ELSE 5
		         END,
		         v.cvss_score DESC NULLS LAST, c.name, v.osv_id`

	rows, err := db.pool.Query(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("list vulnerabilities: %w", err)
	}
	defer rows.Close()

	vulnerabilities := make([]models.Vulnerability, 0)
	for rows.Next() {
		var v models.Vulnerability
		if err := rows.Scan(&v.ID, &v.ComponentID, &v.OSVID, &v.Aliases, &v.Severity, &v.CVSSScore,
			&v.CVSSVector, &v.Summary, &v.FixedVersion, &v.PublishedAt, &v.FixedVersions, &v.SeveritySource,
			&v.AdvisoryURL, &v.ModifiedAt, &v.PackageIdentity, &v.PURL, &v.Name, &v.Version, &v.Ecosystem,
			&v.Direct); err != nil {
			return nil, fmt.Errorf("scan vulnerability: %w", err)
		}
		v.Remediation = models.Remediation(v.Name, v.Version, v.FixedVersion, v.FixedVersions)
		vulnerabilities = append(vulnerabilities, v)
	}
	return vulnerabilities, rows.Err()
}

// scanInsight is what a list shows about a scan beyond its own row.
type scanInsight struct {
	baseline                bool
	added, updated, removed int
	vulnerabilities         *models.VulnerabilitySummary
	risk                    *models.RiskSummary
}

// scanInsights loads drift counts, vulnerability counts, the comparison with
// the base scan, and risk for a set of scans, in one query.
func (db *DB) scanInsights(ctx context.Context, ids []int64) (map[int64]scanInsight, error) {
	out := make(map[int64]scanInsight, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	const query = `
		SELECT s.id, s.status, s.base_scan_id IS NULL, s.enriched_at, COALESCE(s.enrichment_error, ''),
		       s.risk_score, COALESCE(s.risk_level, ''), s.risk_delta,
		       s.vuln_components_checked, s.vuln_components_skipped,
		       COALESCE(d.added, 0), COALESCE(d.updated, 0), COALESCE(d.removed, 0),
		       COALESCE(v.total, 0), COALESCE(v.critical, 0), COALESCE(v.high, 0), COALESCE(v.medium, 0),
		       COALESCE(v.low, 0), COALESCE(v.unrated, 0), COALESCE(v.fixable, 0),
		       cmp.introduced, cmp.resolved
		FROM scans s
		LEFT JOIN scans b ON b.id = s.base_scan_id
		LEFT JOIN LATERAL (
			SELECT COUNT(*) FILTER (WHERE change_type = 'added')   AS added,
			       COUNT(*) FILTER (WHERE change_type = 'updated') AS updated,
			       COUNT(*) FILTER (WHERE change_type = 'removed') AS removed
			FROM drift_events WHERE scan_id = s.id) d ON true
		LEFT JOIN LATERAL (
			SELECT COUNT(*) AS total,
			       COUNT(*) FILTER (WHERE vv.severity = 'CRITICAL') AS critical,
			       COUNT(*) FILTER (WHERE vv.severity = 'HIGH')     AS high,
			       COUNT(*) FILTER (WHERE vv.severity = 'MEDIUM')   AS medium,
			       COUNT(*) FILTER (WHERE vv.severity = 'LOW')      AS low,
			       COUNT(*) FILTER (WHERE vv.severity IS NULL
			                           OR vv.severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')) AS unrated,
			       COUNT(*) FILTER (WHERE COALESCE(vv.fixed_version, '') <> '') AS fixable
			FROM vulnerabilities vv JOIN components cc ON cc.id = vv.component_id
			WHERE cc.scan_id = s.id) v ON s.enriched_at IS NOT NULL
		LEFT JOIN LATERAL (
			SELECT
			  (SELECT COUNT(*) FROM (
			      SELECT vv.package_identity, vv.osv_id FROM vulnerabilities vv
			      JOIN components cc ON cc.id = vv.component_id WHERE cc.scan_id = s.id
			      EXCEPT
			      SELECT vv.package_identity, vv.osv_id FROM vulnerabilities vv
			      JOIN components cc ON cc.id = vv.component_id WHERE cc.scan_id = b.id) x) AS introduced,
			  (SELECT COUNT(*) FROM (
			      SELECT vv.package_identity, vv.osv_id FROM vulnerabilities vv
			      JOIN components cc ON cc.id = vv.component_id WHERE cc.scan_id = b.id
			      EXCEPT
			      SELECT vv.package_identity, vv.osv_id FROM vulnerabilities vv
			      JOIN components cc ON cc.id = vv.component_id WHERE cc.scan_id = s.id) y) AS resolved
		) cmp ON s.enriched_at IS NOT NULL AND b.enriched_at IS NOT NULL
		WHERE s.id = ANY($1)`

	rows, err := db.pool.Query(ctx, query, ids)
	if err != nil {
		return nil, fmt.Errorf("load scan insights: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id                 int64
			status             models.ScanStatus
			insight            scanInsight
			enrichedAt         *time.Time
			enrichmentError    string
			score, delta       *float64
			level              string
			checked, skipped   *int
			summary            models.VulnerabilitySummary
			introduced, solved *int
		)
		if err := rows.Scan(&id, &status, &insight.baseline, &enrichedAt, &enrichmentError, &score, &level, &delta,
			&checked, &skipped, &insight.added, &insight.updated, &insight.removed,
			&summary.Total, &summary.Critical, &summary.High, &summary.Medium, &summary.Low, &summary.Unrated,
			&summary.Fixable, &introduced, &solved); err != nil {
			return nil, fmt.Errorf("scan insight: %w", err)
		}
		if status == models.ScanCompleted {
			switch {
			case enrichedAt != nil:
				summary.Status = models.VulnStatusAnalyzed
				summary.AnalyzedAt = enrichedAt
				summary.Introduced, summary.Resolved = introduced, solved
				summary.ComponentsChecked, summary.ComponentsSkipped = checked, skipped
				insight.risk = &models.RiskSummary{Score: score, Level: level, Delta: delta}
			case enrichmentError != "":
				summary = models.VulnerabilitySummary{Status: models.VulnStatusFailed, Error: RedactSecrets(enrichmentError)}
			default:
				summary = models.VulnerabilitySummary{Status: models.VulnStatusPending}
			}
			if enrichedAt != nil && enrichmentError != "" {
				// An earlier lookup succeeded; a later refresh did not. The
				// counts stand, with the refresh failure alongside.
				summary.Error = RedactSecrets(enrichmentError)
			}
			insight.vulnerabilities = &summary
		}
		out[id] = insight
	}
	return out, rows.Err()
}

// attachInsights fills in Vulnerabilities and Risk on each summary.
func (db *DB) attachInsights(ctx context.Context, summaries ...*models.ScanSummary) error {
	var ids []int64
	for _, s := range summaries {
		if s != nil {
			ids = append(ids, s.ID)
		}
	}
	insights, err := db.scanInsights(ctx, ids)
	if err != nil {
		return err
	}
	for _, s := range summaries {
		if s == nil {
			continue
		}
		insight := insights[s.ID]
		s.Vulnerabilities = insight.vulnerabilities
		s.Risk = insight.risk
	}
	return nil
}

// ScanVulnerabilitySummary is the summary for one scan.
func (db *DB) ScanVulnerabilitySummary(ctx context.Context, scanID int64) (*models.VulnerabilitySummary, error) {
	insights, err := db.scanInsights(ctx, []int64{scanID})
	if err != nil {
		return nil, err
	}
	return insights[scanID].vulnerabilities, nil
}

// attachPullRequestInsights fills in each pull request's vulnerability
// comparison and risk from its latest scan.
func (db *DB) attachPullRequestInsights(ctx context.Context, pulls ...*models.PullRequestSummary) error {
	var ids []int64
	for _, pull := range pulls {
		if pull.ScanID != nil {
			ids = append(ids, *pull.ScanID)
		}
	}
	insights, err := db.scanInsights(ctx, ids)
	if err != nil {
		return err
	}
	for _, pull := range pulls {
		if pull.ScanID == nil {
			continue
		}
		insight := insights[*pull.ScanID]
		pull.Vulnerabilities = insight.vulnerabilities
		if insight.risk != nil {
			pull.RiskScore = insight.risk.Score
			pull.RiskLevel = insight.risk.Level
		}
	}
	return nil
}
