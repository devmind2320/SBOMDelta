package storage_test

import (
	"context"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"sbomdelta/internal/diff"
	"sbomdelta/internal/models"
	"sbomdelta/internal/osv"
	"sbomdelta/internal/risk"
	"sbomdelta/internal/sbom"
	"sbomdelta/internal/storage"
	"sbomdelta/migrations"
)

// TestMigration0008VulnerabilityIntelligence upgrades a database at 0007
// that already holds a scan and a vulnerability row written before 0008,
// then rolls 0008 back. Existing rows keep their data and get the new
// columns' defaults; rolling back removes exactly what 0008 added.
func TestMigration0008VulnerabilityIntelligence(t *testing.T) {
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping database integration tests")
	}
	ctx := context.Background()
	const schema = "test_migration_0008"

	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE; CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	parsed, _ := url.Parse(base)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, err := storage.Open(ctx, parsed.String())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()
	pool := db.Pool()

	if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations (
		version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	for _, version := range []string{
		"0001_init.up.sql", "0002_enrichment_state.up.sql", "0003_manual_repositories.up.sql",
		"0004_repository_access.up.sql", "0005_initial_scan_trigger.up.sql", "0006_users_sessions.up.sql",
		"0007_user_repositories.up.sql",
	} {
		sql, err := migrations.FS.ReadFile(version)
		if err != nil {
			t.Fatalf("read %s: %v", version, err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("apply %s: %v", version, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			t.Fatalf("record %s: %v", version, err)
		}
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO repositories (id, github_repo_id, owner, name) VALUES (1, 1001, 'acme', 'api');
		INSERT INTO scans (id, repository_id, commit_sha, trigger, status, component_count, finished_at)
			VALUES (1, 1, 'abc', 'push', 'completed', 1, now());
		INSERT INTO components (id, scan_id, purl, name, version, ecosystem) VALUES (1, 1, 'pkg:npm/lodash@4.17.20', 'lodash', '4.17.20', 'npm');
		INSERT INTO vulnerabilities (component_id, osv_id, severity, fixed_version) VALUES (1, 'GHSA-old', 'HIGH', '4.17.21');
	`); err != nil {
		t.Fatalf("seed 0007 data: %v", err)
	}

	if err := db.Migrate(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	scan, err := db.GetScan(ctx, 1)
	if err != nil {
		t.Fatalf("GetScan after 0008: %v", err)
	}
	if scan.EnrichedAt != nil || scan.EnrichmentError != "" || scan.RiskLevel != "" || scan.VulnComponentsChecked != nil {
		t.Errorf("an existing scan must come out unanalyzed, got %+v", scan)
	}
	vulns, err := db.ListVulnerabilities(ctx, 1)
	if err != nil || len(vulns) != 1 {
		t.Fatalf("ListVulnerabilities after 0008 = %v, %v", vulns, err)
	}
	if vulns[0].OSVID != "GHSA-old" || vulns[0].PackageIdentity != "" || vulns[0].FixedVersions == nil || len(vulns[0].FixedVersions) != 0 {
		t.Errorf("existing vulnerability after 0008 = %+v", vulns[0])
	}
	ids, err := db.ScansNeedingEnrichment(ctx, 10)
	if err != nil || len(ids) != 1 || ids[0] != 1 {
		t.Errorf("ScansNeedingEnrichment = %v, %v; want the existing scan", ids, err)
	}

	down, err := migrations.FS.ReadFile("0008_vulnerability_intelligence.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("apply down migration: %v", err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema = $1 AND (
		      (table_name = 'scans' AND column_name IN ('enrichment_error', 'enrichment_attempted_at',
		           'vuln_components_checked', 'vuln_components_skipped', 'risk_level'))
		   OR (table_name = 'vulnerabilities' AND column_name IN ('package_identity', 'fixed_versions',
		           'severity_source', 'advisory_url', 'modified_at')))`, schema).Scan(&remaining); err != nil || remaining != 0 {
		t.Errorf("0008 columns after rolling back = %d (err %v), want 0", remaining, err)
	}
	var osvID, fixed string
	if err := pool.QueryRow(ctx, `SELECT osv_id, fixed_version FROM vulnerabilities`).Scan(&osvID, &fixed); err != nil ||
		osvID != "GHSA-old" || fixed != "4.17.21" {
		t.Errorf("rolling back 0008 lost vulnerability data: %q %q %v", osvID, fixed, err)
	}
}

func finding(purl, id, severity, fixed string) osv.Finding {
	identity, _, _, _ := sbom.ParseIdentity(purl)
	f := osv.Finding{PURL: purl, Identity: identity, OSVID: id, Severity: severity, Aliases: []string{"CVE-" + id},
		AdvisoryURL: "https://osv.dev/vulnerability/" + id}
	if fixed != "" {
		f.FixedVersion = fixed
		f.FixedVersions = []string{fixed}
	}
	return f
}

func riskFindings(findings []osv.Finding) []risk.Finding {
	out := make([]risk.Finding, 0, len(findings))
	for _, f := range findings {
		out = append(out, risk.Finding{OSVID: f.OSVID, Identity: f.Identity, PURL: f.PURL, Severity: f.Severity, FixedVersion: f.FixedVersion})
	}
	return out
}

// completedScan stores a scan with its components and its diff against base.
func completedScan(t *testing.T, db *storage.DB, repoID int64, sha string, base *models.Scan, purls ...string) models.Scan {
	t.Helper()
	ctx := context.Background()
	scan, err := db.CreateScan(ctx, models.Scan{RepositoryID: repoID, CommitSHA: sha, Trigger: models.TriggerPush})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	var components []sbom.Component
	for _, purl := range purls {
		components = append(components, component(purl))
	}
	result := storage.ScanResult{ScanID: scan.ID, Components: components}
	if base != nil {
		baseComponents, err := db.ListComponents(ctx, base.ID)
		if err != nil {
			t.Fatal(err)
		}
		result.BaseScanID = &base.ID
		result.Diff = diff.Compare(baseComponents, components)
	}
	if err := db.SaveScanResult(ctx, result); err != nil {
		t.Fatalf("SaveScanResult() error = %v", err)
	}
	scan, err = db.GetScan(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	return scan
}

func enrich(t *testing.T, db *storage.DB, scanID int64, findings []osv.Finding, delta *float64, drift map[int64]float64) risk.Assessment {
	t.Helper()
	assessment := risk.Assess(riskFindings(findings))
	if err := db.SaveEnrichment(context.Background(), storage.EnrichmentResult{
		ScanID: scanID, Findings: findings, Checked: 3, Skipped: 1, Assessment: assessment, RiskDelta: delta, DriftRisk: drift,
	}); err != nil {
		t.Fatalf("SaveEnrichment() error = %v", err)
	}
	return assessment
}

// Findings are stored per component with their fixes, the scan gets its
// score, the comparison with the base scan follows advisories across
// versions, and enriching again replaces rather than duplicates.
func TestEnrichmentIsPersistedScoredAndCompared(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	base := completedScan(t, db, repo.ID, "base", nil, "pkg:npm/lodash@4.17.20", "pkg:npm/qs@6.5.0")
	if summary, err := db.ScanVulnerabilitySummary(ctx, base.ID); err != nil || summary.Status != models.VulnStatusPending {
		t.Fatalf("summary before enrichment = %+v, %v; want pending", summary, err)
	}
	if err := db.RecordEnrichmentFailure(ctx, base.ID, "OSV POST /v1/querybatch returned HTTP 503"); err != nil {
		t.Fatal(err)
	}
	summary, err := db.ScanVulnerabilitySummary(ctx, base.ID)
	if err != nil || summary.Status != models.VulnStatusFailed || !strings.Contains(summary.Error, "HTTP 503") || summary.Total != 0 {
		t.Fatalf("summary after a failed lookup = %+v, %v; want failed with the reason and no counts", summary, err)
	}

	enrich(t, db, base.ID, []osv.Finding{
		finding("pkg:npm/lodash@4.17.20", "GHSA-lodash", "HIGH", "4.17.21"),
		finding("pkg:npm/qs@6.5.0", "GHSA-qs", "MEDIUM", ""),
	}, nil, nil)

	head := completedScan(t, db, repo.ID, "head", &base, "pkg:npm/lodash@4.17.21", "pkg:npm/qs@6.5.1", "pkg:npm/evil@1.0.0")
	events, err := db.ListDriftEvents(ctx, head.ID)
	if err != nil || len(events) != 3 {
		t.Fatalf("drift events = %d, %v", len(events), err)
	}
	drift := map[int64]float64{}
	for _, e := range events {
		if e.Name == "evil" {
			drift[e.ID] = 10
		}
	}
	delta := 1.0
	headFindings := []osv.Finding{
		finding("pkg:npm/qs@6.5.1", "GHSA-qs", "MEDIUM", ""), // still affected after the bump: unchanged
		finding("pkg:npm/evil@1.0.0", "GHSA-evil", "CRITICAL", ""),
	}
	enrich(t, db, head.ID, headFindings, &delta, drift)
	// Enriching again replaces the findings rather than adding to them.
	assessment := enrich(t, db, head.ID, headFindings, &delta, drift)

	scan, err := db.GetScan(ctx, head.ID)
	if err != nil {
		t.Fatal(err)
	}
	if scan.EnrichedAt == nil || scan.EnrichmentError != "" || scan.RiskScore == nil || *scan.RiskScore != assessment.Score ||
		scan.RiskLevel != assessment.Level || scan.RiskDelta == nil || *scan.RiskDelta != 1 {
		t.Errorf("scan after enrichment = %+v", scan)
	}
	if scan.VulnComponentsChecked == nil || *scan.VulnComponentsChecked != 3 || *scan.VulnComponentsSkipped != 1 {
		t.Errorf("coverage = %v/%v, want 3/1", scan.VulnComponentsChecked, scan.VulnComponentsSkipped)
	}

	vulns, err := db.ListVulnerabilities(ctx, head.ID)
	if err != nil || len(vulns) != 2 {
		t.Fatalf("ListVulnerabilities = %d, %v; want 2", len(vulns), err)
	}
	if vulns[0].OSVID != "GHSA-evil" || vulns[0].PackageIdentity != "pkg:npm/evil" || !strings.Contains(vulns[0].Remediation, "No fixed version") {
		t.Errorf("most severe first, with remediation: %+v", vulns[0])
	}

	summary, err = db.ScanVulnerabilitySummary(ctx, head.ID)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Status != models.VulnStatusAnalyzed || summary.Total != 2 || summary.Critical != 1 || summary.Medium != 1 ||
		summary.Introduced == nil || *summary.Introduced != 1 || summary.Resolved == nil || *summary.Resolved != 1 {
		t.Errorf("head summary = %+v (introduced %v resolved %v), want evil introduced and lodash resolved",
			summary, deref(summary.Introduced), deref(summary.Resolved))
	}

	findings, err := db.ScanFindings(ctx, head.ID)
	if err != nil || len(findings) != 2 {
		t.Fatalf("ScanFindings = %v, %v", findings, err)
	}
	baseFindings, _ := db.ScanFindings(ctx, base.ID)
	comparison := risk.Compare(baseFindings, findings)
	if len(comparison.Introduced) != 1 || comparison.Introduced[0].OSVID != "GHSA-evil" || len(comparison.Resolved) != 1 || comparison.Unchanged != 1 {
		t.Errorf("comparison = %+v", comparison)
	}

	events, _ = db.ListDriftEvents(ctx, head.ID)
	for _, e := range events {
		want := 0.0
		if e.Name == "evil" {
			want = 10
		}
		if e.RiskDelta != want {
			t.Errorf("drift %s risk delta = %v, want %v", e.Name, e.RiskDelta, want)
		}
	}

	// A later refresh that fails keeps the stored findings and says so.
	if err := db.RecordEnrichmentFailure(ctx, head.ID, "clone https://x-access-token:ghs_abcdefghijklmnopqrstuvwxyz0123@github.com/acme/api.git"); err != nil {
		t.Fatal(err)
	}
	summary, _ = db.ScanVulnerabilitySummary(ctx, head.ID)
	if summary.Status != models.VulnStatusAnalyzed || summary.Total != 2 || summary.Error == "" {
		t.Errorf("summary after a failed refresh = %+v, want the old counts and the error", summary)
	}
	if strings.Contains(summary.Error, "ghs_") || strings.Contains(summary.Error, "x-access-token") {
		t.Errorf("a credential reached the summary: %q", summary.Error)
	}
}

func deref(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestSaveEnrichmentRejectsFindingsForOtherComponents(t *testing.T) {
	db := newTestDB(t)
	repo := seedRepository(t, db)
	scan := completedScan(t, db, repo.ID, "one", nil, "pkg:npm/lodash@4.17.20")
	err := db.SaveEnrichment(context.Background(), storage.EnrichmentResult{
		ScanID:     scan.ID,
		Findings:   []osv.Finding{finding("pkg:npm/other@1.0.0", "GHSA-x", "LOW", "")},
		Assessment: risk.Assess(nil),
	})
	if err == nil {
		t.Fatal("a finding for a component the scan does not have was stored")
	}
	if got, _ := db.GetScan(context.Background(), scan.ID); got.EnrichedAt != nil {
		t.Error("a rejected enrichment still marked the scan enriched")
	}
}

func TestRedactSecrets(t *testing.T) {
	cases := map[string]string{
		"git fetch failed: https://x-access-token:ghs_secretsecretsecretsecret12@github.com/a/b.git": "git fetch failed: https://[redacted]@github.com/a/b.git",
		"token ghp_abcdefghijklmnopqrstuvwxyz0123 leaked":                                            "token [redacted] leaked",
		"Authorization: Bearer abcdefghijklmnopqrstuvwxyz":                                           "Authorization: Bearer [redacted]",
		"plain failure": "plain failure",
	}
	for in, want := range cases {
		if got := storage.RedactSecrets(in); got != want {
			t.Errorf("RedactSecrets(%q) = %q, want %q", in, got, want)
		}
	}
	if got := storage.RedactSecrets(strings.Repeat("x", 5000)); len(got) > 2100 {
		t.Errorf("long error not truncated: %d bytes", len(got))
	}
}

// impactFixture makes three repositories the user can access, of which they
// track two, and one repository they cannot access, all shipping lodash.
func impactFixture(t *testing.T, db *storage.DB) (models.User, []models.Repository) {
	t.Helper()
	ctx := context.Background()
	installation, err := db.UpsertInstallation(ctx, models.Installation{GitHubInstallationID: 4242, AccountLogin: "acme", AccountType: "Organization"})
	if err != nil {
		t.Fatal(err)
	}
	var repos []models.Repository
	for i, name := range []string{"api", "web", "untracked", "hidden"} {
		githubID := int64(7000 + i)
		repo, err := db.UpsertRepository(ctx, models.Repository{InstallationID: &installation.ID, GitHubRepoID: &githubID,
			Owner: "acme", Name: name, DefaultBranch: "main"})
		if err != nil {
			t.Fatal(err)
		}
		repos = append(repos, repo)
	}
	user := seedUser(t, db, 501, "devmind2320")
	if err := db.ReplaceUserRepositories(ctx, user.ID, []models.AccessibleRepository{
		listedRepo(7000, "acme", "api"), listedRepo(7001, "acme", "web"), listedRepo(7002, "acme", "untracked"),
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, repo := range repos[:2] {
		if err := db.TrackRepository(ctx, user.ID, repo.ID); err != nil {
			t.Fatal(err)
		}
	}
	// Tracked once, then access was lost: it must drop out everywhere.
	if err := db.TrackRepository(ctx, user.ID, repos[3].ID); err != nil {
		t.Fatal(err)
	}
	return user, repos
}

func TestImpactCoversOnlyTrackedAccessibleRepositories(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	user, repos := impactFixture(t, db)

	api := completedScan(t, db, repos[0].ID, "a1", nil, "pkg:npm/lodash@4.17.20", "pkg:npm/express@4.0.0")
	enrich(t, db, api.ID, []osv.Finding{finding("pkg:npm/lodash@4.17.20", "GHSA-lodash", "HIGH", "4.17.21")}, nil, nil)
	web := completedScan(t, db, repos[1].ID, "w1", nil, "pkg:npm/lodash@4.17.19")
	enrich(t, db, web.ID, []osv.Finding{finding("pkg:npm/lodash@4.17.19", "GHSA-lodash", "HIGH", "4.17.21")}, nil, nil)
	for _, repo := range repos[2:] {
		s := completedScan(t, db, repo.ID, "x"+repo.Name, nil, "pkg:npm/lodash@4.17.20")
		enrich(t, db, s.ID, []osv.Finding{finding("pkg:npm/lodash@4.17.20", "GHSA-lodash", "HIGH", "4.17.21")}, nil, nil)
	}

	vulns, coverage, err := db.VulnerabilityImpact(ctx, user.ID, false, 50)
	if err != nil {
		t.Fatalf("VulnerabilityImpact() error = %v", err)
	}
	if coverage != (models.ImpactCoverage{Repositories: 2, Scanned: 2, Analyzed: 2}) {
		t.Errorf("coverage = %+v, want 2 tracked accessible repositories, both scanned and analyzed", coverage)
	}
	if len(vulns) != 1 || vulns[0].OSVID != "GHSA-lodash" || vulns[0].RepositoryCount != 2 || len(vulns[0].Occurrences) != 2 {
		t.Fatalf("impact = %+v, want GHSA-lodash in api and web only", vulns)
	}
	for _, o := range vulns[0].Occurrences {
		if o.RepositoryID != repos[0].ID && o.RepositoryID != repos[1].ID {
			t.Errorf("impact leaked repository %s", o.Name)
		}
	}

	components, _, err := db.ComponentImpact(ctx, user.ID, false, "LODASH", 50)
	if err != nil {
		t.Fatalf("ComponentImpact() error = %v", err)
	}
	if len(components) != 1 || components[0].Identity != "pkg:npm/lodash" || components[0].RepositoryCount != 2 ||
		len(components[0].Versions) != 2 {
		t.Fatalf("component impact = %+v, want lodash in 2 repositories at 2 versions", components)
	}
	if components[0].Occurrences[0].Vulnerabilities != 1 || !components[0].Occurrences[0].Analyzed {
		t.Errorf("occurrence = %+v, want 1 vulnerability on an analyzed scan", components[0].Occurrences[0])
	}

	stranger := seedUser(t, db, 502, "someone-else")
	if vulns, coverage, err := db.VulnerabilityImpact(ctx, stranger.ID, false, 50); err != nil || len(vulns) != 0 || coverage.Repositories != 0 {
		t.Errorf("a user with no access saw %d advisories over %d repositories (err %v)", len(vulns), coverage.Repositories, err)
	}

	// Sign-in disabled for development: every active repository.
	if _, coverage, err := db.VulnerabilityImpact(ctx, 0, true, 50); err != nil || coverage.Repositories != 4 {
		t.Errorf("development coverage = %+v, %v; want all 4 repositories", coverage, err)
	}
}

func TestRecentScansAndTrackedListCarryInsightsWithinAccess(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	user, repos := impactFixture(t, db)

	first := completedScan(t, db, repos[0].ID, "a1", nil, "pkg:npm/lodash@4.17.20")
	enrich(t, db, first.ID, []osv.Finding{finding("pkg:npm/lodash@4.17.20", "GHSA-lodash", "HIGH", "4.17.21")}, nil, nil)
	second := completedScan(t, db, repos[0].ID, "a2", &first, "pkg:npm/lodash@4.17.21", "pkg:npm/left-pad@1.0.0")
	enrich(t, db, second.ID, nil, nil, nil)
	if _, err := db.CreateScan(ctx, models.Scan{RepositoryID: repos[0].ID, CommitSHA: "base-only", Trigger: models.TriggerBackfill}); err != nil {
		t.Fatal(err)
	}
	completedScan(t, db, repos[3].ID, "hidden1", nil, "pkg:npm/lodash@4.17.20")
	completedScan(t, db, repos[2].ID, "untracked1", nil, "pkg:npm/lodash@4.17.20")

	scans, err := db.ListRecentScans(ctx, user.ID, false, 0, 20)
	if err != nil {
		t.Fatalf("ListRecentScans() error = %v", err)
	}
	if len(scans) != 2 || scans[0].ID != second.ID || scans[1].ID != first.ID {
		t.Fatalf("recent scans = %+v, want the two api scans newest first (no backfill, no untracked or hidden repos)", scans)
	}
	latest := scans[0]
	if latest.Owner != "acme" || latest.Name != "api" || latest.Added != 1 || latest.Updated != 1 || latest.Baseline {
		t.Errorf("latest = %+v", latest)
	}
	if latest.Vulnerabilities == nil || latest.Vulnerabilities.Status != models.VulnStatusAnalyzed || latest.Vulnerabilities.Total != 0 ||
		latest.Vulnerabilities.Resolved == nil || *latest.Vulnerabilities.Resolved != 1 || latest.Risk == nil || latest.Risk.Score == nil || *latest.Risk.Score != 0 {
		t.Errorf("latest insights = %+v / %+v, want analyzed, 0 open, 1 resolved, score 0", latest.Vulnerabilities, latest.Risk)
	}
	if !scans[1].Baseline {
		t.Error("the first scan is a baseline")
	}

	if only, err := db.ListRecentScans(ctx, user.ID, false, repos[1].ID, 20); err != nil || len(only) != 0 {
		t.Errorf("filtered to web = %v, %v; want none", only, err)
	}

	tracked, err := db.ListTrackedRepositories(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListTrackedRepositories() error = %v", err)
	}
	if len(tracked) != 2 {
		t.Fatalf("tracked = %d, want 2 (the inaccessible one is left out)", len(tracked))
	}
	for _, repo := range tracked {
		if repo.ID != repos[0].ID {
			continue
		}
		if repo.LastCompletedScan == nil || repo.LastCompletedScan.Vulnerabilities == nil || repo.LastCompletedScan.Risk == nil ||
			repo.LastCompletedScan.Risk.Level != risk.LevelNone {
			t.Errorf("tracked api = %+v", repo.LastCompletedScan)
		}
	}

	page, total, err := db.ListUserRepositories(ctx, user.ID, "", true, 10, 0)
	if err != nil {
		t.Fatalf("ListUserRepositories() error = %v", err)
	}
	if total != 1 || len(page) != 1 || page[0].Name != "untracked" || page[0].Tracked {
		t.Errorf("untracked only = %+v (total %d), want just the untracked repository", page, total)
	}
	if _, total, _ := db.ListUserRepositories(ctx, user.ID, "", false, 10, 0); total != 3 {
		t.Errorf("all repositories total = %d, want 3", total)
	}
	if tracked, err := db.IsTracked(ctx, user.ID, repos[2].ID); err != nil || tracked {
		t.Errorf("IsTracked(untracked) = %v, %v", tracked, err)
	}
}
