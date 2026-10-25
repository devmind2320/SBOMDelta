package scanner

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"sbomdelta/internal/config"
	"sbomdelta/internal/diff"
	"sbomdelta/internal/models"
	"sbomdelta/internal/osv"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/risk"
	"sbomdelta/internal/sbom"
	"sbomdelta/internal/storage"
	"sbomdelta/internal/storage/storagetest"
)

// fakeChecker answers from a fixed table of findings per package URL, or
// fails every call when err is set. It records which scans' components it
// was asked about, in order.
type fakeChecker struct {
	byPURL map[string][]osv.Finding
	err    error
	calls  [][]string
}

func (f *fakeChecker) Check(_ context.Context, components []sbom.Component) (osv.Report, error) {
	var purls []string
	for _, c := range components {
		purls = append(purls, c.PURL)
	}
	f.calls = append(f.calls, purls)
	if f.err != nil {
		return osv.Report{}, f.err
	}
	report := osv.Report{Checked: len(components)}
	for _, c := range components {
		report.Findings = append(report.Findings, f.byPURL[c.PURL]...)
	}
	return report, nil
}

func testComponent(purl string, direct bool) sbom.Component {
	identity, version, ecosystem, name := sbom.ParseIdentity(purl)
	return sbom.Component{PURL: purl, Identity: identity, Name: name, Version: version, Ecosystem: ecosystem, Direct: direct}
}

func osvFinding(purl, id, severity, fixed string) osv.Finding {
	identity, _, _, _ := sbom.ParseIdentity(purl)
	return osv.Finding{PURL: purl, Identity: identity, OSVID: id, Severity: severity, FixedVersion: fixed, Aliases: []string{}}
}

type fixture struct {
	db   *storage.DB
	repo models.Repository
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	db := storagetest.Open(t, "test_scanner")
	ctx := context.Background()
	installation, err := db.UpsertInstallation(ctx, models.Installation{GitHubInstallationID: 4242, AccountLogin: "acme", AccountType: "Organization"})
	if err != nil {
		t.Fatal(err)
	}
	githubID := int64(99001)
	repo, err := db.UpsertRepository(ctx, models.Repository{InstallationID: &installation.ID, GitHubRepoID: &githubID,
		Owner: "acme", Name: "api", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{db: db, repo: repo}
}

func (f fixture) scan(t *testing.T, sha string, base *models.Scan, components ...sbom.Component) models.Scan {
	t.Helper()
	ctx := context.Background()
	scan, err := f.db.CreateScan(ctx, models.Scan{RepositoryID: f.repo.ID, CommitSHA: sha, Trigger: models.TriggerPush})
	if err != nil {
		t.Fatal(err)
	}
	result := storage.ScanResult{ScanID: scan.ID, Components: components}
	if base != nil {
		baseComponents, err := f.db.ListComponents(ctx, base.ID)
		if err != nil {
			t.Fatal(err)
		}
		result.BaseScanID = &base.ID
		result.Diff = diff.Compare(baseComponents, components)
	}
	if err := f.db.SaveScanResult(ctx, result); err != nil {
		t.Fatal(err)
	}
	scan, err = f.db.GetScan(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	return scan
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// A scan whose base was never checked gets its base checked first, then is
// scored, compared and given per-change risk, all from real findings.
func TestEnrichChecksTheBaseFirstAndScoresTheChange(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	checker := &fakeChecker{byPURL: map[string][]osv.Finding{
		"pkg:npm/lodash@4.17.20": {osvFinding("pkg:npm/lodash@4.17.20", "GHSA-lodash", "HIGH", "4.17.21")},
		"pkg:npm/evil@1.0.0":     {osvFinding("pkg:npm/evil@1.0.0", "GHSA-evil", "CRITICAL", "")},
	}}
	jobs := queue.New(f.db.Pool(), time.Minute)
	s := New(f.db, nil, nil, nil, checker, jobs, config.Scanner{}, quiet())

	base := f.scan(t, "base", nil, testComponent("pkg:npm/lodash@4.17.20", true))
	head := f.scan(t, "head", &base, testComponent("pkg:npm/lodash@4.17.21", true), testComponent("pkg:npm/evil@1.0.0", true))

	if err := s.Enrich(ctx, head.ID); err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}
	if len(checker.calls) != 2 || checker.calls[0][0] != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("checker calls = %v, want the base scan first, then the head", checker.calls)
	}

	gotBase, _ := f.db.GetScan(ctx, base.ID)
	gotHead, _ := f.db.GetScan(ctx, head.ID)
	// base: one high on a direct dependency = 6 * 1.5 = 9. head: one critical direct = 15.
	if gotBase.RiskScore == nil || *gotBase.RiskScore != 9 || gotBase.RiskLevel != risk.LevelLow {
		t.Errorf("base risk = %v %q, want 9 low", gotBase.RiskScore, gotBase.RiskLevel)
	}
	if gotHead.RiskScore == nil || *gotHead.RiskScore != 15 || gotHead.RiskLevel != risk.LevelMedium ||
		gotHead.RiskDelta == nil || *gotHead.RiskDelta != 6 {
		t.Errorf("head risk = %v %q delta %v, want 15 medium +6", gotHead.RiskScore, gotHead.RiskLevel, gotHead.RiskDelta)
	}

	events, _ := f.db.ListDriftEvents(ctx, head.ID)
	byName := map[string]float64{}
	for _, e := range events {
		byName[e.Name] = e.RiskDelta
	}
	if byName["evil"] != 15 || byName["lodash"] != -9 {
		t.Errorf("drift risk = %v, want evil +15 and lodash -9", byName)
	}

	report, err := BuildCheckReport(ctx, f.db, head.ID)
	if err != nil {
		t.Fatalf("BuildCheckReport() error = %v", err)
	}
	if !report.Vulns.Available || report.Vulns.Comparison == nil || len(report.Vulns.Comparison.Introduced) != 1 ||
		len(report.Vulns.Comparison.Resolved) != 1 || len(report.Added) != 1 || len(report.Updated) != 1 {
		t.Fatalf("check report = %+v", report)
	}
	if report.Conclusion() != "failure" {
		t.Errorf("conclusion = %q, want failure for an introduced critical", report.Conclusion())
	}
}

// When OSV cannot be reached, the scan keeps its dependency results, records
// why its vulnerabilities are unknown, and a retry is queued once.
func TestEnrichFailureIsRecordedAndRetried(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	checker := &fakeChecker{err: &osv.Error{Status: 503, Message: "OSV POST /v1/querybatch returned HTTP 503"}}
	jobs := queue.New(f.db.Pool(), time.Minute)
	s := New(f.db, nil, nil, nil, checker, jobs, config.Scanner{}, quiet())

	scan := f.scan(t, "one", nil, testComponent("pkg:npm/lodash@4.17.20", false))
	s.enrichAfterScan(ctx, quiet(), scan.ID)
	s.enrichAfterScan(ctx, quiet(), scan.ID)

	got, _ := f.db.GetScan(ctx, scan.ID)
	if got.Status != models.ScanCompleted || got.EnrichedAt != nil || !strings.Contains(got.EnrichmentError, "HTTP 503") || got.RiskScore != nil {
		t.Errorf("scan after a failed lookup = %+v; want completed, unanalyzed, the reason recorded, no score", got)
	}
	var queued int
	if err := f.db.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM jobs WHERE kind = 'enrich' AND dedupe_key = $1`,
		queue.EnrichDedupeKey(scan.ID)).Scan(&queued); err != nil || queued != 1 {
		t.Errorf("queued retries = %d (err %v), want exactly 1", queued, err)
	}

	// The retry job succeeds once OSV is back.
	checker.err = nil
	if err := s.Enrich(ctx, scan.ID); err != nil {
		t.Fatalf("Enrich() retry error = %v", err)
	}
	got, _ = f.db.GetScan(ctx, scan.ID)
	if got.EnrichedAt == nil || got.EnrichmentError != "" || got.RiskScore == nil || *got.RiskScore != 0 {
		t.Errorf("scan after a successful retry = %+v; want analyzed, error cleared, score 0", got)
	}
}

func TestEnrichWithAnalysisDisabledSaysSoAndDoesNotRetry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	jobs := queue.New(f.db.Pool(), time.Minute)
	s := New(f.db, nil, nil, nil, nil, jobs, config.Scanner{}, quiet())

	scan := f.scan(t, "one", nil, testComponent("pkg:npm/lodash@4.17.20", false))
	s.enrichAfterScan(ctx, quiet(), scan.ID)
	if err := s.Enrich(ctx, scan.ID); err != nil {
		t.Errorf("Enrich() with analysis disabled = %v, want nil so the job is not retried", err)
	}
	got, _ := f.db.GetScan(ctx, scan.ID)
	if got.EnrichedAt != nil || !strings.Contains(got.EnrichmentError, "OSV_DISABLED") {
		t.Errorf("scan = %+v, want unanalyzed with the reason", got)
	}
	var queued int
	_ = f.db.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM jobs WHERE kind = 'enrich'`).Scan(&queued)
	if queued != 0 {
		t.Errorf("queued %d retries for a deliberately disabled lookup", queued)
	}
}

func TestEnrichIgnoresScansThatHaveNotCompleted(t *testing.T) {
	f := newFixture(t)
	checker := &fakeChecker{}
	s := New(f.db, nil, nil, nil, checker, nil, config.Scanner{}, quiet())
	scan, err := f.db.CreateScan(context.Background(), models.Scan{RepositoryID: f.repo.ID, CommitSHA: "pending", Trigger: models.TriggerPush})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Enrich(context.Background(), scan.ID); err != nil || len(checker.calls) != 0 {
		t.Errorf("Enrich(pending) = %v with %d lookups, want nil and none", err, len(checker.calls))
	}
	if err := s.Enrich(context.Background(), 999999); err == nil || !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Enrich(missing) = %v, want not found", err)
	}
}

func TestDriftRiskCountsEachPackageOnce(t *testing.T) {
	events := []models.DriftEvent{
		{ID: 1, Identity: "pkg:npm/a", ChangeType: "added"},
		{ID: 2, Identity: "pkg:npm/a", ChangeType: "added"}, // a second version of a
		{ID: 3, Identity: "pkg:npm/b", ChangeType: "removed"},
		{ID: 4, Identity: "pkg:npm/c", ChangeType: "updated"},
		{ID: 5, Identity: "pkg:npm/d", ChangeType: "updated"},
	}
	base := []risk.Finding{
		{Identity: "pkg:npm/b", Severity: "LOW"},
		{Identity: "pkg:npm/c", Severity: "HIGH"},
		{Identity: "pkg:npm/d", Severity: "MEDIUM"},
	}
	head := []risk.Finding{
		{Identity: "pkg:npm/a", Severity: "CRITICAL"},
		{Identity: "pkg:npm/a", Severity: "LOW"},
		{Identity: "pkg:npm/c", Severity: "HIGH", Direct: true},
		{Identity: "pkg:npm/d", Severity: "MEDIUM"},
	}
	got := DriftRisk(events, base, head)
	want := map[int64]float64{1: 11, 3: -1, 4: 3}
	if len(got) != len(want) {
		t.Fatalf("DriftRisk = %v, want %v", got, want)
	}
	for id, delta := range want {
		if got[id] != delta {
			t.Errorf("DriftRisk[%d] = %v, want %v", id, got[id], delta)
		}
	}
}
