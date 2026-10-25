package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"sbomdelta/internal/diff"
	ghapp "sbomdelta/internal/github"
	"sbomdelta/internal/models"
	"sbomdelta/internal/osv"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/risk"
	"sbomdelta/internal/sbom"
	"sbomdelta/internal/storage"
)

func scanOf(t *testing.T, db *storage.DB, repoID int64, sha string, base *models.Scan, purls ...string) models.Scan {
	t.Helper()
	ctx := context.Background()
	scan, err := db.CreateScan(ctx, models.Scan{RepositoryID: repoID, CommitSHA: sha, Trigger: models.TriggerPush})
	if err != nil {
		t.Fatal(err)
	}
	var components []sbom.Component
	for _, purl := range purls {
		identity, version, ecosystem, name := sbom.ParseIdentity(purl)
		components = append(components, sbom.Component{PURL: purl, Identity: identity, Version: version, Ecosystem: ecosystem, Name: name})
	}
	result := storage.ScanResult{ScanID: scan.ID, Components: components}
	if base != nil {
		previous, _ := db.ListComponents(ctx, base.ID)
		result.BaseScanID = &base.ID
		result.Diff = diff.Compare(previous, components)
	}
	if err := db.SaveScanResult(ctx, result); err != nil {
		t.Fatal(err)
	}
	scan, _ = db.GetScan(ctx, scan.ID)
	return scan
}

func enrichWith(t *testing.T, db *storage.DB, scanID int64, findings ...osv.Finding) {
	t.Helper()
	var scored []risk.Finding
	for _, f := range findings {
		scored = append(scored, risk.Finding{OSVID: f.OSVID, Identity: f.Identity, PURL: f.PURL, Severity: f.Severity, FixedVersion: f.FixedVersion})
	}
	if err := db.SaveEnrichment(context.Background(), storage.EnrichmentResult{
		ScanID: scanID, Findings: findings, Checked: len(findings), Assessment: risk.Assess(scored),
	}); err != nil {
		t.Fatal(err)
	}
}

func advisory(purl, id, severity, fixed string) osv.Finding {
	identity, _, _, _ := sbom.ParseIdentity(purl)
	return osv.Finding{PURL: purl, Identity: identity, OSVID: id, Severity: severity, FixedVersion: fixed, Aliases: []string{}}
}

func decodeInto(t *testing.T, raw json.RawMessage, into any) {
	t.Helper()
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
}

// TRACK persists for the user and moves the repository from All Repos to
// Tracked Repos; untracking moves it back. Only accessible repositories can
// be tracked.
func TestTrackMovesARepositoryBetweenTheDashboardSections(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	path := "/api/me/tracked/" + jsonID(f.active.ID)

	if page := f.myRepositories(t, "?exclude=tracked"); page.Total != 2 {
		t.Fatalf("All Repos before tracking = %d, want 2", page.Total)
	}
	for range 2 { // tracking twice is not an error
		if status, body := f.as(t, f.session, http.MethodPut, path); status != http.StatusNoContent {
			t.Fatalf("PUT %s = %d %s, want 204", path, status, body)
		}
	}
	if len(f.scans.requested) != 0 {
		t.Error("tracking must not start a scan")
	}
	_, body := f.do(t, http.MethodGet, "/api/me/tracked", "")
	var tracked []models.TrackedRepository
	decodeInto(t, body["repositories"], &tracked)
	if len(tracked) != 1 || tracked[0].ID != f.active.ID {
		t.Fatalf("Tracked Repos = %+v, want the tracked repository", tracked)
	}
	page := f.myRepositories(t, "?exclude=tracked")
	if page.Total != 1 || len(page.Repositories) != 1 || page.Repositories[0].Name != "dropped" {
		t.Errorf("All Repos after tracking = %+v (total %d), want only the untracked repository", page.Repositories, page.Total)
	}
	if all := f.myRepositories(t, ""); all.Total != 2 {
		t.Errorf("without exclude, All Repos total = %d, want 2", all.Total)
	}

	// A repository outside the user's GitHub list cannot be tracked, and the
	// refusal names nothing.
	githubID := int64(3003)
	other, err := f.db.UpsertRepository(ctx, models.Repository{GitHubRepoID: &githubID, Owner: "stranger", Name: "secret-repo", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if status, body := f.as(t, f.session, http.MethodPut, "/api/me/tracked/"+jsonID(other.ID)); status != http.StatusNotFound || strings.Contains(body, "secret-repo") {
		t.Errorf("tracking an inaccessible repository = %d %s, want a bare 404", status, body)
	}
	if status, _ := f.as(t, f.session, http.MethodPut, "/api/me/tracked/0"); status != http.StatusBadRequest {
		t.Errorf("tracking id 0 = %d, want 400", status)
	}

	if status, _ := f.as(t, f.session, http.MethodDelete, path); status != http.StatusNoContent {
		t.Fatalf("DELETE %s = %d", path, status)
	}
	if page := f.myRepositories(t, "?exclude=tracked"); page.Total != 2 {
		t.Errorf("All Repos after untracking = %d, want 2", page.Total)
	}
}

// Risk and vulnerability changes are reported only once they are known; an
// unanalyzed scan says why instead of reading as zero.
func TestRiskAndVulnerabilityChangesAreReportedHonestly(t *testing.T) {
	f := newFixture(t)

	for _, suffix := range []string{"/risk", "/vulnerability-changes"} {
		status, body := f.do(t, http.MethodGet, "/api/scans/"+jsonID(f.scan.ID)+suffix, "")
		flag := "scored"
		if suffix != "/risk" {
			flag = "available"
		}
		if status != http.StatusOK || string(body[flag]) != "false" || !strings.Contains(string(body["reason"]), "not been checked") {
			t.Errorf("GET %s on an unanalyzed scan = %d %v, want %s false with a reason", suffix, status, body, flag)
		}
	}

	base := scanOf(t, f.db, f.active.ID, "b1", nil, "pkg:npm/lodash@4.17.20", "pkg:npm/qs@6.5.0")
	enrichWith(t, f.db, base.ID, advisory("pkg:npm/lodash@4.17.20", "GHSA-lodash", "HIGH", "4.17.21"))
	head := scanOf(t, f.db, f.active.ID, "h1", &base, "pkg:npm/lodash@4.17.21", "pkg:npm/qs@6.5.0", "pkg:npm/evil@1.0.0")
	enrichWith(t, f.db, head.ID, advisory("pkg:npm/evil@1.0.0", "GHSA-evil", "CRITICAL", ""))

	status, body := f.do(t, http.MethodGet, "/api/scans/"+jsonID(head.ID)+"/risk", "")
	if status != http.StatusOK || string(body["scored"]) != "true" {
		t.Fatalf("GET risk = %d %v", status, body)
	}
	var assessment risk.Assessment
	decodeInto(t, body["assessment"], &assessment)
	if assessment.Score != 10 || assessment.Level != risk.LevelMedium || len(assessment.Factors) != 1 ||
		assessment.Factors[0].Key != "severity_critical" || assessment.Method == "" {
		t.Errorf("assessment = %+v", assessment)
	}

	status, body = f.do(t, http.MethodGet, "/api/scans/"+jsonID(head.ID)+"/vulnerability-changes", "")
	if status != http.StatusOK || string(body["available"]) != "true" {
		t.Fatalf("GET vulnerability-changes = %d %v", status, body)
	}
	var comparison risk.Comparison
	decodeInto(t, body["comparison"], &comparison)
	if len(comparison.Introduced) != 1 || comparison.Introduced[0].OSVID != "GHSA-evil" ||
		len(comparison.Resolved) != 1 || comparison.Resolved[0].OSVID != "GHSA-lodash" {
		t.Errorf("comparison = %+v", comparison)
	}

	status, body = f.do(t, http.MethodGet, "/api/scans/"+jsonID(head.ID)+"/vulnerabilities", "")
	if status != http.StatusOK || string(body["enrichmentAvailable"]) != "true" {
		t.Fatalf("GET vulnerabilities = %d %v", status, body)
	}
	var summary models.VulnerabilitySummary
	decodeInto(t, body["summary"], &summary)
	if summary.Status != models.VulnStatusAnalyzed || summary.Critical != 1 || summary.Introduced == nil || *summary.Introduced != 1 {
		t.Errorf("summary = %+v", summary)
	}
	var vulns []models.Vulnerability
	decodeInto(t, body["vulnerabilities"], &vulns)
	if len(vulns) != 1 || vulns[0].Remediation == "" {
		t.Errorf("vulnerabilities = %+v, want one with remediation guidance", vulns)
	}

	// The baseline has nothing to compare with, and says so.
	status, body = f.do(t, http.MethodGet, "/api/scans/"+jsonID(base.ID)+"/vulnerability-changes", "")
	if status != http.StatusOK || string(body["available"]) != "false" || !strings.Contains(string(body["reason"]), "baseline") {
		t.Errorf("baseline vulnerability-changes = %d %v", status, body)
	}
}

// Last scans and impact cover the user's tracked repositories only.
func TestLastScansAndImpactAreScopedToTrackedRepositories(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	scan := scanOf(t, f.db, f.active.ID, "a1", nil, "pkg:npm/lodash@4.17.20")
	enrichWith(t, f.db, scan.ID, advisory("pkg:npm/lodash@4.17.20", "GHSA-lodash", "HIGH", "4.17.21"))

	_, body := f.do(t, http.MethodGet, "/api/me/scans", "")
	if string(body["scans"]) != "[]" {
		t.Errorf("Last scans before tracking = %s, want []", body["scans"])
	}
	_, body = f.do(t, http.MethodGet, "/api/impact/vulnerabilities", "")
	if string(body["vulnerabilities"]) != "[]" {
		t.Errorf("impact before tracking = %s, want []", body["vulnerabilities"])
	}

	if err := f.db.TrackRepository(ctx, f.user.ID, f.active.ID); err != nil {
		t.Fatal(err)
	}
	status, body := f.do(t, http.MethodGet, "/api/me/scans?limit=5", "")
	var scans []models.ScanOverview
	decodeInto(t, body["scans"], &scans)
	if status != http.StatusOK || len(scans) != 1 || scans[0].ID != scan.ID || scans[0].Name != "kept" ||
		scans[0].Vulnerabilities == nil || scans[0].Vulnerabilities.High != 1 || scans[0].Risk == nil {
		t.Fatalf("Last scans = %d %+v", status, scans)
	}

	_, body = f.do(t, http.MethodGet, "/api/impact/vulnerabilities", "")
	var impact []models.ImpactVulnerability
	decodeInto(t, body["vulnerabilities"], &impact)
	var coverage models.ImpactCoverage
	decodeInto(t, body["coverage"], &coverage)
	if len(impact) != 1 || impact[0].OSVID != "GHSA-lodash" || impact[0].RepositoryCount != 1 || coverage.Analyzed != 1 {
		t.Errorf("impact = %+v coverage %+v", impact, coverage)
	}

	_, body = f.do(t, http.MethodGet, "/api/impact/components?q=lodash", "")
	var components []models.ImpactComponent
	decodeInto(t, body["components"], &components)
	if len(components) != 1 || components[0].Identity != "pkg:npm/lodash" {
		t.Errorf("component impact = %+v", components)
	}
	if status, _ := f.do(t, http.MethodGet, "/api/impact/components?q=l", ""); status != http.StatusBadRequest {
		t.Errorf("a one-character search = %d, want 400", status)
	}

	// Another user who can reach the repository but does not track it sees
	// nothing of it here.
	teammate := newSession(t, f.db, 5001, "teammate")
	grant(t, f.db, userNamed(t, f.db, "teammate"), f.active)
	for _, path := range []string{"/api/me/scans", "/api/impact/vulnerabilities", "/api/impact/components?q=lodash"} {
		if status, body := f.as(t, teammate, http.MethodGet, path); status != http.StatusOK || strings.Contains(body, "GHSA-lodash") || strings.Contains(body, "kept") {
			t.Errorf("GET %s as teammate = %d %s, want nothing of the untracked repository", path, status, body)
		}
	}
}

// Asking to scan a commit that is already scanned, but whose vulnerability
// lookup never succeeded, queues the lookup; once analyzed, it does not.
func TestScanRequestQueuesAMissingVulnerabilityLookup(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	scan := scanOf(t, f.db, f.active.ID, "u1", nil, "pkg:npm/lodash@4.17.20")
	f.scans.scan = scan
	f.scans.outcome = ghapp.ScanUpToDate

	count := func() int {
		var n int
		if err := f.db.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM jobs WHERE kind = 'enrich' AND dedupe_key = $1`,
			queue.EnrichDedupeKey(scan.ID)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	path := "/api/repos/" + jsonID(f.active.ID) + "/scans"
	for range 2 {
		if status, _ := f.do(t, http.MethodPost, path, ""); status != http.StatusAccepted {
			t.Fatalf("POST %s = %d", path, status)
		}
	}
	if count() != 1 {
		t.Errorf("enrich jobs = %d, want exactly 1", count())
	}

	if _, err := f.db.Pool().Exec(ctx, `DELETE FROM jobs`); err != nil {
		t.Fatal(err)
	}
	enrichWith(t, f.db, scan.ID)
	analyzed, _ := f.db.GetScan(ctx, scan.ID)
	f.scans.scan = analyzed
	if status, _ := f.do(t, http.MethodPost, path, ""); status != http.StatusAccepted {
		t.Fatalf("POST %s = %d", path, status)
	}
	if count() != 0 {
		t.Errorf("an analyzed scan was queued for another lookup")
	}
}
