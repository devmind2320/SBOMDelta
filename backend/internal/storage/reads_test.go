package storage_test

import (
	"context"
	"errors"
	"testing"

	"sbomdelta/internal/diff"
	"sbomdelta/internal/models"
	"sbomdelta/internal/sbom"
	"sbomdelta/internal/storage"
)

// A pull request that has never been scanned must still appear in the list,
// with null scan fields rather than being dropped by the join.
func TestListPullRequestsIncludesUnscannedPulls(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	if _, err := db.UpsertPullRequest(ctx, models.PullRequest{
		RepositoryID: repo.ID, Number: 3, Title: "Not scanned yet",
		AuthorLogin: "arya", State: "open", BaseSHA: "base333", HeadSHA: "head333",
	}); err != nil {
		t.Fatalf("UpsertPullRequest() error = %v", err)
	}

	pulls, err := db.ListPullRequests(ctx, repo.ID, 50)
	if err != nil {
		t.Fatalf("ListPullRequests() error = %v", err)
	}
	if len(pulls) != 1 {
		t.Fatalf("pull requests = %d, want 1", len(pulls))
	}
	if pulls[0].ScanID != nil {
		t.Errorf("scan id = %v, want nil for an unscanned pull request", *pulls[0].ScanID)
	}
	if pulls[0].Added != 0 || pulls[0].Updated != 0 || pulls[0].Removed != 0 {
		t.Errorf("change counts = %+v, want zeroes", pulls[0])
	}
	if pulls[0].Title != "Not scanned yet" {
		t.Errorf("title = %q, want it preserved", pulls[0].Title)
	}
}

func TestListPullRequestsCarriesScanCounts(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	pr, err := db.UpsertPullRequest(ctx, models.PullRequest{
		RepositoryID: repo.ID, Number: 142, Title: "Update authentication dependencies",
		AuthorLogin: "arya", State: "open", BaseSHA: "base142", HeadSHA: "head142",
	})
	if err != nil {
		t.Fatalf("UpsertPullRequest() error = %v", err)
	}

	scan, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, PullRequestID: &pr.ID, CommitSHA: "head142",
		BaseCommitSHA: "base142", Trigger: models.TriggerPullRequest,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}

	base := []sbom.Component{component("pkg:npm/axios@1.6.0"), component("pkg:npm/left-pad@1.3.0")}
	head := []sbom.Component{component("pkg:npm/axios@1.7.0"), component("pkg:npm/jsonwebtoken@9.0.2")}
	if err := db.SaveScanResult(ctx, storage.ScanResult{
		ScanID: scan.ID, Components: head, Diff: diff.Compare(base, head),
	}); err != nil {
		t.Fatalf("SaveScanResult() error = %v", err)
	}

	pulls, err := db.ListPullRequests(ctx, repo.ID, 50)
	if err != nil {
		t.Fatalf("ListPullRequests() error = %v", err)
	}
	if len(pulls) != 1 {
		t.Fatalf("pull requests = %d, want 1", len(pulls))
	}

	got := pulls[0]
	if got.ScanID == nil || *got.ScanID != scan.ID {
		t.Fatalf("scan id = %v, want %d", got.ScanID, scan.ID)
	}
	if got.Added != 1 || got.Updated != 1 || got.Removed != 1 {
		t.Errorf("counts = added %d / updated %d / removed %d, want 1/1/1",
			got.Added, got.Updated, got.Removed)
	}
	if got.ComponentCount == nil || *got.ComponentCount != 2 {
		t.Errorf("component count = %v, want 2", got.ComponentCount)
	}
	// Risk scoring is Phase 5; the column must stay null rather than default to 0,
	// so the dashboard can tell "no risk" from "not scored".
	if got.RiskDelta != nil {
		t.Errorf("risk delta = %v, want nil until the risk engine exists", *got.RiskDelta)
	}
}

// Only the newest scan of a pull request should drive its summary -- a PR that
// was pushed to twice must not double-count its drift.
func TestListPullRequestsUsesLatestScanOnly(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	pr, err := db.UpsertPullRequest(ctx, models.PullRequest{
		RepositoryID: repo.ID, Number: 9, State: "open", BaseSHA: "base9", HeadSHA: "head9b",
	})
	if err != nil {
		t.Fatalf("UpsertPullRequest() error = %v", err)
	}

	for _, sha := range []string{"head9a", "head9b"} {
		scan, err := db.CreateScan(ctx, models.Scan{
			RepositoryID: repo.ID, PullRequestID: &pr.ID, CommitSHA: sha,
			Trigger: models.TriggerPullRequest,
		})
		if err != nil {
			t.Fatalf("CreateScan(%s) error = %v", sha, err)
		}
		head := []sbom.Component{component("pkg:npm/axios@1.7.0")}
		if err := db.SaveScanResult(ctx, storage.ScanResult{
			ScanID: scan.ID, Components: head, Diff: diff.Compare(nil, head),
		}); err != nil {
			t.Fatalf("SaveScanResult(%s) error = %v", sha, err)
		}
	}

	pulls, err := db.ListPullRequests(ctx, repo.ID, 50)
	if err != nil {
		t.Fatalf("ListPullRequests() error = %v", err)
	}
	if len(pulls) != 1 {
		t.Fatalf("pull requests = %d, want 1 row for one PR", len(pulls))
	}
	if pulls[0].ComponentCount == nil || *pulls[0].ComponentCount != 1 {
		t.Errorf("component count = %v, want 1 (latest scan only)", pulls[0].ComponentCount)
	}
}

func TestGetPullRequestNotFound(t *testing.T) {
	db := newTestDB(t)
	if _, err := db.GetPullRequest(context.Background(), 99999); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("error = %v, want storage.ErrNotFound", err)
	}
}

func TestGetPullRequest(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	pr, err := db.UpsertPullRequest(ctx, models.PullRequest{
		RepositoryID: repo.ID, Number: 72, Title: "Add JWT support",
		AuthorLogin: "arya", State: "open", BaseRef: "main", BaseSHA: "b72", HeadSHA: "h72",
	})
	if err != nil {
		t.Fatalf("UpsertPullRequest() error = %v", err)
	}

	got, err := db.GetPullRequest(ctx, pr.ID)
	if err != nil {
		t.Fatalf("GetPullRequest() error = %v", err)
	}
	if got.Number != 72 || got.Title != "Add JWT support" || got.AuthorLogin != "arya" {
		t.Errorf("pull request = %+v, want #72 by arya", got)
	}
	if got.BaseRef != "main" {
		t.Errorf("base ref = %q, want %q", got.BaseRef, "main")
	}
}

// Until Phase 4 runs, a scan has components but no advisories. That must read
// as an empty list, not an error -- the dashboard distinguishes "none found"
// from "not analyzed" using its own flag.
func TestListVulnerabilitiesIsEmptyBeforeEnrichment(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	scan, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: "vuln001", Trigger: models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	head := []sbom.Component{component("pkg:npm/lodash@4.17.20")}
	if err := db.SaveScanResult(ctx, storage.ScanResult{ScanID: scan.ID, Components: head}); err != nil {
		t.Fatalf("SaveScanResult() error = %v", err)
	}

	vulnerabilities, err := db.ListVulnerabilities(ctx, scan.ID)
	if err != nil {
		t.Fatalf("ListVulnerabilities() error = %v", err)
	}
	if len(vulnerabilities) != 0 {
		t.Errorf("vulnerabilities = %d, want 0 before enrichment", len(vulnerabilities))
	}
	if vulnerabilities == nil {
		t.Error("vulnerabilities = nil, want an empty slice so the API emits [] not null")
	}
}

// Phase 4 will write these rows; verify now that the read path orders by
// severity and joins the component details the table needs.
func TestListVulnerabilitiesOrdersBySeverity(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	scan, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: "vuln002", Trigger: models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	head := []sbom.Component{component("pkg:npm/lodash@4.17.20")}
	if err := db.SaveScanResult(ctx, storage.ScanResult{ScanID: scan.ID, Components: head}); err != nil {
		t.Fatalf("SaveScanResult() error = %v", err)
	}

	var componentID int64
	if err := db.Pool().QueryRow(ctx,
		`SELECT id FROM components WHERE scan_id = $1`, scan.ID).Scan(&componentID); err != nil {
		t.Fatalf("look up component: %v", err)
	}

	// Insert out of severity order on purpose.
	for _, row := range []struct {
		osvID    string
		severity string
		score    float64
	}{
		{"GHSA-low", "LOW", 3.1},
		{"GHSA-crit", "CRITICAL", 9.8},
		{"GHSA-med", "MODERATE", 5.4},
		{"GHSA-high", "HIGH", 7.5},
	} {
		if _, err := db.Pool().Exec(ctx, `
			INSERT INTO vulnerabilities (component_id, osv_id, severity, cvss_score, summary)
			VALUES ($1, $2, $3, $4, $5)`,
			componentID, row.osvID, row.severity, row.score, "test advisory"); err != nil {
			t.Fatalf("insert %s: %v", row.osvID, err)
		}
	}

	vulnerabilities, err := db.ListVulnerabilities(ctx, scan.ID)
	if err != nil {
		t.Fatalf("ListVulnerabilities() error = %v", err)
	}
	if len(vulnerabilities) != 4 {
		t.Fatalf("vulnerabilities = %d, want 4", len(vulnerabilities))
	}

	want := []string{"GHSA-crit", "GHSA-high", "GHSA-med", "GHSA-low"}
	for i, id := range want {
		if vulnerabilities[i].OSVID != id {
			t.Errorf("position %d = %q, want %q (severity order)", i, vulnerabilities[i].OSVID, id)
		}
	}
	// The component details have to ride along, or the table needs a second query.
	if vulnerabilities[0].Name != "lodash" || vulnerabilities[0].Version != "4.17.20" {
		t.Errorf("component details = %s@%s, want lodash@4.17.20",
			vulnerabilities[0].Name, vulnerabilities[0].Version)
	}
	if vulnerabilities[0].Ecosystem != "npm" {
		t.Errorf("ecosystem = %q, want npm", vulnerabilities[0].Ecosystem)
	}
}

// The enrichment flag must come from the scan's own state. Reporting "no
// vulnerabilities" for a scan that was never enriched would be the dashboard
// claiming a clean result it has not earned.
func TestScanTracksEnrichmentState(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	scan, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: "enrich1", Trigger: models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	if err := db.SaveScanResult(ctx, storage.ScanResult{
		ScanID:     scan.ID,
		Components: []sbom.Component{component("pkg:npm/lodash@4.17.21")},
	}); err != nil {
		t.Fatalf("SaveScanResult() error = %v", err)
	}

	stored, err := db.GetScan(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScan() error = %v", err)
	}
	if stored.EnrichedAt != nil {
		t.Errorf("enrichedAt = %v, want nil before enrichment runs", stored.EnrichedAt)
	}

	// Phase 4 will stamp this; verify the read path surfaces it.
	if _, err := db.Pool().Exec(ctx, `UPDATE scans SET enriched_at = now() WHERE id = $1`, scan.ID); err != nil {
		t.Fatalf("stamp enriched_at: %v", err)
	}
	stored, err = db.GetScan(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScan() error = %v", err)
	}
	if stored.EnrichedAt == nil {
		t.Error("enrichedAt = nil, want the timestamp to survive the round trip")
	}
}
