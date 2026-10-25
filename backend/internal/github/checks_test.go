package github

import (
	"strings"
	"testing"

	"sbomdelta/internal/diff"
	"sbomdelta/internal/risk"
)

func analyzed(findings []risk.Finding, comparison *risk.Comparison) VulnerabilityReport {
	return VulnerabilityReport{Available: true, Assessment: risk.Assess(findings), Comparison: comparison}
}

func TestCheckConclusionPolicy(t *testing.T) {
	critical := risk.Finding{OSVID: "GHSA-c", Package: "evil", Version: "1.0.0", Severity: "CRITICAL"}
	low := risk.Finding{OSVID: "GHSA-l", Package: "meh", Version: "1.0.0", Severity: "LOW", FixedVersion: "1.0.1"}
	added := []diff.Change{{Type: diff.Added, Name: "evil", NewVersion: "1.0.0", Ecosystem: "npm"}}

	cases := []struct {
		name   string
		report CheckReport
		want   string
	}{
		{"nothing changed, nothing vulnerable", CheckReport{Components: 3, Vulns: analyzed(nil, &risk.Comparison{})}, "success"},
		{"drift only", CheckReport{Added: added, Vulns: analyzed(nil, &risk.Comparison{})}, "neutral"},
		{"introduced critical", CheckReport{Added: added, Vulns: analyzed([]risk.Finding{critical},
			&risk.Comparison{Introduced: []risk.Finding{critical}})}, "failure"},
		{"introduced low only", CheckReport{Added: added, Vulns: analyzed([]risk.Finding{low},
			&risk.Comparison{Introduced: []risk.Finding{low}})}, "neutral"},
		{"existing critical, nothing new", CheckReport{Vulns: analyzed([]risk.Finding{critical},
			&risk.Comparison{Unchanged: 1})}, "success"},
		{"vulnerability data unavailable", CheckReport{Vulns: VulnerabilityReport{Reason: "OSV returned HTTP 503"}}, "neutral"},
		{"baseline with vulnerabilities", CheckReport{Baseline: true, Vulns: analyzed([]risk.Finding{critical}, nil)}, "neutral"},
		{"clean baseline", CheckReport{Baseline: true, Vulns: analyzed(nil, nil)}, "success"},
	}
	for _, c := range cases {
		if got := c.report.Conclusion(); got != c.want {
			t.Errorf("%s: conclusion = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRenderCheckLeadsWithIntroducedVulnerabilities(t *testing.T) {
	critical := risk.Finding{OSVID: "GHSA-crit-1234", Package: "evil", Version: "1.0.0", Severity: "CRITICAL"}
	fixed := risk.Finding{OSVID: "GHSA-old-5678", Package: "lodash", Version: "4.17.20", Severity: "HIGH", FixedVersion: "4.17.21"}
	report := CheckReport{
		Components: 12,
		Added:      []diff.Change{{Type: diff.Added, Name: "evil", NewVersion: "1.0.0", Ecosystem: "npm"}},
		Updated:    []diff.Change{{Type: diff.Updated, Name: "lodash", OldVersion: "4.17.20", NewVersion: "4.17.21", Ecosystem: "npm"}},
		Vulns: analyzed([]risk.Finding{critical}, &risk.Comparison{
			Introduced: []risk.Finding{critical}, Resolved: []risk.Finding{fixed}}),
	}
	title, summary, text := RenderCheck(report)
	if title != "1 critical/high vulnerability introduced" {
		t.Errorf("title = %q", title)
	}
	for _, want := range []string{"**1 added** · **1 updated** · **0 removed**", "1 vulnerability introduced", "Risk score **10** (medium)"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary missing %q:\n%s", want, summary)
		}
	}
	for _, want := range []string{"### Vulnerabilities introduced (1)", "GHSA-crit-1234", "no fix published",
		"### Vulnerabilities resolved (1)", "fixed in 4.17.21", "### Added (1)", "Risk score:"} {
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q:\n%s", want, text)
		}
	}
}

func TestRenderCheckSaysWhenVulnerabilityDataIsUnavailable(t *testing.T) {
	report := CheckReport{
		Components: 4,
		Updated:    []diff.Change{{Type: diff.Updated, Name: "lodash", OldVersion: "1", NewVersion: "2", Ecosystem: "npm"}},
		Vulns:      VulnerabilityReport{Reason: "OSV POST /v1/querybatch returned HTTP 503"},
	}
	title, summary, text := RenderCheck(report)
	if title != "1 dependency change" {
		t.Errorf("title = %q", title)
	}
	if !strings.Contains(summary, "Vulnerability data is unavailable for this commit: OSV POST /v1/querybatch returned HTTP 503") {
		t.Errorf("summary = %q", summary)
	}
	if strings.Contains(text, "Risk score") || strings.Contains(summary, "Risk score") {
		t.Error("an unanalyzed commit must not show a risk score")
	}
}
