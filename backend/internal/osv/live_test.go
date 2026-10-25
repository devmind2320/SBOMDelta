//go:build osvlive

package osv

import (
	"context"
	"testing"
	"time"

	"sbomdelta/internal/sbom"
)

// TestLiveOSV checks the client against the real OSV.dev API with packages
// whose advisories are long published. It needs the network, so it is built
// only with the osvlive tag and CI does not depend on a third-party service:
//
//	go test -tags osvlive ./internal/osv -run TestLiveOSV -v
func TestLiveOSV(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	report, err := NewClient(DefaultBaseURL).Check(ctx, []sbom.Component{
		component("pkg:npm/lodash@4.17.20"),
		component("pkg:pypi/requests@2.19.0"),
		component("pkg:golang/golang.org/x/text@v0.3.5"),
		component("pkg:npm/lodash@4.17.21"),
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if report.Checked != 4 || report.Skipped != 0 {
		t.Errorf("checked/skipped = %d/%d, want 4/0", report.Checked, report.Skipped)
	}
	byPackage := map[string][]Finding{}
	for _, f := range report.Findings {
		byPackage[f.PURL] = append(byPackage[f.PURL], f)
		t.Logf("%s %s severity=%q (%s) cvss=%v fix=%q fixes=%v", f.PURL, f.OSVID, f.Severity, f.SeveritySource,
			f.CVSSScore, f.FixedVersion, f.FixedVersions)
	}
	found := false
	for _, f := range byPackage["pkg:npm/lodash@4.17.20"] {
		for _, alias := range f.Aliases {
			if alias == "CVE-2021-23337" {
				found = true
				if f.FixedVersion != "4.17.21" || f.Severity == "" {
					t.Errorf("CVE-2021-23337 = %+v, want fixed in 4.17.21 with a severity", f)
				}
			}
		}
	}
	if !found {
		t.Error("lodash 4.17.20 should be affected by CVE-2021-23337")
	}
	if len(byPackage["pkg:pypi/requests@2.19.0"]) == 0 || len(byPackage["pkg:golang/golang.org/x/text@v0.3.5"]) == 0 {
		t.Error("requests 2.19.0 and x/text v0.3.5 have published advisories")
	}
	for _, f := range byPackage["pkg:npm/lodash@4.17.21"] {
		if f.FixedVersion != "" && compareVersions(f.FixedVersion, "4.17.21") <= 0 {
			t.Errorf("recommended a fix at or below the installed version: %+v", f)
		}
	}
}
