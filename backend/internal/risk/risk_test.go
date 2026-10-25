package risk

import (
	"reflect"
	"testing"
)

func TestAssessIsDeterministicAndExplained(t *testing.T) {
	findings := []Finding{
		{OSVID: "GHSA-1", Package: "lodash", Identity: "pkg:npm/lodash", Severity: "CRITICAL", Direct: true, FixedVersion: "4.17.21"},
		{OSVID: "GHSA-2", Package: "minimist", Identity: "pkg:npm/minimist", Severity: "HIGH"},
		{OSVID: "GHSA-3", Package: "qs", Identity: "pkg:npm/qs", Severity: "moderate", FixedVersion: "6.5.3"},
		{OSVID: "PYSEC-4", Package: "x", Identity: "pkg:pypi/x", Severity: ""},
		{OSVID: "GHSA-5", Package: "y", Identity: "pkg:npm/y", Severity: "LOW"},
	}
	got := Assess(findings)

	// 10*1.5 + 6 + 3 + 2 + 1 = 27
	if got.Score != 27 || got.Uncapped != 27 || got.Level != LevelHigh {
		t.Fatalf("score/level = %v/%v (uncapped %v), want 27/high", got.Score, got.Level, got.Uncapped)
	}
	if got.Total != 5 || got.Fixable != 2 {
		t.Errorf("total/fixable = %d/%d, want 5/2", got.Total, got.Fixable)
	}
	var sum float64
	keys := []string{}
	for _, f := range got.Factors {
		sum += f.Points
		keys = append(keys, f.Key)
	}
	if sum != got.Score {
		t.Errorf("factors add up to %v, want the score %v: every point must be attributed", sum, got.Score)
	}
	wantKeys := []string{"severity_critical", "severity_high", "severity_medium", "severity_low", "severity_unrated", "direct_dependency"}
	if !reflect.DeepEqual(keys, wantKeys) {
		t.Errorf("factor keys = %v, want %v", keys, wantKeys)
	}
	if got.Top[0].OSVID != "GHSA-1" || got.Top[0].Points != 15 {
		t.Errorf("top contributor = %+v, want GHSA-1 with 15 points", got.Top[0])
	}
	if again := Assess(findings); !reflect.DeepEqual(again, got) {
		t.Error("the same findings gave a different assessment")
	}
}

func TestAssessLevelsAndCap(t *testing.T) {
	if got := Assess(nil); got.Score != 0 || got.Level != LevelNone || len(got.Factors) != 0 {
		t.Errorf("no findings = %+v, want score 0 level none", got)
	}
	var many []Finding
	for i := 0; i < 12; i++ {
		many = append(many, Finding{OSVID: string(rune('A' + i)), Severity: "CRITICAL"})
	}
	got := Assess(many)
	if got.Score != MaxScore || got.Uncapped != 120 || got.Level != LevelCritical || len(got.Top) != 10 {
		t.Errorf("capped = %v (uncapped %v, level %v, top %d), want 100/120/critical/10", got.Score, got.Uncapped, got.Level, len(got.Top))
	}
	for score, want := range map[float64]string{0: LevelNone, 1: LevelLow, 9.9: LevelLow, 10: LevelMedium, 24.9: LevelMedium, 25: LevelHigh, 49.9: LevelHigh, 50: LevelCritical} {
		if LevelFor(score) != want {
			t.Errorf("LevelFor(%v) = %v, want %v", score, LevelFor(score), want)
		}
	}
}

func TestCompareTracksAdvisoriesAcrossVersions(t *testing.T) {
	base := []Finding{
		{OSVID: "GHSA-old", Identity: "pkg:npm/a", Package: "a", Version: "1.0.0", Severity: "HIGH"},
		{OSVID: "GHSA-kept", Identity: "pkg:npm/b", Package: "b", Version: "1.0.0", Severity: "LOW"},
	}
	head := []Finding{
		// b upgraded but still affected by the same advisory: unchanged.
		{OSVID: "GHSA-kept", Identity: "pkg:npm/b", Package: "b", Version: "1.1.0", Severity: "LOW"},
		{OSVID: "GHSA-new-low", Identity: "pkg:npm/c", Package: "c", Severity: "LOW"},
		{OSVID: "GHSA-new-crit", Identity: "pkg:npm/d", Package: "d", Severity: "CRITICAL"},
	}
	got := Compare(base, head)
	if got.Unchanged != 1 || len(got.Introduced) != 2 || len(got.Resolved) != 1 {
		t.Fatalf("comparison = %+v", got)
	}
	if got.Introduced[0].OSVID != "GHSA-new-crit" {
		t.Errorf("introduced must be most severe first, got %v", got.Introduced)
	}
	if got.Resolved[0].OSVID != "GHSA-old" {
		t.Errorf("resolved = %v", got.Resolved)
	}
	if Blocking(got.Introduced) != 1 || Blocking(got.Resolved) != 1 || Blocking(nil) != 0 {
		t.Error("Blocking counts critical and high findings only")
	}
}
