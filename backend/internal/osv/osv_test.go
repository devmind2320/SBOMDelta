package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"sbomdelta/internal/sbom"
)

// Reference scores from the FIRST CVSS v3.1 calculator.
func TestCVSSv3BaseScoreMatchesTheSpecification(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N": 5.4,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for vector, want := range cases {
		got, ok := CVSSv3BaseScore(vector)
		if !ok || got != want {
			t.Errorf("CVSSv3BaseScore(%q) = %v, %v; want %v", vector, got, ok, want)
		}
	}
	for _, bad := range []string{
		"", "CVSS:2.0/AV:N", "CVSS:3.1/AV:N/AC:L", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Q/C:H/I:H/A:H",
	} {
		if _, ok := CVSSv3BaseScore(bad); ok {
			t.Errorf("CVSSv3BaseScore(%q) accepted an invalid vector", bad)
		}
	}
}

func TestRatingsAndNormalization(t *testing.T) {
	for score, want := range map[float64]string{9.0: "CRITICAL", 8.9: "HIGH", 7.0: "HIGH", 6.9: "MEDIUM", 4.0: "MEDIUM", 3.9: "LOW", 0.1: "LOW", 0: ""} {
		if got := CVSSv3Rating(score); got != want {
			t.Errorf("CVSSv3Rating(%v) = %q, want %q", score, got, want)
		}
	}
	for in, want := range map[string]string{"moderate": "MEDIUM", "HIGH": "HIGH", " low ": "LOW", "critical": "CRITICAL", "important": "", "": ""} {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRecommendedFixIsTheSmallestUpgradeOutOfTheRange(t *testing.T) {
	cases := []struct {
		installed string
		fixes     []string
		want      string
	}{
		{"4.17.20", []string{"4.17.21"}, "4.17.21"},
		{"2.1.0", []string{"1.9.3", "2.5.0", "3.0.1"}, "2.5.0"},
		{"1.2.0", []string{"1.10.0", "1.9.0"}, "1.9.0"},
		{"2.0.0", []string{"1.0.5"}, ""}, // only an older line is fixed: no downgrade advice
		{"1.0", nil, ""},
		{"", []string{"1.0"}, ""},
		{"5.3.18.RELEASE", []string{"5.3.20.RELEASE", "5.2.22.RELEASE"}, "5.3.20.RELEASE"},
		{"v0.0.0-20210101", []string{"v0.0.0-20220315"}, "v0.0.0-20220315"},
	}
	for _, c := range cases {
		if got := RecommendedFix(c.installed, c.fixes); got != c.want {
			t.Errorf("RecommendedFix(%q, %v) = %q, want %q", c.installed, c.fixes, got, c.want)
		}
	}
}

func TestQueryPURLDropsQualifiersAndSkipsWhatOSVCannotMatch(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/lodash@4.17.20":                          "pkg:npm/lodash@4.17.20",
		"pkg:npm/%40babel/core@7.0.0":                     "pkg:npm/%40babel/core@7.0.0",
		"pkg:maven/org.apache/commons@1.0?type=jar":       "pkg:maven/org.apache/commons@1.0",
		"pkg:golang/github.com/x/y@v1.2.3#sub/dir":        "pkg:golang/github.com/x/y@v1.2.3",
		"pkg:pypi/requests@2.0.0":                         "pkg:pypi/requests@2.0.0",
		"pkg:npm/no-version":                              "",
		"pkg:deb/debian/curl@7.0?distro=debian-11":        "",
		"pkg:github/actions/checkout@v4":                  "",
		"not a purl":                                      "",
		"pkg:generic/openssl@3.0.0?download_url=x.tar.gz": "",
	}
	for in, want := range cases {
		got, ok := QueryPURL(in)
		if got != want || ok != (want != "") {
			t.Errorf("QueryPURL(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

// fakeOSV serves querybatch and vulns from fixed data, recording requests.
type fakeOSV struct {
	mu       sync.Mutex
	byPURL   map[string][]string // query purl -> advisory ids
	vulns    map[string]Vulnerability
	reject   map[string]bool // query purls answered with 400
	pageSize int
	batches  int
	fail     int // HTTP status for every request, when set
}

func (f *fakeOSV) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.fail != 0 {
			http.Error(w, "upstream trouble", f.fail)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			f.batches++
			var request batchRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("bad querybatch body: %v", err)
			}
			type result struct {
				Vulns         []map[string]string `json:"vulns"`
				NextPageToken string              `json:"next_page_token,omitempty"`
			}
			out := struct {
				Results []result `json:"results"`
			}{}
			for _, q := range request.Queries {
				if f.reject[q.Package.PURL] {
					http.Error(w, "invalid purl", http.StatusBadRequest)
					return
				}
				ids := f.byPURL[q.Package.PURL]
				start := 0
				if q.PageToken != "" {
					start = len(q.PageToken) // token encodes the offset as its length
				}
				end := len(ids)
				var next string
				if f.pageSize > 0 && end-start > f.pageSize {
					end = start + f.pageSize
					next = strings.Repeat("x", end)
				}
				res := result{Vulns: []map[string]string{}, NextPageToken: next}
				for _, id := range ids[start:end] {
					res.Vulns = append(res.Vulns, map[string]string{"id": id})
				}
				out.Results = append(out.Results, res)
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			vuln, ok := f.vulns[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(vuln)
		default:
			http.NotFound(w, r)
		}
	})
}

func component(purl string) sbom.Component {
	identity, version, ecosystem, name := sbom.ParseIdentity(purl)
	return sbom.Component{PURL: purl, Identity: identity, Version: version, Ecosystem: ecosystem, Name: name}
}

func lodashAdvisory() Vulnerability {
	var v Vulnerability
	v.ID = "GHSA-35jh-r3h4-6jhm"
	v.Summary = "Command Injection in lodash"
	v.Aliases = []string{"CVE-2021-23337"}
	v.Severity = []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}}
	v.References = []Reference{{Type: "WEB", URL: "https://example.com"}, {Type: "ADVISORY", URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}}
	affected := Affected{}
	affected.Package.Ecosystem = "npm"
	affected.Package.Name = "lodash"
	affected.Ranges = []Range{{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "4.17.21"}}}}
	other := Affected{}
	other.Package.Ecosystem = "npm"
	other.Package.Name = "lodash-es"
	other.Ranges = []Range{{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "9.9.9"}}}}
	v.Affected = []Affected{other, affected}
	return v
}

func TestCheckReturnsFindingsWithSeverityAndFix(t *testing.T) {
	ratedOnly := Vulnerability{ID: "GHSA-rated", Summary: "", Details: "First line of details.\nMore.",
		DatabaseSpecific: DatabaseSpecific{Severity: "MODERATE"}}
	unrated := Vulnerability{ID: "PYSEC-unrated", Summary: "No rating at all"}
	fake := &fakeOSV{
		byPURL: map[string][]string{
			"pkg:npm/lodash@4.17.20":  {"GHSA-35jh-r3h4-6jhm", "GHSA-rated"},
			"pkg:pypi/requests@2.0.0": {"PYSEC-unrated", "GHSA-gone"},
		},
		vulns: map[string]Vulnerability{
			"GHSA-35jh-r3h4-6jhm": lodashAdvisory(),
			"GHSA-rated":          ratedOnly,
			"PYSEC-unrated":       unrated,
		},
	}
	server := httptest.NewServer(fake.handler(t))
	defer server.Close()

	report, err := NewClient(server.URL).Check(context.Background(), []sbom.Component{
		component("pkg:npm/lodash@4.17.20"),
		component("pkg:pypi/requests@2.0.0"),
		component("pkg:npm/clean@1.0.0"),
		component("pkg:deb/debian/curl@7.0"),
		component("pkg:npm/unversioned"),
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if report.Checked != 3 || report.Skipped != 2 {
		t.Errorf("checked/skipped = %d/%d, want 3/2", report.Checked, report.Skipped)
	}
	if len(report.Findings) != 3 {
		t.Fatalf("got %d findings, want 3 (an advisory OSV no longer serves is skipped): %+v", len(report.Findings), report.Findings)
	}

	lodash := report.Findings[0]
	if lodash.OSVID != "GHSA-35jh-r3h4-6jhm" || lodash.Identity != "pkg:npm/lodash" {
		t.Fatalf("first finding = %+v", lodash)
	}
	if lodash.Severity != "HIGH" || lodash.SeveritySource != SourceCVSSv3 || lodash.CVSSScore == nil || *lodash.CVSSScore != 7.2 {
		t.Errorf("lodash severity = %q from %q score %v, want HIGH from cvss_v3 7.2", lodash.Severity, lodash.SeveritySource, lodash.CVSSScore)
	}
	// Only the lodash entry's fixes apply, not lodash-es's.
	if lodash.FixedVersion != "4.17.21" || len(lodash.FixedVersions) != 1 {
		t.Errorf("lodash fix = %q %v, want 4.17.21 only", lodash.FixedVersion, lodash.FixedVersions)
	}
	if lodash.AdvisoryURL != "https://nvd.nist.gov/vuln/detail/CVE-2021-23337" {
		t.Errorf("advisory url = %q", lodash.AdvisoryURL)
	}

	rated := report.Findings[1]
	if rated.Severity != "MEDIUM" || rated.SeveritySource != SourceAdvisory || rated.Summary != "First line of details." {
		t.Errorf("rated finding = %+v", rated)
	}
	if rated.FixedVersion != "" || len(rated.FixedVersions) != 0 || rated.AdvisoryURL != "https://osv.dev/vulnerability/GHSA-rated" {
		t.Errorf("rated finding fix/url = %q %v %q", rated.FixedVersion, rated.FixedVersions, rated.AdvisoryURL)
	}

	if report.Findings[2].Severity != "" || report.Findings[2].SeveritySource != "" {
		t.Errorf("an advisory without a rating must stay unrated, got %+v", report.Findings[2])
	}
}

func TestCheckFollowsPaginationAndIsolatesRejectedQueries(t *testing.T) {
	ids := []string{"A-1", "A-2", "A-3", "A-4", "A-5"}
	vulns := map[string]Vulnerability{}
	for _, id := range ids {
		vulns[id] = Vulnerability{ID: id, DatabaseSpecific: DatabaseSpecific{Severity: "LOW"}}
	}
	fake := &fakeOSV{
		byPURL:   map[string][]string{"pkg:npm/many@1.0.0": ids},
		vulns:    vulns,
		reject:   map[string]bool{"pkg:npm/odd@1.0.0": true},
		pageSize: 2,
	}
	server := httptest.NewServer(fake.handler(t))
	defer server.Close()

	report, err := NewClient(server.URL).Check(context.Background(), []sbom.Component{
		component("pkg:npm/many@1.0.0"), component("pkg:npm/odd@1.0.0"),
		component("pkg:npm/fine@1.0.0"), component("pkg:npm/fine2@2.0.0"),
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(report.Findings) != 5 {
		t.Errorf("got %d findings across pages, want 5", len(report.Findings))
	}
	if report.Checked != 3 || report.Skipped != 1 {
		t.Errorf("checked/skipped = %d/%d, want 3/1 (the rejected query is skipped, not fatal)", report.Checked, report.Skipped)
	}
}

func TestCheckFailsWholeWhenOSVIsUnavailable(t *testing.T) {
	fake := &fakeOSV{fail: http.StatusServiceUnavailable}
	server := httptest.NewServer(fake.handler(t))
	defer server.Close()

	_, err := NewClient(server.URL).Check(context.Background(), []sbom.Component{component("pkg:npm/lodash@4.17.20")})
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("Check error = %v, want an HTTP 503 error", err)
	}
	if strings.Contains(err.Error(), "upstream trouble") {
		t.Errorf("the response body leaked into the error: %v", err)
	}
}

func TestCheckWithNothingToAskMakesNoRequests(t *testing.T) {
	fake := &fakeOSV{}
	server := httptest.NewServer(fake.handler(t))
	defer server.Close()

	report, err := NewClient(server.URL).Check(context.Background(), []sbom.Component{component("pkg:deb/debian/curl@7.0")})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if fake.batches != 0 || report.Checked != 0 || report.Skipped != 1 || len(report.Findings) != 0 {
		t.Errorf("batches=%d report=%+v", fake.batches, report)
	}
}

// OSV lists one vulnerability once per database that published it; those
// records are one finding, not three.
func TestMergeAliasesFoldsOneVulnerabilityFromSeveralDatabases(t *testing.T) {
	score := 7.5
	findings := []Finding{
		{PURL: "pkg:golang/golang.org/x/text@v0.3.5", OSVID: "GO-2021-0113", Aliases: []string{"CVE-2021-38561", "GHSA-ppp9-7jff-5vj2"},
			FixedVersions: []string{"0.3.7"}, FixedVersion: "0.3.7"},
		{PURL: "pkg:golang/golang.org/x/text@v0.3.5", OSVID: "GHSA-ppp9-7jff-5vj2", Aliases: []string{"CVE-2021-38561"},
			Severity: "HIGH", SeveritySource: SourceCVSSv3, CVSSScore: &score, FixedVersions: []string{"0.3.7"}, FixedVersion: "0.3.7"},
		// Linked only through the CVE, transitively.
		{PURL: "pkg:golang/golang.org/x/text@v0.3.5", OSVID: "CVE-2021-38561", Aliases: []string{}},
		{PURL: "pkg:golang/golang.org/x/text@v0.3.5", OSVID: "GO-2022-1059", Aliases: []string{"CVE-2022-32149", "GHSA-69ch-w2m2-3vjp"},
			FixedVersions: []string{"0.3.8"}, FixedVersion: "0.3.8"},
		{PURL: "pkg:golang/golang.org/x/text@v0.3.5", OSVID: "GO-2026-0001", Aliases: []string{}, FixedVersions: []string{"0.39.0"}},
	}
	got := MergeAliases(findings)
	if len(got) != 3 {
		t.Fatalf("merged into %d findings, want 3: %+v", len(got), got)
	}
	first := got[0]
	if first.OSVID != "GHSA-ppp9-7jff-5vj2" || first.Severity != "HIGH" {
		t.Errorf("kept %s (%s), want the GHSA record with its CVSS severity", first.OSVID, first.Severity)
	}
	if strings.Join(first.Aliases, ",") != "CVE-2021-38561,GO-2021-0113" {
		t.Errorf("aliases = %v, want the other records' IDs", first.Aliases)
	}
	if got[1].OSVID != "GO-2022-1059" || got[2].OSVID != "GO-2026-0001" {
		t.Errorf("unrelated records must stay separate: %s, %s", got[1].OSVID, got[2].OSVID)
	}
	if got[2].FixedVersion != "0.39.0" {
		t.Errorf("a record without a recommended fix gets one from its fixed versions: %q", got[2].FixedVersion)
	}
	if single := MergeAliases(findings[:1]); len(single) != 1 {
		t.Error("one finding stays one finding")
	}
}
