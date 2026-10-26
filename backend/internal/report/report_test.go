package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"sbomdelta/internal/models"
	"sbomdelta/internal/sbom"
)

func sampleReport(checked bool) Report {
	analyzed := time.Date(2026, 10, 26, 19, 0, 0, 0, time.UTC)
	baseID := int64(24)
	score := 16.0
	scan := models.Scan{
		ID: 25, RepositoryID: 3, BaseScanID: &baseID,
		CommitSHA: "e9db50ab073fc0ac6500dc8157fb887659640d84", BaseCommitSHA: "326a6b5d0000000000000000000000000000000",
		Trigger: models.TriggerPush, Status: models.ScanCompleted, ComponentCount: 3,
		FinishedAt: &analyzed, CreatedAt: analyzed,
	}
	if checked {
		scan.EnrichedAt, scan.RiskScore, scan.RiskLevel = &analyzed, &score, "medium"
	}
	r := Report{
		Repository: models.Repository{ID: 3, Owner: "devmind2320", Name: "SBOMDelta"},
		Scan:       scan,
		Components: []sbom.Component{
			{PURL: "pkg:golang/golang.org/x/crypto@v0.55.0", Name: "golang.org/x/crypto", Version: "v0.55.0", Ecosystem: "golang", Type: "library", Licenses: []string{"BSD-3-Clause"}},
			{PURL: "pkg:npm/vue@3.5.22", Name: "vue", Version: "3.5.22", Ecosystem: "npm", Type: "library", Direct: true, LicenseExpression: "MIT"},
			{PURL: "pkg:npm/=cmd@1.0.0", Name: "=HYPERLINK(\"https://evil.example\")", Version: "-1+1", Ecosystem: "npm"},
		},
		Drift: []models.DriftEvent{
			{ChangeType: "updated", Name: "vue", OldVersion: "3.5.21", NewVersion: "3.5.22"},
		},
		Generated: analyzed.Add(time.Hour),
	}
	if checked {
		r.Vulnerabilities = []models.Vulnerability{
			{OSVID: "GO-2026-5932", PURL: "pkg:golang/golang.org/x/crypto@v0.55.0", Name: "golang.org/x/crypto", Version: "v0.55.0"},
			{OSVID: "GO-2026-6354", Severity: "HIGH", FixedVersion: "0.56.0", PURL: "pkg:golang/golang.org/x/crypto@v0.55.0", Name: "golang.org/x/crypto", Version: "v0.55.0"},
			{OSVID: "GO-2026-6355", Severity: "moderate", FixedVersion: "0.56.0", PURL: "pkg:golang/golang.org/x/crypto@v0.55.0", Name: "golang.org/x/crypto", Version: "v0.55.0"},
		}
	}
	return r
}

func readCSV(t *testing.T, r Report) [][]string {
	t.Helper()
	var out bytes.Buffer
	if err := WriteCSV(&out, r); err != nil {
		t.Fatalf("WriteCSV() error = %v", err)
	}
	rows, err := csv.NewReader(&out).ReadAll()
	if err != nil {
		t.Fatalf("the CSV does not parse: %v", err)
	}
	return rows
}

func TestCSVHasOneRowPerComponentWithItsVulnerabilities(t *testing.T) {
	rows := readCSV(t, sampleReport(true))
	if len(rows) != 4 {
		t.Fatalf("rows = %d, want a header and 3 components", len(rows))
	}
	if strings.Join(rows[0], ",") != strings.Join(CSVHeader, ",") {
		t.Errorf("header = %v", rows[0])
	}
	crypto := rows[1]
	want := []string{"golang.org/x/crypto", "v0.55.0", "golang", "library", "false", "BSD-3-Clause",
		"pkg:golang/golang.org/x/crypto@v0.55.0", "3", "HIGH", "GO-2026-5932 GO-2026-6354 GO-2026-6355", "0.56.0"}
	if strings.Join(crypto, "|") != strings.Join(want, "|") {
		t.Errorf("crypto row =\n %v\nwant\n %v", crypto, want)
	}
	if vue := rows[2]; vue[4] != "true" || vue[5] != "MIT" || vue[7] != "0" || vue[8] != "" {
		t.Errorf("vue row = %v, want direct, MIT and no vulnerabilities", vue)
	}
}

// A value a spreadsheet would run as a formula is written as text.
func TestCSVNeutralizesFormulas(t *testing.T) {
	row := readCSV(t, sampleReport(true))[3]
	if row[0] != `'=HYPERLINK("https://evil.example")` || row[1] != "'-1+1" {
		t.Errorf("row = %v, want the formula-like cells prefixed with '", row)
	}
}

// Before the vulnerability lookup, the report says so instead of claiming zero.
func TestCSVOfAnUncheckedScanDoesNotReportZero(t *testing.T) {
	for _, row := range readCSV(t, sampleReport(false))[1:] {
		if row[7] != "" || row[8] != "not checked" {
			t.Errorf("row = %v, want an empty count and \"not checked\"", row)
		}
	}
}

func writePDF(t *testing.T, r Report) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := WritePDF(&out, r); err != nil {
		t.Fatalf("WritePDF() error = %v", err)
	}
	return out.Bytes()
}

// checkPDFStructure verifies what a reader relies on to open the file: the
// header, every cross-reference offset landing on its object, the trailer
// pointing at the table, and each stream's declared length. It returns the
// page count.
func checkPDFStructure(t *testing.T, doc []byte) int {
	t.Helper()
	if !bytes.HasPrefix(doc, []byte("%PDF-1.4\n")) || !bytes.HasSuffix(doc, []byte("%%EOF\n")) {
		t.Fatalf("not a complete PDF: %q ... %q", doc[:min(20, len(doc))], doc[max(0, len(doc)-20):])
	}
	start := regexp.MustCompile(`startxref\n(\d+)\n%%EOF\n$`).FindSubmatch(doc)
	if start == nil {
		t.Fatal("no startxref")
	}
	xref, _ := strconv.Atoi(string(start[1]))
	if !bytes.HasPrefix(doc[xref:], []byte("xref\n0 ")) {
		t.Fatalf("startxref %d does not point at the cross-reference table", xref)
	}
	entries := regexp.MustCompile(`(\d{10}) 00000 n \n`).FindAllSubmatch(doc[xref:], -1)
	for i, entry := range entries {
		offset, _ := strconv.Atoi(string(entry[1]))
		if want := fmt.Sprintf("%d 0 obj\n", i+1); !bytes.HasPrefix(doc[offset:], []byte(want)) {
			t.Errorf("xref entry %d points at %q, want %q", i+1, doc[offset:offset+12], want)
		}
	}
	for _, m := range regexp.MustCompile(`<< /Length (\d+) >>\nstream\n`).FindAllSubmatchIndex(doc, -1) {
		length, _ := strconv.Atoi(string(doc[m[2]:m[3]]))
		if end := m[1] + length; !bytes.HasPrefix(doc[end:], []byte("\nendstream")) {
			t.Errorf("a stream's /Length %d does not end at endstream", length)
		}
	}
	return len(regexp.MustCompile(`/Type /Page /Parent`).FindAll(doc, -1))
}

func TestPDFIsWellFormedAndShowsTheScan(t *testing.T) {
	doc := writePDF(t, sampleReport(true))
	if pages := checkPDFStructure(t, doc); pages != 1 {
		t.Errorf("pages = %d, want 1", pages)
	}
	for _, want := range []string{
		"(SBOM report)", "(devmind2320/SBOMDelta)", "(e9db50ab073fc0ac6500dc8157fb887659640d84)",
		"(Vulnerabilities \\(3\\))", "(GO-2026-6354)", "(no fix published)", "(16 \\(medium\\))",
		"(3 known: 0 critical, 1 high, 1 medium, 0 low, 1 unrated; 2 fixable)",
		"(Dependency changes \\(1\\))", "(0 added, 1 updated, 0 removed)", "(Components \\(3\\))", "(Page 1 of 1)",
	} {
		if !bytes.Contains(doc, []byte(want)) {
			t.Errorf("the PDF does not contain %s", want)
		}
	}
	// Worst first: HIGH, then MEDIUM, then unrated.
	high, medium, unrated := bytes.Index(doc, []byte("(GO-2026-6354)")), bytes.Index(doc, []byte("(GO-2026-6355)")), bytes.Index(doc, []byte("(GO-2026-5932)"))
	if !(high < medium && medium < unrated) {
		t.Errorf("vulnerabilities are not ordered by severity: %d %d %d", high, medium, unrated)
	}
}

func TestPDFOfAnUncheckedScanSaysSo(t *testing.T) {
	doc := writePDF(t, sampleReport(false))
	checkPDFStructure(t, doc)
	for _, want := range []string{"(not checked yet)", "(Not checked against OSV.dev yet, so nothing can be said about known vulnerabilities.)"} {
		if !bytes.Contains(doc, []byte(want)) {
			t.Errorf("the PDF does not contain %s", want)
		}
	}
	if bytes.Contains(doc, []byte("0 known")) {
		t.Error("an unchecked scan is reported as having no vulnerabilities")
	}
}

// Text from the scanned repository cannot end a PDF string early, and a long
// component list continues on further pages, each with the table header.
func TestPDFEscapesTextAndPaginates(t *testing.T) {
	r := sampleReport(true)
	r.Components = nil
	for i := range 150 {
		r.Components = append(r.Components, sbom.Component{
			PURL: fmt.Sprintf("pkg:npm/p%d@1", i), Name: fmt.Sprintf(`evil) Tj ET (\%d`, i), Version: "1", Ecosystem: "npm",
		})
	}
	r.Components[0].Name = "ünïcode – 世界 " + strings.Repeat("long", 40)
	doc := writePDF(t, r)
	pages := checkPDFStructure(t, doc)
	if pages < 3 {
		t.Errorf("pages = %d, want the 150 components spread over several", pages)
	}
	if got := bytes.Count(doc, []byte("(Ecosystem)")); got != pages {
		t.Errorf("the components table header appears %d times over %d pages", got, pages)
	}
	if bytes.Contains(doc, []byte("(evil) Tj")) || !bytes.Contains(doc, []byte(`(evil\) Tj ET \(\\1)`)) {
		t.Error("a component name is not escaped")
	}
	if !bytes.Contains(doc, []byte("(\xfcn\xefcode \x96 ?? longlong")) {
		t.Error("non-ASCII text is not encoded for WinAnsi")
	}
	if !bytes.Contains(doc, []byte(fmt.Sprintf("(Page %d of %d)", pages, pages))) {
		t.Error("the last page is not numbered")
	}
}

func TestFilenameIsSafeForTheHeader(t *testing.T) {
	r := sampleReport(true)
	if got := r.Filename("pdf"); got != "sbomdelta-SBOMDelta-e9db50a.pdf" {
		t.Errorf("Filename() = %q", got)
	}
	r.Repository.Name = `a"b;c/..\d`
	if got := r.Filename("csv"); got != "sbomdelta-a-b-c-..-d-e9db50a.csv" {
		t.Errorf("Filename() = %q", got)
	}
}

func TestWrapAndFit(t *testing.T) {
	if got := fit("abcdefghij", 10, 6*7); got != "abcd..." {
		t.Errorf("fit() = %q", got)
	}
	if got := fit("short", 10, 600); got != "short" {
		t.Errorf("fit() = %q", got)
	}
	if got := wrap("one two three "+strings.Repeat("x", 12), 9); strings.Join(got, "|") != "one two|three|xxxxxxxxx|xxx" {
		t.Errorf("wrap() = %q", got)
	}
}
