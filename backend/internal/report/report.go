// Package report renders one scan as a downloadable SBOM report, as CSV or
// PDF.
//
// Both are built from what the database already holds for the scan (its
// components, vulnerabilities and changes), not from the archived CycloneDX
// document, so a report never depends on blob storage being reachable from
// the reader's browser. Neither format pulls in a dependency: CSV is the
// standard library's, and the PDF is written directly (see pdf.go).
package report

import (
	"regexp"
	"strings"
	"time"

	"sbomdelta/internal/models"
	"sbomdelta/internal/sbom"
)

// Report is everything one scan's report shows.
type Report struct {
	Repository      models.Repository
	Scan            models.Scan
	Components      []sbom.Component
	Vulnerabilities []models.Vulnerability
	Drift           []models.DriftEvent
	Generated       time.Time
}

// Checked reports whether the scan has been checked for vulnerabilities, so
// that an empty list means "none known" rather than "not looked at".
func (r Report) Checked() bool { return r.Scan.EnrichedAt != nil }

// Filename is the download name, e.g. sbomdelta-web-app-e9db50a.pdf. It is
// limited to characters that need no quoting in a Content-Disposition header.
func (r Report) Filename(extension string) string {
	sha := r.Scan.CommitSHA
	if len(sha) > 7 {
		sha = sha[:7]
	}
	name := unsafeFilename.ReplaceAllString(r.Repository.Name+"-"+sha, "-")
	return "sbomdelta-" + strings.Trim(name, "-.") + "." + extension
}

var unsafeFilename = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// severities is the order findings are reported in, worst first; "" is
// unrated.
var severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", ""}

// severity normalizes an advisory's severity the way the risk score does.
func severity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "MODERATE" {
		return "MEDIUM"
	}
	for _, known := range severities {
		if s == known {
			return s
		}
	}
	return ""
}

func severityRank(s string) int {
	for i, known := range severities {
		if severity(s) == known {
			return i
		}
	}
	return len(severities)
}

func severityLabel(s string) string {
	if s = severity(s); s == "" {
		return "UNRATED"
	}
	return s
}

// byComponent groups the vulnerabilities by the component they affect.
func (r Report) byComponent() map[string][]models.Vulnerability {
	out := make(map[string][]models.Vulnerability)
	for _, v := range r.Vulnerabilities {
		out[v.PURL] = append(out[v.PURL], v)
	}
	return out
}

// license is a component's license as one string.
func license(c sbom.Component) string {
	if c.LicenseExpression != "" {
		return c.LicenseExpression
	}
	return strings.Join(c.Licenses, " AND ")
}

// driftCounts is how many dependencies were added, updated and removed.
func (r Report) driftCounts() (added, updated, removed int) {
	for _, e := range r.Drift {
		switch e.ChangeType {
		case "added":
			added++
		case "updated":
			updated++
		case "removed":
			removed++
		}
	}
	return added, updated, removed
}
