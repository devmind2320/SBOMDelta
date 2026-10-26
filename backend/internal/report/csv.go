package report

import (
	"encoding/csv"
	"io"
	"slices"
	"strconv"
	"strings"
)

// CSVHeader is the first row of the CSV report.
var CSVHeader = []string{
	"name", "version", "ecosystem", "type", "direct", "license", "purl",
	"vulnerabilities", "highest_severity", "advisories", "fixed_in",
}

// WriteCSV writes one row per component, with the vulnerabilities known for
// it. On a scan not yet checked for vulnerabilities, those columns say so
// instead of reporting zero.
func WriteCSV(w io.Writer, r Report) error {
	out := csv.NewWriter(w)
	if err := out.Write(CSVHeader); err != nil {
		return err
	}
	vulnerabilities := r.byComponent()
	for _, c := range r.Components {
		count, highest, advisories, fixed := "", "not checked", "", ""
		if r.Checked() {
			found := vulnerabilities[c.PURL]
			count, highest = strconv.Itoa(len(found)), ""
			ids := make([]string, 0, len(found))
			fixes := make([]string, 0, len(found))
			for i, v := range found {
				if i == 0 || severityRank(v.Severity) < severityRank(highest) {
					highest = severityLabel(v.Severity)
				}
				ids = append(ids, v.OSVID)
				if v.FixedVersion != "" && !slices.Contains(fixes, v.FixedVersion) {
					fixes = append(fixes, v.FixedVersion)
				}
			}
			advisories, fixed = strings.Join(ids, " "), strings.Join(fixes, " ")
		}
		row := []string{
			c.Name, c.Version, c.Ecosystem, c.Type, strconv.FormatBool(c.Direct), license(c), c.PURL,
			count, highest, advisories, fixed,
		}
		for i := range row {
			row[i] = cell(row[i])
		}
		if err := out.Write(row); err != nil {
			return err
		}
	}
	out.Flush()
	return out.Error()
}

// cell keeps a spreadsheet from reading a value as a formula. Package names
// and versions come from the scanned repository, which anyone with push
// access controls.
func cell(value string) string {
	if value != "" && strings.ContainsRune("=+-@\t\r", rune(value[0])) {
		return "'" + value
	}
	return value
}
