package report

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"sbomdelta/internal/models"
)

// The PDF is written directly rather than through a library: it needs only
// text and rules on A4 pages, in the standard Helvetica and Courier fonts,
// which every PDF reader has, so nothing is embedded. Tables are set in
// Courier, whose fixed width lets a cell be cut to fit exactly.

const (
	pageWidth  = 595.0
	pageHeight = 842.0
	margin     = 40.0
	footerY    = 24.0
	bodySize   = 8.0
	rowHeight  = 11.0
	// charWidth is the width of one Courier character, per point of size.
	charWidth = 0.6
)

// Font resource names, as each page declares them.
const (
	helvetica     = "F1"
	helveticaBold = "F2"
	courier       = "F3"
	courierBold   = "F4"
)

var fonts = []string{"Helvetica", "Helvetica-Bold", "Courier", "Courier-Bold"}

// WritePDF writes the report as a PDF document.
func WritePDF(w io.Writer, r Report) error {
	p := &pdf{}
	p.newPage()

	p.text(margin, p.y, helveticaBold, 18, "SBOM report")
	p.y -= 20
	p.text(margin, p.y, helvetica, 11, fitHelvetica(r.Repository.FullName(), 11, pageWidth-2*margin))
	p.y -= 24

	added, updated, removed := r.driftCounts()
	direct := 0
	for _, c := range r.Components {
		if c.Direct {
			direct++
		}
	}
	scanned := r.Scan.CreatedAt
	if r.Scan.FinishedAt != nil {
		scanned = *r.Scan.FinishedAt
	}
	compared := "nothing: this scan is the repository's baseline"
	if r.Scan.BaseScanID != nil {
		compared = r.Scan.BaseCommitSHA
	}
	facts := [][2]string{
		{"Repository", r.Repository.FullName()},
		{"Commit", r.Scan.CommitSHA},
		{"Trigger", strings.ReplaceAll(string(r.Scan.Trigger), "_", " ")},
		{"Status", string(r.Scan.Status)},
		{"Scanned", formatTime(scanned)},
		{"Compared with", compared},
		{"Components", fmt.Sprintf("%d (%d direct)", len(r.Components), direct)},
	}
	if r.Scan.BaseScanID != nil {
		facts = append(facts, [2]string{"Changes", fmt.Sprintf("%d added, %d updated, %d removed", added, updated, removed)})
	}
	facts = append(facts, [2]string{"Vulnerabilities", r.vulnerabilityLine()})
	facts = append(facts, [2]string{"Risk score", r.riskLine()})
	if r.Scan.SBOMSHA256 != "" {
		facts = append(facts, [2]string{"SBOM sha256", r.Scan.SBOMSHA256})
	}
	facts = append(facts, [2]string{"Generated", formatTime(r.Generated)})
	for _, fact := range facts {
		p.text(margin, p.y, helveticaBold, 9, fact[0])
		p.text(margin+90, p.y, courier, 9, fit(fact[1], 9, pageWidth-2*margin-90))
		p.y -= 13
	}

	p.heading(fmt.Sprintf("Vulnerabilities (%d)", len(r.Vulnerabilities)))
	switch {
	case !r.Checked():
		p.note("Not checked against OSV.dev yet, so nothing can be said about known vulnerabilities.")
	case len(r.Vulnerabilities) == 0:
		p.note("OSV.dev lists no known vulnerabilities for these component versions.")
	default:
		vulnerabilities := slices.Clone(r.Vulnerabilities)
		slices.SortStableFunc(vulnerabilities, func(a, b models.Vulnerability) int {
			if d := severityRank(a.Severity) - severityRank(b.Severity); d != 0 {
				return d
			}
			return strings.Compare(a.Name+"\x00"+a.OSVID, b.Name+"\x00"+b.OSVID)
		})
		rows := make([][]string, 0, len(vulnerabilities))
		for _, v := range vulnerabilities {
			fixed := v.FixedVersion
			if fixed == "" {
				fixed = "no fix published"
			}
			rows = append(rows, []string{severityLabel(v.Severity), v.OSVID, v.Name, v.Version, fixed})
		}
		p.table([]column{{"Severity", 9}, {"Advisory", 20}, {"Package", 36}, {"Version", 18}, {"Fixed in", 18}}, rows)
	}

	if r.Scan.BaseScanID != nil {
		p.heading(fmt.Sprintf("Dependency changes (%d)", len(r.Drift)))
		if len(r.Drift) == 0 {
			p.note("No dependency changed against " + shortSHA(r.Scan.BaseCommitSHA) + ".")
		} else {
			rows := make([][]string, 0, len(r.Drift))
			for _, e := range r.Drift {
				rows = append(rows, []string{e.ChangeType, e.Name, e.OldVersion, e.NewVersion})
			}
			p.table([]column{{"Change", 8}, {"Package", 50}, {"From", 22}, {"To", 22}}, rows)
		}
	}

	p.heading(fmt.Sprintf("Components (%d)", len(r.Components)))
	if len(r.Components) == 0 {
		p.note("The SBOM lists no components.")
	} else {
		rows := make([][]string, 0, len(r.Components))
		for _, c := range r.Components {
			directLabel := "no"
			if c.Direct {
				directLabel = "yes"
			}
			rows = append(rows, []string{c.Name, c.Version, c.Ecosystem, directLabel, license(c)})
		}
		p.table([]column{{"Name", 40}, {"Version", 20}, {"Ecosystem", 10}, {"Direct", 6}, {"License", 26}}, rows)
	}

	footer := "SBOMDelta · " + r.Repository.FullName() + " @ " + shortSHA(r.Scan.CommitSHA)
	_, err := w.Write(p.document(r.Repository.FullName()+" "+shortSHA(r.Scan.CommitSHA), r.Generated, footer))
	return err
}

func (r Report) vulnerabilityLine() string {
	if !r.Checked() {
		if r.Scan.EnrichmentError != "" {
			return "not checked: the lookup failed (" + r.Scan.EnrichmentError + ")"
		}
		return "not checked yet"
	}
	counts := map[string]int{}
	fixable := 0
	for _, v := range r.Vulnerabilities {
		counts[severity(v.Severity)]++
		if v.FixedVersion != "" {
			fixable++
		}
	}
	return fmt.Sprintf("%d known: %d critical, %d high, %d medium, %d low, %d unrated; %d fixable",
		len(r.Vulnerabilities), counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts[""], fixable)
}

func (r Report) riskLine() string {
	if !r.Checked() || r.Scan.RiskScore == nil {
		return "not scored: the scan has not been checked for vulnerabilities"
	}
	line := strconv.FormatFloat(*r.Scan.RiskScore, 'f', -1, 64)
	if r.Scan.RiskLevel != "" {
		line += " (" + r.Scan.RiskLevel + ")"
	}
	return line
}

func formatTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// pdf collects the pages' content streams; document assembles the file.
type pdf struct {
	pages []*bytes.Buffer
	page  *bytes.Buffer
	// y is the baseline of the next line, from the bottom of the page.
	y float64
}

type column struct {
	title string
	// chars is the column's width in Courier characters.
	chars int
}

func (p *pdf) newPage() {
	p.page = &bytes.Buffer{}
	p.pages = append(p.pages, p.page)
	p.y = pageHeight - margin
}

// room starts a new page unless height fits above the footer, and reports
// whether it did.
func (p *pdf) room(height float64) bool {
	if p.y-height < footerY+20 {
		p.newPage()
		return true
	}
	return false
}

func (p *pdf) text(x, y float64, font string, size float64, s string) {
	fmt.Fprintf(p.page, "BT /%s %g Tf %.2f %.2f Td (%s) Tj ET\n", font, size, x, y, encode(s))
}

func (p *pdf) rule(y float64) {
	fmt.Fprintf(p.page, "0.75 G 0.5 w %.2f %.2f m %.2f %.2f l S 0 G\n", margin, y, pageWidth-margin, y)
}

func (p *pdf) heading(title string) {
	p.room(60)
	p.y -= 14
	p.text(margin, p.y, helveticaBold, 12, title)
	p.y -= 6
	p.rule(p.y)
	p.y -= 13
}

// note is a line or more of plain text, wrapped to the page.
func (p *pdf) note(s string) {
	limit := (pageWidth - 2*margin) / (charWidth * 9)
	for _, line := range wrap(s, int(limit)) {
		p.room(13)
		p.text(margin, p.y, courier, 9, line)
		p.y -= 13
	}
}

// table writes rows under a header, repeating the header on each new page.
func (p *pdf) table(columns []column, rows [][]string) {
	const gap = 6.0
	width := func(c column) float64 { return float64(c.chars) * charWidth * bodySize }
	header := func() {
		x := margin
		for _, c := range columns {
			p.text(x, p.y, courierBold, bodySize, fit(c.title, bodySize, width(c)))
			x += width(c) + gap
		}
		p.y -= 4
		p.rule(p.y)
		p.y -= rowHeight - 2
	}
	p.room(rowHeight * 3)
	header()
	for _, row := range rows {
		if p.room(rowHeight) {
			header()
		}
		x := margin
		for i, c := range columns {
			p.text(x, p.y, courier, bodySize, fit(row[i], bodySize, width(c)))
			x += width(c) + gap
		}
		p.y -= rowHeight
	}
}

// document assembles the PDF: catalog, page tree, fonts, information
// dictionary, then each page and its content stream, and the cross-reference
// table that locates them.
func (p *pdf) document(title string, created time.Time, footer string) []byte {
	var out bytes.Buffer
	var offsets []int
	object := func(body string) {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", len(offsets), body)
	}

	// Objects 1 to 7 are fixed; page i is object 8+2i, its content 9+2i.
	const firstPage = 8
	kids := make([]string, len(p.pages))
	for i := range p.pages {
		kids[i] = fmt.Sprintf("%d 0 R", firstPage+2*i)
	}
	fontRefs := make([]string, len(fonts))
	for i := range fonts {
		fontRefs[i] = fmt.Sprintf("/F%d %d 0 R", i+1, 3+i)
	}

	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	object("<< /Type /Catalog /Pages 2 0 R >>")
	object(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(p.pages)))
	for _, font := range fonts {
		object("<< /Type /Font /Subtype /Type1 /BaseFont /" + font + " /Encoding /WinAnsiEncoding >>")
	}
	object(fmt.Sprintf("<< /Title (%s) /Producer (SBOMDelta) /CreationDate (D:%s) >>",
		encode(title), created.UTC().Format("20060102150405Z")))
	for i, page := range p.pages {
		p.page = page
		p.text(margin, footerY, helvetica, 7, fitHelvetica(footer, 7, pageWidth-2*margin-60))
		pageNumber := fmt.Sprintf("Page %d of %d", i+1, len(p.pages))
		p.text(pageWidth-margin-float64(len(pageNumber))*charWidth*7, footerY, courier, 7, pageNumber)

		object(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %g %g] /Resources << /Font << %s >> >> /Contents %d 0 R >>",
			pageWidth, pageHeight, strings.Join(fontRefs, " "), firstPage+2*i+1))
		object(fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", page.Len(), page.Bytes()))
	}

	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /Info 7 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, xref)
	return out.Bytes()
}

// fit cuts s to the Courier characters that fit in width at size, and marks
// the cut.
func fit(s string, size, width float64) string {
	limit := int(width / (charWidth * size))
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	if limit <= 3 {
		return string(runes[:max(limit, 0)])
	}
	return string(runes[:limit-3]) + "..."
}

// fitHelvetica cuts s for Helvetica, counting every character as wide as
// its widest (about one em), so the text can never overflow.
func fitHelvetica(s string, size, width float64) string {
	return fit(s, size*1.02/charWidth, width)
}

// wrap breaks s into lines of at most limit characters, at spaces where it
// can.
func wrap(s string, limit int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		for len([]rune(word)) > limit {
			if line != "" {
				lines, line = append(lines, line), ""
			}
			runes := []rune(word)
			lines, word = append(lines, string(runes[:limit])), string(runes[limit:])
		}
		switch {
		case line == "":
			line = word
		case len([]rune(line))+1+len([]rune(word)) <= limit:
			line += " " + word
		default:
			lines, line = append(lines, line), word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// winAnsi maps the typographic characters outside Latin-1 that
// WinAnsiEncoding has to their codes.
var winAnsi = map[rune]byte{
	'€': 0x80, '‚': 0x82, '„': 0x84, '…': 0x85, '•': 0x95, '–': 0x96, '—': 0x97,
	'‘': 0x91, '’': 0x92, '“': 0x93, '”': 0x94, '™': 0x99,
}

// encode turns s into the bytes of a PDF literal string in WinAnsiEncoding:
// one byte per character, with the delimiters escaped. Characters the
// standard fonts cannot show become '?', and control characters spaces, so
// nothing in a package name or advisory can break out of the string.
func encode(s string) string {
	var out strings.Builder
	for _, r := range s {
		switch {
		case r == '(' || r == ')' || r == '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case r < 0x20:
			out.WriteByte(' ')
		case r < 0x7f:
			out.WriteRune(r)
		case r >= 0xa0 && r <= 0xff:
			out.WriteByte(byte(r))
		default:
			if b, ok := winAnsi[r]; ok {
				out.WriteByte(b)
			} else {
				out.WriteByte('?')
			}
		}
	}
	return out.String()
}
