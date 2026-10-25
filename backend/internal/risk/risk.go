// Package risk turns a scan's vulnerability findings into a score a person
// can check by hand.
//
// The model is deliberately simple and fully deterministic: the same findings
// always give the same score, every point is attributed to a named factor,
// and nothing is estimated (no exploit probabilities, no reachability
// guesses). It answers "how much known-vulnerable code does this commit
// ship, weighted by severity", which is what the stored data supports.
//
// Score
//
//	Each finding (one advisory on one component) earns points by severity:
//	    CRITICAL 10, HIGH 6, MEDIUM 3, LOW 1, unrated 2.
//	A finding on a direct dependency (one the project declares itself, when
//	the SBOM records that) earns 1.5x, because it is the project's own
//	choice and the quickest to change.
//	The score is the sum, rounded to one decimal place and capped at 100.
//
// Level
//
//	none      score 0 (no known advisories)
//	low       below 10
//	medium    10 to below 25
//	high      25 to below 50
//	critical  50 and above
//
// A scan that has not been checked against the vulnerability database has no
// score at all: "unknown" is never reported as zero.
package risk

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Method describes the model in one paragraph, for the API and the UI.
const Method = "Each known vulnerability on a component scores by severity (critical 10, high 6, medium 3, " +
	"low 1, unrated 2), multiplied by 1.5 when the component is a direct dependency. The score is the sum, " +
	"capped at 100. Levels: none (0), low (<10), medium (<25), high (<50), critical (50+). " +
	"Only vulnerabilities reported by OSV.dev for the scanned versions count; nothing is estimated."

// Weights per severity.
var Weights = map[string]float64{
	"CRITICAL": 10,
	"HIGH":     6,
	"MEDIUM":   3,
	"LOW":      1,
	"":         2,
}

// DirectMultiplier applies to findings on direct dependencies.
const DirectMultiplier = 1.5

// MaxScore caps the score.
const MaxScore = 100

// Levels.
const (
	LevelNone     = "none"
	LevelLow      = "low"
	LevelMedium   = "medium"
	LevelHigh     = "high"
	LevelCritical = "critical"
)

// Finding is the part of a stored vulnerability the model reads.
type Finding struct {
	OSVID        string `json:"osvId"`
	Package      string `json:"package"`
	Version      string `json:"version"`
	Identity     string `json:"identity"`
	PURL         string `json:"purl"`
	Severity     string `json:"severity"`
	Direct       bool   `json:"direct"`
	FixedVersion string `json:"fixedVersion,omitempty"`
}

// Factor is one named contribution to the score.
type Factor struct {
	Key         string  `json:"key"`
	Label       string  `json:"label"`
	Count       int     `json:"count"`
	Points      float64 `json:"points"`
	Explanation string  `json:"explanation"`
}

// Contributor is one finding and the points it earned.
type Contributor struct {
	Finding
	Points float64 `json:"points"`
}

// Assessment is a scored scan.
type Assessment struct {
	Score float64 `json:"score"`
	Level string  `json:"level"`
	// Uncapped is the sum before the cap, shown when the cap applied.
	Uncapped float64  `json:"uncapped"`
	Factors  []Factor `json:"factors"`
	// Top lists the highest-scoring findings, most points first.
	Top     []Contributor `json:"top"`
	Fixable int           `json:"fixable"`
	Total   int           `json:"total"`
	Method  string        `json:"method"`
}

// Points is what one finding earns.
func Points(f Finding) float64 {
	points := Weights[normalize(f.Severity)]
	if f.Direct {
		points *= DirectMultiplier
	}
	return points
}

func normalize(severity string) string {
	severity = strings.ToUpper(strings.TrimSpace(severity))
	if severity == "MODERATE" {
		return "MEDIUM"
	}
	if _, ok := Weights[severity]; !ok {
		return ""
	}
	return severity
}

// Assess scores a set of findings.
func Assess(findings []Finding) Assessment {
	out := Assessment{Factors: []Factor{}, Top: []Contributor{}, Method: Method, Total: len(findings)}

	type group struct {
		count  int
		points float64
	}
	bySeverity := map[string]*group{}
	var directExtra float64
	directCount := 0
	contributors := make([]Contributor, 0, len(findings))
	for _, f := range findings {
		severity := normalize(f.Severity)
		base := Weights[severity]
		g := bySeverity[severity]
		if g == nil {
			g = &group{}
			bySeverity[severity] = g
		}
		g.count++
		g.points += base
		points := base
		if f.Direct {
			directCount++
			directExtra += base * (DirectMultiplier - 1)
			points = base * DirectMultiplier
		}
		if f.FixedVersion != "" {
			out.Fixable++
		}
		out.Uncapped += points
		contributors = append(contributors, Contributor{Finding: f, Points: points})
	}

	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", ""} {
		g := bySeverity[severity]
		if g == nil {
			continue
		}
		name := strings.ToLower(severity)
		key := "severity_" + name
		label := fmt.Sprintf("%d %s-severity vulnerabilit%s", g.count, name, plural(g.count))
		explanation := fmt.Sprintf("%d × %s points for each %s finding.", g.count, trim(Weights[severity]), name)
		if severity == "" {
			key = "severity_unrated"
			label = fmt.Sprintf("%d unrated vulnerabilit%s", g.count, plural(g.count))
			explanation = fmt.Sprintf("%d × %s points: the advisory gives no severity, so it is not counted as harmless.",
				g.count, trim(Weights[""]))
		}
		out.Factors = append(out.Factors, Factor{Key: key, Label: label, Count: g.count, Points: round1(g.points), Explanation: explanation})
	}
	if directCount > 0 {
		out.Factors = append(out.Factors, Factor{
			Key:         "direct_dependency",
			Label:       fmt.Sprintf("%d on direct dependencies", directCount),
			Count:       directCount,
			Points:      round1(directExtra),
			Explanation: fmt.Sprintf("Findings on dependencies the project declares itself count %sx.", trim(DirectMultiplier)),
		})
	}

	out.Uncapped = round1(out.Uncapped)
	out.Score = math.Min(out.Uncapped, MaxScore)
	out.Level = LevelFor(out.Score)

	sort.SliceStable(contributors, func(i, j int) bool {
		if contributors[i].Points != contributors[j].Points {
			return contributors[i].Points > contributors[j].Points
		}
		if contributors[i].Package != contributors[j].Package {
			return contributors[i].Package < contributors[j].Package
		}
		return contributors[i].OSVID < contributors[j].OSVID
	})
	if len(contributors) > 10 {
		contributors = contributors[:10]
	}
	out.Top = contributors
	return out
}

// LevelFor maps a score onto its level.
func LevelFor(score float64) string {
	switch {
	case score <= 0:
		return LevelNone
	case score < 10:
		return LevelLow
	case score < 25:
		return LevelMedium
	case score < 50:
		return LevelHigh
	default:
		return LevelCritical
	}
}

// Key identifies a finding across scans: the same advisory on the same
// package, whatever version.
type Key struct {
	Identity string
	OSVID    string
}

// Comparison is how a scan's findings differ from its base scan's.
type Comparison struct {
	Introduced []Finding `json:"introduced"`
	Resolved   []Finding `json:"resolved"`
	Unchanged  int       `json:"unchanged"`
}

// Compare reports the findings in head that base does not have
// (introduced), and those in base that head no longer has (resolved). A
// package upgraded from one vulnerable version to another that is still
// affected by the same advisory is unchanged, not resolved-and-reintroduced.
func Compare(base, head []Finding) Comparison {
	inBase := map[Key]Finding{}
	for _, f := range base {
		inBase[Key{f.Identity, f.OSVID}] = f
	}
	inHead := map[Key]bool{}
	out := Comparison{Introduced: []Finding{}, Resolved: []Finding{}}
	for _, f := range head {
		key := Key{f.Identity, f.OSVID}
		if inHead[key] {
			continue
		}
		inHead[key] = true
		if _, ok := inBase[key]; ok {
			out.Unchanged++
		} else {
			out.Introduced = append(out.Introduced, f)
		}
	}
	seen := map[Key]bool{}
	for _, f := range base {
		key := Key{f.Identity, f.OSVID}
		if inHead[key] || seen[key] {
			continue
		}
		seen[key] = true
		out.Resolved = append(out.Resolved, f)
	}
	bySeverity := func(list []Finding) {
		sort.SliceStable(list, func(i, j int) bool {
			if Weights[normalize(list[i].Severity)] != Weights[normalize(list[j].Severity)] {
				return Weights[normalize(list[i].Severity)] > Weights[normalize(list[j].Severity)]
			}
			if list[i].Package != list[j].Package {
				return list[i].Package < list[j].Package
			}
			return list[i].OSVID < list[j].OSVID
		})
	}
	bySeverity(out.Introduced)
	bySeverity(out.Resolved)
	return out
}

// Blocking reports whether any finding is critical or high: what fails a
// pull request's check.
func Blocking(findings []Finding) int {
	n := 0
	for _, f := range findings {
		switch normalize(f.Severity) {
		case "CRITICAL", "HIGH":
			n++
		}
	}
	return n
}

func round1(value float64) float64 { return math.Round(value*10) / 10 }

func trim(value float64) string {
	return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%.1f", value), "0"), ".")
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
