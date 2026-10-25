package osv

import (
	"math"
	"strings"
)

// CVSSv3BaseScore computes the base score of a CVSS v3.0 or v3.1 vector
// using the formulas in the FIRST specification
// (https://www.first.org/cvss/v3.1/specification-document, section 7). It
// reports false for anything that is not a complete v3 base vector.
func CVSSv3BaseScore(vector string) (float64, bool) {
	parts := strings.Split(vector, "/")
	if len(parts) < 9 || (parts[0] != "CVSS:3.0" && parts[0] != "CVSS:3.1") {
		return 0, false
	}
	metrics := map[string]string{}
	for _, part := range parts[1:] {
		key, value, ok := strings.Cut(part, ":")
		if !ok {
			return 0, false
		}
		metrics[key] = value
	}

	scopeChanged := metrics["S"] == "C"
	if metrics["S"] != "C" && metrics["S"] != "U" {
		return 0, false
	}
	av, ok1 := lookup(metrics["AV"], map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac, ok2 := lookup(metrics["AC"], map[string]float64{"L": 0.77, "H": 0.44})
	prWeights := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scopeChanged {
		prWeights = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr, ok3 := lookup(metrics["PR"], prWeights)
	ui, ok4 := lookup(metrics["UI"], map[string]float64{"N": 0.85, "R": 0.62})
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, ok5 := lookup(metrics["C"], cia)
	i, ok6 := lookup(metrics["I"], cia)
	a, ok7 := lookup(metrics["A"], cia)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploitability := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, true
	}
	if scopeChanged {
		return roundUp(math.Min(1.08*(impact+exploitability), 10)), true
	}
	return roundUp(math.Min(impact+exploitability, 10)), true
}

func lookup(value string, weights map[string]float64) (float64, bool) {
	weight, ok := weights[value]
	return weight, ok
}

// roundUp is the specification's Roundup: the smallest number with one
// decimal place that is equal to or higher than its input, computed on
// integers to avoid floating-point surprises (Appendix A).
func roundUp(value float64) float64 {
	scaled := int64(math.Round(value * 100000))
	if scaled%10000 == 0 {
		return float64(scaled) / 100000
	}
	return float64(scaled/10000+1) / 10
}

// CVSSv3Rating is the qualitative rating for a base score (specification
// section 5). A score of 0 is "None", which is not a severity worth showing,
// so it maps to LOW only when above zero.
func CVSSv3Rating(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return ""
	}
}
