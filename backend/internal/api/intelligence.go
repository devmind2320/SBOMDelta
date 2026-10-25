package api

import (
	"net/http"
	"strconv"
	"strings"

	"sbomdelta/internal/auth"
	"sbomdelta/internal/models"
	"sbomdelta/internal/risk"
)

// scope is who an across-repositories question is asked for: the signed-in
// user's tracked repositories, or every repository when sign-in is disabled
// for local development.
func (a *API) scope(r *http.Request) (userID int64, allRepositories bool) {
	if a.auth.Disabled() {
		return 0, true
	}
	user, _ := auth.UserFrom(r.Context())
	return user.ID, false
}

// listRecentScans returns the newest scans of the user's tracked
// repositories ("Last scans"), optionally for one repository
// (?repositoryId=), with drift, vulnerability and risk numbers.
func (a *API) listRecentScans(w http.ResponseWriter, r *http.Request) {
	var repositoryID int64
	if raw := r.URL.Query().Get("repositoryId"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id <= 0 {
			writeError(w, http.StatusBadRequest, "repositoryId must be a positive integer")
			return
		}
		if !a.authorizeRepository(w, r, id) {
			return
		}
		repositoryID = id
	}
	userID, all := a.scope(r)
	scans, err := a.db.ListRecentScans(r.Context(), userID, all, repositoryID, limitParam(r, 20, 100))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": scans})
}

// scanRisk explains a scan's risk score: the factors and findings that make
// it up, and how it is computed. An unanalyzed scan has no score, and says
// why, rather than reporting zero.
func (a *API) scanRisk(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if !a.authorizeScan(w, r, id) {
		return
	}
	scan, err := a.db.GetScan(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if scan.EnrichedAt == nil {
		reason := "This scan has not been checked for vulnerabilities yet."
		switch {
		case scan.Status != models.ScanCompleted:
			reason = "The scan has not completed."
		case scan.EnrichmentError != "":
			reason = "The vulnerability lookup failed: " + scan.EnrichmentError
		}
		writeJSON(w, http.StatusOK, map[string]any{"scored": false, "reason": reason, "method": risk.Method})
		return
	}
	findings, err := a.db.ScanFindings(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scored":     true,
		"assessment": risk.Assess(findings),
		"delta":      scan.RiskDelta,
		"analyzedAt": scan.EnrichedAt,
		"method":     risk.Method,
	})
}

// vulnerabilityChanges compares a scan's vulnerabilities with its base
// scan's: what the change introduced and what it resolved. It answers
// available: false, with a reason, when either side has not been checked or
// there is no base to compare with.
func (a *API) vulnerabilityChanges(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if !a.authorizeScan(w, r, id) {
		return
	}
	scan, err := a.db.GetScan(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	unavailable := func(reason string) {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "reason": reason, "baseScanId": scan.BaseScanID})
	}
	switch {
	case scan.EnrichedAt == nil:
		unavailable("This scan has not been checked for vulnerabilities yet.")
		return
	case scan.BaseScanID == nil:
		unavailable("This scan is a baseline: there is no earlier scan to compare with.")
		return
	}
	base, err := a.db.GetScan(r.Context(), *scan.BaseScanID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if base.EnrichedAt == nil {
		unavailable("The scan this one is compared with has not been checked for vulnerabilities yet.")
		return
	}
	head, err := a.db.ScanFindings(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	before, err := a.db.ScanFindings(r.Context(), base.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"available":  true,
		"baseScanId": base.ID,
		"comparison": risk.Compare(before, head),
		"riskDelta":  scan.RiskDelta,
	})
}

// vulnerabilityImpact lists advisories affecting the latest scans of the
// user's tracked repositories, each with every repository it affects.
func (a *API) vulnerabilityImpact(w http.ResponseWriter, r *http.Request) {
	userID, all := a.scope(r)
	impact, coverage, err := a.db.VulnerabilityImpact(r.Context(), userID, all, limitParam(r, 100, 500))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"vulnerabilities": impact, "coverage": coverage})
}

// componentImpact finds a dependency (?q=, by name or package URL) across
// the latest scans of the user's tracked repositories.
func (a *API) componentImpact(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) < 2 {
		writeError(w, http.StatusBadRequest, "q must be at least 2 characters")
		return
	}
	if len(q) > 200 {
		writeError(w, http.StatusBadRequest, "q must be at most 200 characters")
		return
	}
	userID, all := a.scope(r)
	components, coverage, err := a.db.ComponentImpact(r.Context(), userID, all, q, limitParam(r, 50, 200))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"components": components, "coverage": coverage, "query": q})
}
