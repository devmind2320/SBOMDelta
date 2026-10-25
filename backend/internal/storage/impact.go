package storage

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"sbomdelta/internal/models"
	"sbomdelta/internal/risk"
	"sbomdelta/internal/sbom"
)

// impactScope is the set of repositories an impact question is asked over,
// each with its latest completed default-branch scan (scan columns NULL
// when it has none): the repositories the user tracks and can still access,
// or every repository SBOMDelta can reach when sign-in is disabled for
// local development. $1 is the user.
func impactScope(allRepositories bool) string {
	scope := `
		SELECT r.id, r.owner, r.name FROM repositories r
		JOIN user_tracked_repositories t ON t.repository_id = r.id AND t.user_id = $1
		WHERE ` + userCanAccess("r")
	if allRepositories {
		scope = `
		SELECT r.id, r.owner, r.name FROM repositories r
		WHERE $1::bigint IS NOT NULL AND ` + aliasedRepositoryAccess + ` = 'active'`
	}
	return `
		WITH scope AS (` + scope + `),
		latest AS (
			SELECT sc.id AS repo_id, sc.owner, sc.name, lc.id AS scan_id, lc.commit_sha, lc.enriched_at
			FROM scope sc
			LEFT JOIN LATERAL (
				SELECT s.id, s.commit_sha, s.enriched_at FROM scans s
				WHERE s.repository_id = sc.id AND s.pull_request_id IS NULL AND s.trigger <> 'backfill'
				  AND s.status = 'completed'
				ORDER BY s.created_at DESC, s.id DESC
				LIMIT 1) lc ON true
		)`
}

func (db *DB) impactCoverage(ctx context.Context, userID int64, allRepositories bool) (models.ImpactCoverage, error) {
	var c models.ImpactCoverage
	err := db.pool.QueryRow(ctx, impactScope(allRepositories)+`
		SELECT COUNT(*), COUNT(scan_id), COUNT(enriched_at) FROM latest`, userID).
		Scan(&c.Repositories, &c.Scanned, &c.Analyzed)
	if err != nil {
		return models.ImpactCoverage{}, fmt.Errorf("impact coverage: %w", err)
	}
	return c, nil
}

// VulnerabilityImpact lists the advisories affecting the latest scans of a
// user's tracked repositories, each with the repositories it affects: the
// most severe first, then those affecting the most repositories.
func (db *DB) VulnerabilityImpact(ctx context.Context, userID int64, allRepositories bool, limit int) ([]models.ImpactVulnerability, models.ImpactCoverage, error) {
	coverage, err := db.impactCoverage(ctx, userID, allRepositories)
	if err != nil {
		return nil, coverage, err
	}
	rows, err := db.pool.Query(ctx, impactScope(allRepositories)+`
		SELECT v.osv_id, v.aliases, COALESCE(v.severity, ''), v.cvss_score, COALESCE(v.summary, ''),
		       COALESCE(v.advisory_url, ''),
		       l.repo_id, l.owner, l.name, l.scan_id, l.commit_sha,
		       c.name, c.version, c.purl, c.direct, COALESCE(v.fixed_version, '')
		FROM latest l
		JOIN components c ON c.scan_id = l.scan_id
		JOIN vulnerabilities v ON v.component_id = c.id
		WHERE l.enriched_at IS NOT NULL
		ORDER BY v.osv_id, lower(l.owner), lower(l.name), c.name, c.version`, userID)
	if err != nil {
		return nil, coverage, fmt.Errorf("vulnerability impact: %w", err)
	}
	defer rows.Close()

	byID := map[string]*models.ImpactVulnerability{}
	repos := map[string]map[int64]bool{}
	var order []string
	for rows.Next() {
		var v models.ImpactVulnerability
		var o models.ImpactOccurrence
		if err := rows.Scan(&v.OSVID, &v.Aliases, &v.Severity, &v.CVSSScore, &v.Summary, &v.AdvisoryURL,
			&o.RepositoryID, &o.Owner, &o.Name, &o.ScanID, &o.CommitSHA,
			&o.Package, &o.Version, &o.PURL, &o.Direct, &o.FixedVersion); err != nil {
			return nil, coverage, fmt.Errorf("scan vulnerability impact: %w", err)
		}
		o.Analyzed = true
		existing := byID[v.OSVID]
		if existing == nil {
			v.Occurrences = []models.ImpactOccurrence{}
			byID[v.OSVID] = &v
			repos[v.OSVID] = map[int64]bool{}
			order = append(order, v.OSVID)
			existing = &v
		}
		existing.Occurrences = append(existing.Occurrences, o)
		repos[v.OSVID][o.RepositoryID] = true
	}
	if err := rows.Err(); err != nil {
		return nil, coverage, err
	}

	out := make([]models.ImpactVulnerability, 0, len(order))
	for _, id := range order {
		v := byID[id]
		v.RepositoryCount = len(repos[id])
		if v.Aliases == nil {
			v.Aliases = []string{}
		}
		out = append(out, *v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		wi, wj := risk.Weights[out[i].Severity], risk.Weights[out[j].Severity]
		if wi != wj {
			return wi > wj
		}
		if out[i].RepositoryCount != out[j].RepositoryCount {
			return out[i].RepositoryCount > out[j].RepositoryCount
		}
		return out[i].OSVID < out[j].OSVID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, coverage, nil
}

// ComponentImpact finds a dependency by name or package URL substring across
// the latest scans of a user's tracked repositories, grouped by package
// (all versions together), with each repository's version and how many
// advisories affect it there.
func (db *DB) ComponentImpact(ctx context.Context, userID int64, allRepositories bool, search string, limit int) ([]models.ImpactComponent, models.ImpactCoverage, error) {
	coverage, err := db.impactCoverage(ctx, userID, allRepositories)
	if err != nil {
		return nil, coverage, err
	}
	pattern := "%" + escapeLike(strings.ToLower(strings.TrimSpace(search))) + "%"
	rows, err := db.pool.Query(ctx, impactScope(allRepositories)+`
		SELECT l.repo_id, l.owner, l.name, l.scan_id, l.commit_sha, l.enriched_at IS NOT NULL,
		       c.name, c.version, c.purl, c.ecosystem, c.direct,
		       (SELECT COUNT(*) FROM vulnerabilities v WHERE v.component_id = c.id)
		FROM latest l
		JOIN components c ON c.scan_id = l.scan_id
		WHERE lower(c.name) LIKE $2 ESCAPE '\' OR lower(c.purl) LIKE $2 ESCAPE '\'
		ORDER BY c.purl, lower(l.owner), lower(l.name)
		LIMIT 2000`, userID, pattern)
	if err != nil {
		return nil, coverage, fmt.Errorf("component impact: %w", err)
	}
	defer rows.Close()

	byIdentity := map[string]*models.ImpactComponent{}
	repos := map[string]map[int64]bool{}
	versions := map[string]map[string]bool{}
	var order []string
	for rows.Next() {
		var o models.ImpactOccurrence
		var ecosystem string
		if err := rows.Scan(&o.RepositoryID, &o.Owner, &o.Name, &o.ScanID, &o.CommitSHA, &o.Analyzed,
			&o.Package, &o.Version, &o.PURL, &ecosystem, &o.Direct, &o.Vulnerabilities); err != nil {
			return nil, coverage, fmt.Errorf("scan component impact: %w", err)
		}
		identity, _, _, _ := sbom.ParseIdentity(o.PURL)
		group := byIdentity[identity]
		if group == nil {
			group = &models.ImpactComponent{Identity: identity, Name: o.Package, Ecosystem: ecosystem,
				Occurrences: []models.ImpactOccurrence{}}
			byIdentity[identity] = group
			repos[identity] = map[int64]bool{}
			versions[identity] = map[string]bool{}
			order = append(order, identity)
		}
		group.Occurrences = append(group.Occurrences, o)
		repos[identity][o.RepositoryID] = true
		if !versions[identity][o.Version] {
			versions[identity][o.Version] = true
			group.Versions = append(group.Versions, o.Version)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, coverage, err
	}

	out := make([]models.ImpactComponent, 0, len(order))
	for _, identity := range order {
		group := byIdentity[identity]
		group.RepositoryCount = len(repos[identity])
		out = append(out, *group)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RepositoryCount != out[j].RepositoryCount {
			return out[i].RepositoryCount > out[j].RepositoryCount
		}
		return out[i].Identity < out[j].Identity
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, coverage, nil
}
