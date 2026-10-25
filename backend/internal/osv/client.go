// Package osv looks components up in OSV.dev, the open vulnerability
// database run by Google that aggregates GitHub Security Advisories, PyPA,
// RustSec, the Go vulnerability database and others under one schema
// (https://ossf.github.io/osv-schema/).
//
// Matching a package version to the advisories that affect it is OSV's job,
// done with each ecosystem's own version rules; this package never second-
// guesses that answer. It only asks the question correctly (one package URL
// with an exact version per component), reads the advisories back, and
// derives what the dashboard shows: a severity, the fixed versions, and the
// one fix to recommend for the installed version.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/package-url/packageurl-go"

	"sbomdelta/internal/sbom"
)

// DefaultBaseURL is OSV's public API. It needs no credentials.
const DefaultBaseURL = "https://api.osv.dev"

const (
	// OSV accepts at most 1000 queries per batch.
	maxBatch = 1000
	// Advisory details are fetched one by one; this many at a time keeps a
	// large dependency tree quick without hammering a free public service.
	detailConcurrency = 8
	// A batch can page; this bounds a pathological answer.
	maxPages = 20
)

// Client talks to the OSV API.
type Client struct {
	baseURL string
	http    *http.Client
}

func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Finding is one advisory affecting one component.
type Finding struct {
	// PURL is the component's package URL exactly as the scan stored it.
	PURL     string
	Identity string
	OSVID    string
	Aliases  []string
	Summary  string
	// Severity is CRITICAL, HIGH, MEDIUM, LOW, or empty when the advisory
	// carries no usable rating. SeveritySource says where it came from.
	Severity       string
	SeveritySource string
	CVSSScore      *float64
	CVSSVector     string
	// FixedVersion is the lowest fixed version above the installed one, when
	// one can be determined; FixedVersions is everything OSV lists.
	FixedVersion  string
	FixedVersions []string
	AdvisoryURL   string
	Published     *time.Time
	Modified      *time.Time
}

// Report is the answer for one scan's components.
type Report struct {
	Findings []Finding
	// Checked is how many components OSV was asked about; Skipped is how
	// many could not be asked about (see QueryPURL).
	Checked int
	Skipped int
}

// Error is a failed exchange with OSV. Message names the endpoint and status,
// never a response body.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }

// Check asks OSV about every component and returns the advisories that
// affect them. It fails as a whole rather than returning a partial answer: a
// half-checked scan must not read as a clean one.
func (c *Client) Check(ctx context.Context, components []sbom.Component) (Report, error) {
	type target struct {
		component sbom.Component
		query     string
	}
	var targets []target
	report := Report{}
	for _, component := range components {
		query, ok := QueryPURL(component.PURL)
		if !ok {
			report.Skipped++
			continue
		}
		targets = append(targets, target{component: component, query: query})
	}

	queries := make([]string, len(targets))
	for i, t := range targets {
		queries[i] = t.query
	}
	ids, rejected, err := c.queryAll(ctx, queries)
	if err != nil {
		return Report{}, err
	}
	report.Checked = len(targets) - len(rejected)
	report.Skipped += len(rejected)

	unique := map[string]struct{}{}
	for _, list := range ids {
		for _, id := range list {
			unique[id] = struct{}{}
		}
	}
	vulns, err := c.fetchAll(ctx, unique)
	if err != nil {
		return Report{}, err
	}

	for i, t := range targets {
		var findings []Finding
		for _, id := range ids[i] {
			vuln, ok := vulns[id]
			if !ok || vuln.Withdrawn != nil {
				continue
			}
			findings = append(findings, vuln.findingFor(t.component))
		}
		report.Findings = append(report.Findings, MergeAliases(findings)...)
	}
	sort.Slice(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.PURL != b.PURL {
			return a.PURL < b.PURL
		}
		return a.OSVID < b.OSVID
	})
	return report, nil
}

// supportedTypes are the package URL types OSV indexes by package URL with
// language-ecosystem version semantics. Operating-system packages (deb, apk,
// rpm) need a distribution release to match correctly, which a source-tree
// SBOM does not carry, so they are counted as skipped rather than matched
// against the wrong release.
var supportedTypes = map[string]bool{
	"npm": true, "pypi": true, "maven": true, "golang": true, "cargo": true,
	"gem": true, "nuget": true, "composer": true, "hex": true, "pub": true,
	"swift": true, "hackage": true, "cran": true,
}

// QueryPURL is the package URL OSV is asked about for a component: type,
// namespace, name and version only. Qualifiers and subpaths are dropped
// (OSV does not match on them, and some make it reject the query). It
// reports false when the component cannot be checked: no version, an
// unparseable package URL, or a type OSV does not cover.
func QueryPURL(purl string) (string, bool) {
	instance, err := packageurl.FromString(purl)
	if err != nil || instance.Version == "" || !supportedTypes[instance.Type] {
		return "", false
	}
	bare := packageurl.PackageURL{
		Type:      instance.Type,
		Namespace: instance.Namespace,
		Name:      instance.Name,
		Version:   instance.Version,
	}
	return bare.ToString(), true
}

type batchRequest struct {
	Queries []batchQuery `json:"queries"`
}

type batchQuery struct {
	Package   batchPackage `json:"package"`
	PageToken string       `json:"page_token,omitempty"`
}

type batchPackage struct {
	PURL string `json:"purl"`
}

type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// queryAll returns the advisory IDs for each query, in order, following
// pagination. Queries OSV rejects one by one (a 400 for a single query) are
// returned as rejected instead of failing the whole scan.
func (c *Client) queryAll(ctx context.Context, queries []string) ([][]string, map[int]bool, error) {
	ids := make([][]string, len(queries))
	rejected := map[int]bool{}
	for start := 0; start < len(queries); start += maxBatch {
		end := min(start+maxBatch, len(queries))
		indexes := make([]int, 0, end-start)
		for i := start; i < end; i++ {
			indexes = append(indexes, i)
		}
		if err := c.queryIndexes(ctx, queries, indexes, ids, rejected); err != nil {
			return nil, nil, err
		}
	}
	return ids, rejected, nil
}

// queryIndexes runs one batch. A 400 means one of the queries is malformed;
// the batch is split in half until the culprit is isolated, so one odd
// package URL costs a few extra requests rather than the whole answer.
func (c *Client) queryIndexes(ctx context.Context, queries []string, indexes []int, ids [][]string, rejected map[int]bool) error {
	if len(indexes) == 0 {
		return nil
	}
	tokens := make(map[int]string)
	pending := indexes
	for page := 0; len(pending) > 0; page++ {
		if page == maxPages {
			return &Error{Message: fmt.Sprintf("OSV querybatch paged more than %d times", maxPages)}
		}
		request := batchRequest{Queries: make([]batchQuery, len(pending))}
		for i, index := range pending {
			request.Queries[i] = batchQuery{Package: batchPackage{PURL: queries[index]}, PageToken: tokens[index]}
		}
		var response batchResponse
		err := c.post(ctx, "/v1/querybatch", request, &response)
		var osvErr *Error
		if errors.As(err, &osvErr) && osvErr.Status == http.StatusBadRequest && page == 0 {
			if len(pending) == 1 {
				rejected[pending[0]] = true
				return nil
			}
			half := len(pending) / 2
			if err := c.queryIndexes(ctx, queries, pending[:half], ids, rejected); err != nil {
				return err
			}
			return c.queryIndexes(ctx, queries, pending[half:], ids, rejected)
		}
		if err != nil {
			return err
		}
		if len(response.Results) != len(pending) {
			return &Error{Message: fmt.Sprintf("OSV querybatch answered %d results for %d queries", len(response.Results), len(pending))}
		}
		var next []int
		for i, result := range response.Results {
			index := pending[i]
			for _, vuln := range result.Vulns {
				if vuln.ID != "" {
					ids[index] = append(ids[index], vuln.ID)
				}
			}
			if result.NextPageToken != "" {
				tokens[index] = result.NextPageToken
				next = append(next, index)
			}
		}
		pending = next
	}
	return nil
}

// fetchAll loads the full record of every advisory, a few at a time.
func (c *Client) fetchAll(ctx context.Context, ids map[string]struct{}) (map[string]*Vulnerability, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	out := make(map[string]*Vulnerability, len(ids))
	var mu sync.Mutex
	var firstErr error
	work := make(chan string)
	var wg sync.WaitGroup
	for range detailConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				vuln, err := c.get(ctx, id)
				mu.Lock()
				switch {
				case err != nil && firstErr == nil:
					firstErr = err
					cancel()
				case err == nil && vuln != nil:
					out[id] = vuln
				}
				mu.Unlock()
			}
		}()
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
feed:
	for _, id := range sorted {
		select {
		case work <- id:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil && len(out) < len(ids) {
		return nil, &Error{Message: "OSV lookup cancelled: " + err.Error()}
	}
	return out, nil
}

// get loads one advisory. An advisory OSV no longer has (404) is skipped
// rather than failing the scan: it was listed a moment ago and has since
// been withdrawn or merged into another record.
func (c *Client) get(ctx context.Context, id string) (*Vulnerability, error) {
	var vuln Vulnerability
	err := c.do(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil, &vuln)
	var osvErr *Error
	if errors.As(err, &osvErr) && osvErr.Status == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if vuln.ID == "" {
		vuln.ID = id
	}
	return &vuln, nil
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode OSV request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("build OSV request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "SBOMDelta")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := c.http.Do(request)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return &Error{Message: fmt.Sprintf("OSV %s %s: %v", method, endpointName(path), err)}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return &Error{Status: response.StatusCode,
			Message: fmt.Sprintf("OSV %s %s returned HTTP %d", method, endpointName(path), response.StatusCode)}
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<20)).Decode(out); err != nil {
		return &Error{Message: fmt.Sprintf("OSV %s %s returned a response that is not valid JSON", method, endpointName(path))}
	}
	return nil
}

// endpointName keeps advisory IDs out of error messages that are grouped by
// endpoint, without hiding which endpoint failed.
func endpointName(path string) string {
	if strings.HasPrefix(path, "/v1/vulns/") {
		return "/v1/vulns/{id}"
	}
	return path
}
