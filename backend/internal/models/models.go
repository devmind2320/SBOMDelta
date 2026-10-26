// Package models holds the persisted domain types shared by the storage
// layer, the worker and the API.
package models

import "time"

// User is someone who has signed in to the dashboard.
type User struct {
	ID           int64  `json:"id"`
	GitHubUserID int64  `json:"githubUserId"`
	Login        string `json:"login"`
	AvatarURL    string `json:"avatarUrl,omitempty"`
}

type Installation struct {
	ID                   int64  `json:"id"`
	GitHubInstallationID int64  `json:"githubInstallationId"`
	AccountLogin         string `json:"accountLogin"`
	// AccountID is GitHub's numeric ID for the account, which survives a
	// rename. Zero until an installation event or reconciliation reports it.
	AccountID   int64      `json:"accountId,omitempty"`
	AccountType string     `json:"accountType"`
	SuspendedAt *time.Time `json:"suspendedAt,omitempty"`
	DeletedAt   *time.Time `json:"deletedAt,omitempty"`
}

type Repository struct {
	ID             int64  `json:"id"`
	InstallationID *int64 `json:"installationId,omitempty"`
	// GitHubRepoID is nil for repositories registered manually rather than
	// through the GitHub App.
	GitHubRepoID *int64 `json:"githubRepoId,omitempty"`
	// CloneURL is set for manually registered repositories, which are cloned
	// anonymously because there is no installation token to use.
	CloneURL      string    `json:"cloneUrl,omitempty"`
	Owner         string    `json:"owner"`
	Name          string    `json:"name"`
	DefaultBranch string    `json:"defaultBranch"`
	Private       bool      `json:"private"`
	CreatedAt     time.Time `json:"createdAt"`
	// Access says whether SBOMDelta can currently reach the repository. It is
	// derived on read; a repository that lost access keeps its row and its
	// scan history.
	Access RepositoryAccess `json:"access"`
	// AccessRevokedAt is when the repository was removed from its
	// installation's selection, if it has been.
	AccessRevokedAt *time.Time `json:"accessRevokedAt,omitempty"`
}

// FullName is the owner/name form GitHub uses throughout its API.
func (r Repository) FullName() string { return r.Owner + "/" + r.Name }

// Accessible reports whether new scans of this repository can run.
func (r Repository) Accessible() bool { return r.Access == AccessActive }

type RepositoryAccess string

const (
	AccessActive RepositoryAccess = "active"
	// AccessRevoked: the installation still exists but no longer includes
	// this repository.
	AccessRevoked RepositoryAccess = "revoked"
	// AccessUninstalled: the installation that granted access was deleted.
	AccessUninstalled RepositoryAccess = "uninstalled"
	// AccessSuspended: the installation is suspended, so its token is
	// unusable until it is unsuspended.
	AccessSuspended RepositoryAccess = "suspended"
)

type Commit struct {
	ID           int64      `json:"id"`
	RepositoryID int64      `json:"repositoryId"`
	SHA          string     `json:"sha"`
	Ref          string     `json:"ref,omitempty"`
	AuthorLogin  string     `json:"authorLogin,omitempty"`
	AuthorEmail  string     `json:"authorEmail,omitempty"`
	Message      string     `json:"message,omitempty"`
	CommittedAt  *time.Time `json:"committedAt,omitempty"`
}

type PullRequest struct {
	ID           int64  `json:"id"`
	RepositoryID int64  `json:"repositoryId"`
	Number       int    `json:"number"`
	Title        string `json:"title,omitempty"`
	AuthorLogin  string `json:"authorLogin,omitempty"`
	State        string `json:"state"`
	BaseRef      string `json:"baseRef,omitempty"`
	BaseSHA      string `json:"baseSha"`
	HeadSHA      string `json:"headSha"`
}

type ScanStatus string

const (
	ScanPending   ScanStatus = "pending"
	ScanRunning   ScanStatus = "running"
	ScanCompleted ScanStatus = "completed"
	ScanFailed    ScanStatus = "failed"
)

type ScanTrigger string

const (
	TriggerPush        ScanTrigger = "push"
	TriggerPullRequest ScanTrigger = "pull_request"
	TriggerManual      ScanTrigger = "manual"
	TriggerBackfill    ScanTrigger = "backfill"
	// TriggerInitial is the first scan of a repository the GitHub App can
	// reach, taken at its default branch head without waiting for a push.
	TriggerInitial ScanTrigger = "initial"
)

type Scan struct {
	ID               int64       `json:"id"`
	RepositoryID     int64       `json:"repositoryId"`
	PullRequestID    *int64      `json:"pullRequestId,omitempty"`
	BaseScanID       *int64      `json:"baseScanId,omitempty"`
	CommitSHA        string      `json:"commitSha"`
	BaseCommitSHA    string      `json:"baseCommitSha,omitempty"`
	Trigger          ScanTrigger `json:"trigger"`
	Status           ScanStatus  `json:"status"`
	SBOMLocation     string      `json:"sbomLocation,omitempty"`
	SBOMSHA256       string      `json:"sbomSha256,omitempty"`
	ComponentCount   int         `json:"componentCount"`
	RiskScore        *float64    `json:"riskScore,omitempty"`
	RiskDelta        *float64    `json:"riskDelta,omitempty"`
	GitHubCheckRunID *int64      `json:"githubCheckRunId,omitempty"`
	Error            string      `json:"error,omitempty"`
	EnrichedAt       *time.Time  `json:"enrichedAt,omitempty"`
	// EnrichmentError is why the last vulnerability lookup failed, if it did.
	EnrichmentError string `json:"enrichmentError,omitempty"`
	// RiskLevel is none, low, medium, high or critical once enriched.
	RiskLevel             string     `json:"riskLevel,omitempty"`
	VulnComponentsChecked *int       `json:"vulnComponentsChecked,omitempty"`
	VulnComponentsSkipped *int       `json:"vulnComponentsSkipped,omitempty"`
	StartedAt             *time.Time `json:"startedAt,omitempty"`
	FinishedAt            *time.Time `json:"finishedAt,omitempty"`
	CreatedAt             time.Time  `json:"createdAt"`
}

type Component struct {
	ID                int64    `json:"id"`
	ScanID            int64    `json:"scanId"`
	PURL              string   `json:"purl"`
	Name              string   `json:"name"`
	Version           string   `json:"version"`
	Ecosystem         string   `json:"ecosystem"`
	Type              string   `json:"type,omitempty"`
	LicenseExpression string   `json:"licenseExpression,omitempty"`
	Licenses          []string `json:"licenses"`
	Direct            bool     `json:"direct"`
}

type DriftEvent struct {
	ID         int64     `json:"id"`
	ScanID     int64     `json:"scanId"`
	BaseScanID *int64    `json:"baseScanId,omitempty"`
	ChangeType string    `json:"changeType"`
	Identity   string    `json:"identity"`
	PURL       string    `json:"purl"`
	Name       string    `json:"name"`
	Ecosystem  string    `json:"ecosystem"`
	OldVersion string    `json:"oldVersion,omitempty"`
	NewVersion string    `json:"newVersion,omitempty"`
	Direction  string    `json:"direction,omitempty"`
	RiskDelta  float64   `json:"riskDelta"`
	CreatedAt  time.Time `json:"createdAt"`
}

// Vulnerability is one advisory affecting one component, as reported by
// OSV.dev when the scan was enriched.
type Vulnerability struct {
	ID           int64      `json:"id"`
	ComponentID  int64      `json:"componentId"`
	OSVID        string     `json:"osvId"`
	Aliases      []string   `json:"aliases"`
	Severity     string     `json:"severity,omitempty"`
	CVSSScore    *float64   `json:"cvssScore,omitempty"`
	CVSSVector   string     `json:"cvssVector,omitempty"`
	Summary      string     `json:"summary,omitempty"`
	FixedVersion string     `json:"fixedVersion,omitempty"`
	PublishedAt  *time.Time `json:"publishedAt,omitempty"`
	// FixedVersions is every fixed version OSV lists; FixedVersion is the
	// one recommended for the installed version.
	FixedVersions   []string   `json:"fixedVersions"`
	SeveritySource  string     `json:"severitySource,omitempty"`
	AdvisoryURL     string     `json:"advisoryUrl,omitempty"`
	ModifiedAt      *time.Time `json:"modifiedAt,omitempty"`
	PackageIdentity string     `json:"packageIdentity"`
	// Remediation is what to do about it, in words, derived from the fixes.
	Remediation string `json:"remediation"`

	// Denormalized from the component so a vulnerability table needs one query.
	PURL      string `json:"purl"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	Direct    bool   `json:"direct"`
}

// Remediation describes how to fix a vulnerable component.
func Remediation(name, version, fixedVersion string, fixedVersions []string) string {
	switch {
	case fixedVersion != "":
		return "Upgrade " + name + " from " + version + " to " + fixedVersion + " or later."
	case len(fixedVersions) > 0:
		return "Fixed releases exist only on other release lines (" + joinLimited(fixedVersions, 3) +
			"); move " + name + " to one of them, or check the advisory."
	default:
		return "No fixed version is published. Consider replacing or removing " + name +
			", or apply the mitigations in the advisory."
	}
}

func joinLimited(values []string, limit int) string {
	out := ""
	for i, value := range values {
		if i == limit {
			return out + ", …"
		}
		if i > 0 {
			out += ", "
		}
		out += value
	}
	return out
}

// Vulnerability analysis states of a completed scan.
const (
	VulnStatusAnalyzed = "analyzed"
	VulnStatusPending  = "pending"
	VulnStatusFailed   = "failed"
)

// VulnerabilitySummary is the vulnerability picture of one scan, for lists.
// Counts are meaningful only when Status is analyzed; pending and failed
// scans have none, which is not the same as having zero.
type VulnerabilitySummary struct {
	Status     string     `json:"status"`
	Error      string     `json:"error,omitempty"`
	AnalyzedAt *time.Time `json:"analyzedAt,omitempty"`
	Total      int        `json:"total"`
	Critical   int        `json:"critical"`
	High       int        `json:"high"`
	Medium     int        `json:"medium"`
	Low        int        `json:"low"`
	Unrated    int        `json:"unrated"`
	Fixable    int        `json:"fixable"`
	// Introduced and Resolved compare with the base scan; nil when there is
	// no analyzed base scan to compare with.
	Introduced        *int `json:"introduced,omitempty"`
	Resolved          *int `json:"resolved,omitempty"`
	ComponentsChecked *int `json:"componentsChecked,omitempty"`
	ComponentsSkipped *int `json:"componentsSkipped,omitempty"`
}

// RiskSummary is a scan's risk score; nil fields mean not scored.
type RiskSummary struct {
	Score *float64 `json:"score"`
	Level string   `json:"level,omitempty"`
	Delta *float64 `json:"delta,omitempty"`
}

// AccessibleRepository is a repository GitHub says a user can reach through
// one of the App's installations, as recorded at sign-in.
type AccessibleRepository struct {
	GitHubRepoID         int64  `json:"githubRepoId"`
	GitHubInstallationID int64  `json:"githubInstallationId"`
	Owner                string `json:"owner"`
	Name                 string `json:"name"`
	Private              bool   `json:"private"`
	DefaultBranch        string `json:"defaultBranch,omitempty"`
}

// ScanSummary is the part of a scan the dashboard shows in a list.
type ScanSummary struct {
	ID             int64       `json:"id"`
	Status         ScanStatus  `json:"status"`
	Trigger        ScanTrigger `json:"trigger"`
	CommitSHA      string      `json:"commitSha"`
	ComponentCount int         `json:"componentCount"`
	Error          string      `json:"error,omitempty"`
	CreatedAt      time.Time   `json:"createdAt"`
	FinishedAt     *time.Time  `json:"finishedAt,omitempty"`
	// Vulnerabilities and Risk are set on completed scans where a list asks
	// for them.
	Vulnerabilities *VulnerabilitySummary `json:"vulnerabilities,omitempty"`
	Risk            *RiskSummary          `json:"risk,omitempty"`
}

// ScanOverview is one row of the "Last scans" list: a scan with the
// repository it belongs to and everything a reader needs to judge it.
type ScanOverview struct {
	ScanSummary
	RepositoryID      int64  `json:"repositoryId"`
	Owner             string `json:"owner"`
	Name              string `json:"name"`
	DefaultBranch     string `json:"defaultBranch"`
	Ref               string `json:"ref,omitempty"`
	PullRequestID     *int64 `json:"pullRequestId,omitempty"`
	PullRequestNumber *int   `json:"pullRequestNumber,omitempty"`
	PullRequestTitle  string `json:"pullRequestTitle,omitempty"`
	BaseScanID        *int64 `json:"baseScanId,omitempty"`
	Baseline          bool   `json:"baseline"`
	Added             int    `json:"added"`
	Updated           int    `json:"updated"`
	Removed           int    `json:"removed"`
}

// UserRepository is one row of a user's "All Repos" list: what GitHub
// reported at sign-in, joined to what SBOMDelta has stored about it.
type UserRepository struct {
	AccessibleRepository
	// RepositoryID and Access are nil until the installation's repository
	// list has been stored, which happens shortly after it is installed.
	RepositoryID *int64            `json:"repositoryId,omitempty"`
	Access       *RepositoryAccess `json:"access,omitempty"`
	Tracked      bool              `json:"tracked"`
	LatestScan   *ScanSummary      `json:"latestScan,omitempty"`
	// LastCompletedScan is the newest branch scan that finished; a repository
	// has a report to open only once there is one.
	LastCompletedScan *ScanSummary `json:"lastCompletedScan,omitempty"`
}

// TrackedRepository is one row of a user's "Tracked Repos" list. LatestScan
// is the newest branch scan in any state; LastCompletedScan is the newest one
// that finished, whose results stay current when a later scan fails.
type TrackedRepository struct {
	Repository
	TrackedAt         time.Time    `json:"trackedAt"`
	LatestScan        *ScanSummary `json:"latestScan,omitempty"`
	LastCompletedScan *ScanSummary `json:"lastCompletedScan,omitempty"`
	// Dependency changes found by LastCompletedScan against its base. A scan
	// with no base is an initial inventory: Baseline is true and these are 0.
	Baseline bool `json:"baseline"`
	Added    int  `json:"added"`
	Updated  int  `json:"updated"`
	Removed  int  `json:"removed"`
}

// PullRequestSummary is a pull request plus the headline numbers from its most
// recent scan, which is what a PR list needs to render in one query.
type PullRequestSummary struct {
	PullRequest

	ScanID         *int64      `json:"scanId,omitempty"`
	ScanStatus     *ScanStatus `json:"scanStatus,omitempty"`
	RiskDelta      *float64    `json:"riskDelta,omitempty"`
	ComponentCount *int        `json:"componentCount,omitempty"`
	Added          int         `json:"added"`
	Updated        int         `json:"updated"`
	Removed        int         `json:"removed"`
	// Vulnerabilities compares the latest scan with the pull request's base.
	Vulnerabilities *VulnerabilitySummary `json:"vulnerabilities,omitempty"`
	RiskScore       *float64              `json:"riskScore,omitempty"`
	RiskLevel       string                `json:"riskLevel,omitempty"`
}

// ImpactCoverage says how much of a user's portfolio an impact answer
// covers: repositories with no completed scan, or whose latest scan has not
// been checked for vulnerabilities, cannot appear in it.
type ImpactCoverage struct {
	Repositories int `json:"repositories"`
	Scanned      int `json:"scanned"`
	Analyzed     int `json:"analyzed"`
}

// ImpactOccurrence is one repository where an advisory or component occurs,
// at its latest completed default-branch scan.
type ImpactOccurrence struct {
	RepositoryID    int64  `json:"repositoryId"`
	Owner           string `json:"owner"`
	Name            string `json:"name"`
	ScanID          int64  `json:"scanId"`
	CommitSHA       string `json:"commitSha"`
	Package         string `json:"package"`
	Version         string `json:"version"`
	PURL            string `json:"purl"`
	Direct          bool   `json:"direct"`
	FixedVersion    string `json:"fixedVersion,omitempty"`
	Vulnerabilities int    `json:"vulnerabilities"`
	Analyzed        bool   `json:"analyzed"`
}

// ImpactVulnerability is one advisory and every tracked repository it
// affects.
type ImpactVulnerability struct {
	OSVID           string             `json:"osvId"`
	Aliases         []string           `json:"aliases"`
	Severity        string             `json:"severity,omitempty"`
	CVSSScore       *float64           `json:"cvssScore,omitempty"`
	Summary         string             `json:"summary,omitempty"`
	AdvisoryURL     string             `json:"advisoryUrl,omitempty"`
	RepositoryCount int                `json:"repositoryCount"`
	Occurrences     []ImpactOccurrence `json:"occurrences"`
}

// ImpactComponent is one dependency (all versions) and every tracked
// repository that ships it.
type ImpactComponent struct {
	Identity        string             `json:"identity"`
	Name            string             `json:"name"`
	Ecosystem       string             `json:"ecosystem"`
	Versions        []string           `json:"versions"`
	RepositoryCount int                `json:"repositoryCount"`
	Occurrences     []ImpactOccurrence `json:"occurrences"`
}
