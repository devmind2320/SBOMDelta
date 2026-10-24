// Package models holds the persisted domain types shared by the storage
// layer, the worker and the API.
package models

import "time"

type Installation struct {
	ID                   int64      `json:"id"`
	GitHubInstallationID int64      `json:"githubInstallationId"`
	AccountLogin         string     `json:"accountLogin"`
	AccountType          string     `json:"accountType"`
	SuspendedAt          *time.Time `json:"suspendedAt,omitempty"`
	DeletedAt            *time.Time `json:"deletedAt,omitempty"`
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
	StartedAt        *time.Time  `json:"startedAt,omitempty"`
	FinishedAt       *time.Time  `json:"finishedAt,omitempty"`
	CreatedAt        time.Time   `json:"createdAt"`
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

// Vulnerability is one advisory affecting one component. Populated by the OSV
// enrichment step in Phase 4; the table exists and stays empty until then.
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

	// Denormalized from the component so a vulnerability table needs one query.
	PURL      string `json:"purl"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
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
}
