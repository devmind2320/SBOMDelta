package github

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	gh "github.com/google/go-github/v66/github"

	"sbomdelta/internal/models"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/storage"
)

// WebhookHandler receives GitHub events, records the minimum needed to act on
// them, and enqueues work.
//
// It deliberately does no scanning: a webhook handler that clones a repository
// holds GitHub's delivery open for minutes and will simply time out. Everything
// expensive happens on the worker.
type WebhookHandler struct {
	secret string
	db     *storage.DB
	queue  *queue.Queue
	logger *slog.Logger
}

func NewWebhookHandler(secret string, db *storage.DB, q *queue.Queue, logger *slog.Logger) *WebhookHandler {
	return &WebhookHandler{secret: secret, db: db, queue: q, logger: logger}
}

func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// ValidatePayload verifies the HMAC-SHA256 signature in X-Hub-Signature-256
	// using a constant-time comparison. An unsigned or wrongly signed request
	// is rejected before its body is ever parsed.
	body, err := gh.ValidatePayload(r, []byte(h.secret))
	if err != nil {
		h.logger.Warn("rejected webhook with invalid signature", "error", err, "remote", r.RemoteAddr)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	eventType := gh.WebHookType(r)
	deliveryID := gh.DeliveryID(r)
	logger := h.logger.With("event", eventType, "delivery", deliveryID)

	event, err := gh.ParseWebHook(eventType, body)
	if err != nil {
		logger.Warn("could not parse webhook payload", "error", err)
		// The signature was valid, so this is an event shape we do not know.
		// Returning 202 stops GitHub from retrying something we will never
		// understand.
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// GitHub guarantees at-least-once delivery and retries on any non-2xx.
	// Recording the delivery ID first makes a replay a no-op.
	if deliveryID != "" {
		fresh, err := h.db.RecordWebhookDelivery(r.Context(), deliveryID, eventType, actionOf(event))
		if err != nil {
			logger.Error("could not record webhook delivery", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !fresh {
			logger.Info("ignoring replayed webhook delivery")
			w.WriteHeader(http.StatusAccepted)
			return
		}
	}

	if err := h.dispatch(r.Context(), logger, event); err != nil {
		logger.Error("could not handle webhook", "error", err)
		// A 500 asks GitHub to redeliver; the delivery row above was written
		// in a separate transaction, so allow the retry to proceed by
		// forgetting this delivery.
		if deliveryID != "" {
			h.forgetDelivery(r.Context(), deliveryID)
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *WebhookHandler) forgetDelivery(ctx context.Context, deliveryID string) {
	if _, err := h.db.Pool().Exec(context.WithoutCancel(ctx),
		`DELETE FROM webhook_deliveries WHERE delivery_id = $1`, deliveryID); err != nil {
		h.logger.Error("could not roll back webhook delivery record", "error", err, "delivery", deliveryID)
	}
}

func (h *WebhookHandler) dispatch(ctx context.Context, logger *slog.Logger, event any) error {
	switch typed := event.(type) {
	case *gh.InstallationEvent:
		return h.handleInstallation(ctx, logger, typed)
	case *gh.InstallationRepositoriesEvent:
		return h.handleInstallationRepositories(ctx, logger, typed)
	case *gh.PushEvent:
		return h.handlePush(ctx, logger, typed)
	case *gh.PullRequestEvent:
		return h.handlePullRequest(ctx, logger, typed)
	case *gh.PingEvent:
		logger.Info("received ping from github")
		return nil
	default:
		logger.Debug("ignoring unhandled event type")
		return nil
	}
}

func (h *WebhookHandler) handleInstallation(ctx context.Context, logger *slog.Logger, event *gh.InstallationEvent) error {
	installation := event.GetInstallation()
	if installation == nil {
		return errors.New("installation event carried no installation")
	}

	switch event.GetAction() {
	case "deleted":
		return h.db.MarkInstallationDeleted(ctx, installation.GetID())
	case "suspend", "unsuspend", "created", "new_permissions_accepted":
		record, err := h.db.UpsertInstallation(ctx, models.Installation{
			GitHubInstallationID: installation.GetID(),
			AccountLogin:         installation.GetAccount().GetLogin(),
			AccountType:          installation.GetAccount().GetType(),
			SuspendedAt:          timePtr(installation.SuspendedAt),
		})
		if err != nil {
			return err
		}
		for _, repo := range event.Repositories {
			if _, err := h.upsertRepositoryFromEvent(ctx, record.ID, repo, installation.GetAccount().GetLogin()); err != nil {
				return err
			}
		}
		logger.Info("recorded installation", "account", record.AccountLogin, "repos", len(event.Repositories))
		return nil
	default:
		return nil
	}
}

func (h *WebhookHandler) handleInstallationRepositories(ctx context.Context, logger *slog.Logger, event *gh.InstallationRepositoriesEvent) error {
	installation := event.GetInstallation()
	if installation == nil {
		return errors.New("installation_repositories event carried no installation")
	}
	record, err := h.db.UpsertInstallation(ctx, models.Installation{
		GitHubInstallationID: installation.GetID(),
		AccountLogin:         installation.GetAccount().GetLogin(),
		AccountType:          installation.GetAccount().GetType(),
	})
	if err != nil {
		return err
	}

	for _, repo := range event.RepositoriesAdded {
		if _, err := h.upsertRepositoryFromEvent(ctx, record.ID, repo, installation.GetAccount().GetLogin()); err != nil {
			return err
		}
	}
	logger.Info("updated installation repositories",
		"added", len(event.RepositoriesAdded), "removed", len(event.RepositoriesRemoved))
	return nil
}

// upsertRepositoryFromEvent handles the trimmed-down repository shape that
// installation events carry, where FullName is present but Owner often is not.
func (h *WebhookHandler) upsertRepositoryFromEvent(ctx context.Context, installationID int64, repo *gh.Repository, fallbackOwner string) (models.Repository, error) {
	if repo == nil {
		return models.Repository{}, errors.New("event carried a nil repository")
	}
	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()
	if owner == "" {
		if before, after, found := strings.Cut(repo.GetFullName(), "/"); found {
			owner, name = before, after
		} else {
			owner = fallbackOwner
		}
	}
	defaultBranch := repo.GetDefaultBranch()
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	return h.db.UpsertRepository(ctx, models.Repository{
		InstallationID: &installationID,
		GitHubRepoID:   githubID(repo.GetID()),
		Owner:          owner,
		Name:           name,
		DefaultBranch:  defaultBranch,
		Private:        repo.GetPrivate(),
	})
}

// handlePush scans commits landing on the default branch.
//
// Only the default branch is tracked because that is what "the security state
// of this project" means; feature branches are covered by their pull requests,
// where the comparison against the merge base is the useful one.
func (h *WebhookHandler) handlePush(ctx context.Context, logger *slog.Logger, event *gh.PushEvent) error {
	repo := event.GetRepo()
	if repo == nil {
		return errors.New("push event carried no repository")
	}
	if event.GetDeleted() {
		return nil
	}

	defaultBranch := repo.GetDefaultBranch()
	if defaultBranch == "" {
		defaultBranch = "main"
	}
	if event.GetRef() != "refs/heads/"+defaultBranch {
		logger.Debug("ignoring push outside the default branch", "ref", event.GetRef())
		return nil
	}

	headSHA := event.GetAfter()
	if headSHA == "" || isZeroSHA(headSHA) {
		return nil
	}

	installationRecordID, err := h.installationRecordID(ctx, event.GetInstallation())
	if err != nil {
		return err
	}

	record, err := h.db.UpsertRepository(ctx, models.Repository{
		InstallationID: installationRecordID,
		GitHubRepoID:   githubID(repo.GetID()),
		Owner:          repo.GetOwner().GetName(),
		Name:           repo.GetName(),
		DefaultBranch:  defaultBranch,
		Private:        repo.GetPrivate(),
	})
	if err != nil {
		return err
	}

	if err := h.db.UpsertCommit(ctx, models.Commit{
		RepositoryID: record.ID,
		SHA:          headSHA,
		Ref:          event.GetRef(),
		AuthorLogin:  event.GetHeadCommit().GetAuthor().GetLogin(),
		AuthorEmail:  event.GetHeadCommit().GetAuthor().GetEmail(),
		Message:      event.GetHeadCommit().GetMessage(),
		CommittedAt:  timePtr(event.GetHeadCommit().Timestamp),
	}); err != nil {
		return err
	}

	// The push's "before" SHA is the previous tip of the branch, which is
	// exactly the state this commit should be measured against.
	baseSHA := event.GetBefore()
	if isZeroSHA(baseSHA) {
		baseSHA = ""
	}

	scan, err := h.db.CreateScan(ctx, models.Scan{
		RepositoryID:  record.ID,
		CommitSHA:     headSHA,
		BaseCommitSHA: baseSHA,
		Trigger:       models.TriggerPush,
	})
	if err != nil {
		return err
	}

	return h.enqueueScan(ctx, logger, scan, record.FullName())
}

func (h *WebhookHandler) handlePullRequest(ctx context.Context, logger *slog.Logger, event *gh.PullRequestEvent) error {
	switch event.GetAction() {
	case "opened", "reopened", "synchronize", "ready_for_review":
	default:
		return nil
	}

	repo := event.GetRepo()
	pr := event.GetPullRequest()
	if repo == nil || pr == nil {
		return errors.New("pull_request event was missing its repository or pull request")
	}
	if pr.GetDraft() && event.GetAction() != "ready_for_review" {
		logger.Debug("ignoring draft pull request", "number", pr.GetNumber())
		return nil
	}

	installationRecordID, err := h.installationRecordID(ctx, event.GetInstallation())
	if err != nil {
		return err
	}

	record, err := h.db.UpsertRepository(ctx, models.Repository{
		InstallationID: installationRecordID,
		GitHubRepoID:   githubID(repo.GetID()),
		Owner:          repo.GetOwner().GetLogin(),
		Name:           repo.GetName(),
		DefaultBranch:  repo.GetDefaultBranch(),
		Private:        repo.GetPrivate(),
	})
	if err != nil {
		return err
	}

	stored, err := h.db.UpsertPullRequest(ctx, models.PullRequest{
		RepositoryID: record.ID,
		Number:       pr.GetNumber(),
		Title:        pr.GetTitle(),
		AuthorLogin:  pr.GetUser().GetLogin(),
		State:        pr.GetState(),
		BaseRef:      pr.GetBase().GetRef(),
		BaseSHA:      pr.GetBase().GetSHA(),
		HeadSHA:      pr.GetHead().GetSHA(),
	})
	if err != nil {
		return err
	}

	if err := h.db.UpsertCommit(ctx, models.Commit{
		RepositoryID: record.ID,
		SHA:          pr.GetHead().GetSHA(),
		Ref:          "refs/pull/" + fmt.Sprint(pr.GetNumber()) + "/head",
		AuthorLogin:  pr.GetUser().GetLogin(),
	}); err != nil {
		return err
	}

	scan, err := h.db.CreateScan(ctx, models.Scan{
		RepositoryID:  record.ID,
		PullRequestID: &stored.ID,
		CommitSHA:     pr.GetHead().GetSHA(),
		BaseCommitSHA: pr.GetBase().GetSHA(),
		Trigger:       models.TriggerPullRequest,
	})
	if err != nil {
		return err
	}

	logger = logger.With("pr", pr.GetNumber())
	return h.enqueueScan(ctx, logger, scan, record.FullName())
}

func (h *WebhookHandler) enqueueScan(ctx context.Context, logger *slog.Logger, scan models.Scan, fullName string) error {
	// A scan already past pending was queued by an earlier delivery of the
	// same commit; leave it alone rather than racing the worker.
	if scan.Status != models.ScanPending {
		logger.Info("scan already in flight", "scan", scan.ID, "status", scan.Status)
		return nil
	}

	dedupeKey := fmt.Sprintf("scan:%d", scan.ID)
	jobID, err := h.queue.Enqueue(ctx, queue.KindScan, queue.ScanPayload{ScanID: scan.ID}, dedupeKey)
	if err != nil {
		return err
	}
	if jobID == 0 {
		logger.Info("scan job already queued", "scan", scan.ID)
		return nil
	}
	logger.Info("queued scan", "scan", scan.ID, "job", jobID, "repo", fullName, "commit", scan.CommitSHA)
	return nil
}

// installationRecordID maps GitHub's installation ID to our row ID, tolerating
// events that arrive before the installation event itself.
func (h *WebhookHandler) installationRecordID(ctx context.Context, installation *gh.Installation) (*int64, error) {
	if installation == nil || installation.GetID() == 0 {
		return nil, nil
	}
	record, err := h.db.UpsertInstallation(ctx, models.Installation{
		GitHubInstallationID: installation.GetID(),
		AccountLogin:         installation.GetAccount().GetLogin(),
		AccountType:          installation.GetAccount().GetType(),
	})
	if err != nil {
		return nil, err
	}
	return &record.ID, nil
}

// isZeroSHA reports whether a SHA is git's all-zeroes sentinel, which marks a
// created or deleted ref rather than a real commit.
func isZeroSHA(sha string) bool {
	if sha == "" {
		return false
	}
	return strings.Trim(sha, "0") == ""
}

func actionOf(event any) string {
	type actioner interface{ GetAction() string }
	if typed, ok := event.(actioner); ok {
		return typed.GetAction()
	}
	return ""
}

// githubID boxes a GitHub repository ID. Repositories that arrive over a
// webhook always have one; manually registered repositories do not.
func githubID(id int64) *int64 {
	return &id
}
