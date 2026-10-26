package github

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

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
//
// Only installations the gate approves may queue work (see installationGate).
// Every other installation is still recorded, so its uninstall and suspension
// are tracked and the logs show who installed it, but nothing it sends is
// scanned or reconciled.
type WebhookHandler struct {
	secret string
	gate   installationGate
	db     *storage.DB
	queue  *queue.Queue
	logger *slog.Logger
}

func NewWebhookHandler(secret string, allowedAccounts []int64, db *storage.DB, q *queue.Queue, logger *slog.Logger) *WebhookHandler {
	return &WebhookHandler{secret: secret, gate: installationGate{allowedAccounts: allowedAccounts, db: db}, db: db, queue: q, logger: logger}
}

// QueueReconciliationAfterSignIn queues a reconciliation of each installation
// a user's sign-in just listed and the gate now approves. Signing in is what
// connects an installation, so one installed moments ago gets its
// repositories stored and scanned now rather than at the next webhook or
// worker restart. An installation whose installation event has not arrived
// yet is skipped: that event reconciles it. Each installation has at most one
// such job waiting, however often its users sign in.
func (h *WebhookHandler) QueueReconciliationAfterSignIn(ctx context.Context, githubInstallationIDs []int64) error {
	for _, id := range githubInstallationIDs {
		installation, err := h.db.GetInstallationByGitHubID(ctx, id)
		if errors.Is(err, storage.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if installation.DeletedAt != nil || installation.SuspendedAt != nil {
			continue
		}
		reason, err := h.gate.refusal(ctx, installation)
		if err != nil {
			return err
		}
		if reason != "" {
			logRefused(h.logger, installation, "sign-in", reason)
			continue
		}
		key := fmt.Sprintf("signin-reconcile:%d", id)
		if _, err := h.queue.ReleaseDeadDedupeKey(ctx, key); err != nil {
			return err
		}
		if _, err := h.queue.Enqueue(ctx, queue.KindReconcileInstallation,
			queue.ReconcileInstallationPayload{GitHubInstallationID: id}, key); err != nil {
			return err
		}
	}
	return nil
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
		// Repositories are not touched: their access is reported as
		// uninstalled from the installation row, and their history stays.
		return h.db.MarkInstallationDeleted(ctx, installation.GetID())
	case "suspend", "unsuspend", "created", "new_permissions_accepted":
		record, err := h.db.UpsertInstallation(ctx, models.Installation{
			GitHubInstallationID: installation.GetID(),
			AccountLogin:         installation.GetAccount().GetLogin(),
			AccountID:            installation.GetAccount().GetID(),
			AccountType:          installation.GetAccount().GetType(),
			SuspendedAt:          timePtr(installation.SuspendedAt),
		})
		if err != nil {
			return err
		}
		reason, err := h.gate.refusal(ctx, record)
		if err != nil {
			return err
		}
		if reason != "" {
			logRefused(logger, record, "installation "+event.GetAction(), reason)
			return nil
		}
		for _, repo := range event.Repositories {
			if _, err := h.upsertRepositoryFromEvent(ctx, record.ID, repo, installation.GetAccount().GetLogin()); err != nil {
				return err
			}
		}
		logger.Info("recorded installation",
			"action", event.GetAction(), "account", record.AccountLogin, "repos", len(event.Repositories))

		// Only "created" carries a repository list, and even that one is not
		// a complete statement of access. Ask GitHub for the real list
		// whenever the installation becomes usable. A suspended installation
		// cannot mint a token, so there is nothing to ask until it returns.
		if event.GetAction() == "suspend" {
			return nil
		}
		return h.enqueueReconcile(ctx, logger, installation.GetID())
	default:
		return nil
	}
}

func (h *WebhookHandler) handleInstallationRepositories(ctx context.Context, logger *slog.Logger, event *gh.InstallationRepositoriesEvent) error {
	installation := event.GetInstallation()
	if installation == nil {
		return errors.New("installation_repositories event carried no installation")
	}
	// Not an installation lifecycle event, so it must not clear a suspension
	// or undo an uninstall -- a redelivery can arrive after either.
	record, err := h.db.EnsureInstallation(ctx, installation.GetID(),
		installation.GetAccount().GetLogin(), installation.GetAccount().GetType(), installation.GetAccount().GetID())
	if err != nil {
		return err
	}
	// Removals below still apply to an unapproved installation: revoking
	// access only takes work away, and an account dropped from the allowlist
	// may still have repositories recorded from when it was on it.
	reason, err := h.gate.refusal(ctx, record)
	if err != nil {
		return err
	}
	approved := reason == ""
	if !approved {
		logRefused(logger, record, "installation_repositories "+event.GetAction(), reason)
	}

	if approved {
		for _, repo := range event.RepositoriesAdded {
			if _, err := h.upsertRepositoryFromEvent(ctx, record.ID, repo, installation.GetAccount().GetLogin()); err != nil {
				return err
			}
		}
	}

	// Narrowing access from "All repositories" to a selection, or removing a
	// repository from the selection, arrives here. The rows are marked
	// revoked rather than deleted so their scan history survives.
	removedIDs := make([]int64, 0, len(event.RepositoriesRemoved))
	for _, repo := range event.RepositoriesRemoved {
		if id := repo.GetID(); id != 0 {
			removedIDs = append(removedIDs, id)
		}
	}
	revoked, err := h.db.MarkRepositoriesRevoked(ctx, record.ID, removedIDs)
	if err != nil {
		return err
	}

	logger.Info("updated installation repositories",
		"action", event.GetAction(), "selection", event.GetRepositorySelection(),
		"added", len(event.RepositoriesAdded), "removed", len(event.RepositoriesRemoved), "revoked", revoked)

	if !approved {
		return nil
	}
	// The event describes a delta. Reconciling afterwards repairs anything an
	// earlier, missed delivery left behind.
	return h.enqueueReconcile(ctx, logger, installation.GetID())
}

// reconcileSettleDelay holds back the reconciliation a webhook asks for. The
// webhook itself is applied immediately; the follow-up listing waits so that
// it reads GitHub after the change the webhook announced has propagated,
// rather than a listing that still shows the old selection and would undo it.
const reconcileSettleDelay = 2 * time.Minute

func (h *WebhookHandler) enqueueReconcile(ctx context.Context, logger *slog.Logger, githubInstallationID int64) error {
	// No dedupe key: reconciliation is idempotent and cheap, and a dedupe key
	// would stay pinned to a dead job and block every later reconciliation.
	jobID, err := h.queue.EnqueueAfter(ctx, queue.KindReconcileInstallation,
		queue.ReconcileInstallationPayload{GitHubInstallationID: githubInstallationID}, "", reconcileSettleDelay)
	if err != nil {
		return err
	}
	logger.Info("queued repository reconciliation", "installation", githubInstallationID, "job", jobID)
	return nil
}

// upsertRepositoryFromEvent records a repository that an installation event
// says is accessible.
func (h *WebhookHandler) upsertRepositoryFromEvent(ctx context.Context, installationID int64, repo *gh.Repository, fallbackOwner string) (models.Repository, error) {
	model, err := repositoryFromGitHub(installationID, repo, fallbackOwner)
	if err != nil {
		return models.Repository{}, err
	}
	return h.db.UpsertAccessibleRepository(ctx, model)
}

// repositoryFromGitHub handles both the full repository objects the REST API
// returns and the trimmed-down shape installation events carry, where
// FullName is present but Owner often is not.
func repositoryFromGitHub(installationID int64, repo *gh.Repository, fallbackOwner string) (models.Repository, error) {
	if repo == nil {
		return models.Repository{}, errors.New("github returned a nil repository")
	}
	if repo.GetID() == 0 {
		return models.Repository{}, fmt.Errorf("repository %q has no GitHub id", repo.GetFullName())
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

	return models.Repository{
		InstallationID: &installationID,
		GitHubRepoID:   githubID(repo.GetID()),
		Owner:          owner,
		Name:           name,
		DefaultBranch:  defaultBranch,
		Private:        repo.GetPrivate(),
	}, nil
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

	installationRecordID, approved, err := h.approvedInstallation(ctx, logger, event.GetInstallation(), "push")
	if err != nil || !approved {
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
	if !record.Accessible() {
		// Typically a redelivery of an event from before access was
		// revoked. The stored row is refreshed, but nothing is scanned.
		logger.Info("ignoring event for inaccessible repository", "repo", record.FullName(), "access", record.Access)
		return nil
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

	return enqueuePendingScan(ctx, h.queue, logger, scan, record.FullName())
}

func (h *WebhookHandler) handlePullRequest(ctx context.Context, logger *slog.Logger, event *gh.PullRequestEvent) error {
	switch event.GetAction() {
	case "opened", "reopened", "synchronize", "ready_for_review":
	case "closed", "edited":
		return h.recordPullRequestState(ctx, logger, event)
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

	installationRecordID, approved, err := h.approvedInstallation(ctx, logger, event.GetInstallation(), "pull_request")
	if err != nil || !approved {
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
	if !record.Accessible() {
		// Typically a redelivery of an event from before access was
		// revoked. The stored row is refreshed, but nothing is scanned.
		logger.Info("ignoring event for inaccessible repository", "repo", record.FullName(), "access", record.Access)
		return nil
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
	return enqueuePendingScan(ctx, h.queue, logger, scan, record.FullName())
}

// recordPullRequestState keeps a scanned pull request's state and title
// current when it is closed, merged or retitled. Nothing is scanned: the
// code did not change.
func (h *WebhookHandler) recordPullRequestState(ctx context.Context, logger *slog.Logger, event *gh.PullRequestEvent) error {
	repo := event.GetRepo()
	pr := event.GetPullRequest()
	if repo == nil || pr == nil {
		return errors.New("pull_request event was missing its repository or pull request")
	}
	stored, err := h.db.GetRepositoryByGitHubID(ctx, repo.GetID())
	if errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	state := pr.GetState()
	if pr.GetMerged() {
		state = "merged"
	}
	changed, err := h.db.UpdatePullRequestState(ctx, stored.ID, pr.GetNumber(), state, pr.GetTitle())
	if err != nil {
		return err
	}
	if changed {
		logger.Info("recorded pull request state", "pr", pr.GetNumber(), "state", state)
	}
	return nil
}

// enqueuePendingScan queues a scan job for a scan that has not started. Every
// path that creates a scan -- push, pull request and initial scan -- goes
// through it, so they share one dedupe key per scan and cannot queue the same
// scan twice or re-run one that is already finished.
func enqueuePendingScan(ctx context.Context, q *queue.Queue, logger *slog.Logger, scan models.Scan, fullName string) error {
	// A scan already past pending was queued by an earlier delivery of the
	// same commit; leave it alone rather than racing the worker.
	if scan.Status != models.ScanPending {
		logger.Info("scan already in flight", "scan", scan.ID, "status", scan.Status)
		return nil
	}

	dedupeKey := fmt.Sprintf("scan:%d", scan.ID)
	jobID, err := q.Enqueue(ctx, queue.KindScan, queue.ScanPayload{ScanID: scan.ID}, dedupeKey)
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

// approvedInstallation maps GitHub's installation ID to our row ID, tolerating
// events that arrive before the installation event itself, and reports
// whether the installation gate lets it queue work. An event with no
// installation is never approved.
//
// Push and pull request payloads carry only the installation's ID, so this
// must not use UpsertInstallation: that would blank the stored account and
// clear any suspension or uninstall. The account ID, which an account
// allowlist needs, comes from the stored row that the installation event or
// reconciliation filled in.
func (h *WebhookHandler) approvedInstallation(ctx context.Context, logger *slog.Logger, installation *gh.Installation, event string) (*int64, bool, error) {
	if installation == nil || installation.GetID() == 0 {
		logger.Warn("ignoring event with no GitHub App installation", "trigger", event)
		return nil, false, nil
	}
	record, err := h.db.EnsureInstallation(ctx, installation.GetID(),
		installation.GetAccount().GetLogin(), installation.GetAccount().GetType(), installation.GetAccount().GetID())
	if err != nil {
		return nil, false, err
	}
	reason, err := h.gate.refusal(ctx, record)
	if err != nil {
		return nil, false, err
	}
	if reason != "" {
		logRefused(logger, record, event, reason)
		return nil, false, nil
	}
	return &record.ID, true, nil
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
