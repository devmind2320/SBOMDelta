package github

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	gh "github.com/google/go-github/v66/github"

	"sbomdelta/internal/models"
	"sbomdelta/internal/storage/storagetest"
)

const testWebhookSecret = "webhook-test-secret"

func pullRequestEvent(action string, number int, head string, merged bool) *gh.PullRequestEvent {
	return &gh.PullRequestEvent{
		Action: gh.String(action),
		Number: gh.Int(number),
		Repo: &gh.Repository{
			ID: gh.Int64(8801), Name: gh.String("api"), DefaultBranch: gh.String("main"), Private: gh.Bool(true),
			Owner: &gh.User{Login: gh.String("devmind2320")},
		},
		PullRequest: &gh.PullRequest{
			Number: gh.Int(number), Title: gh.String("Bump lodash"), State: gh.String(map[bool]string{true: "closed", false: "open"}[action == "closed"]),
			Merged: gh.Bool(merged), User: &gh.User{Login: gh.String("dev")},
			Base: &gh.PullRequestBranch{Ref: gh.String("main"), SHA: gh.String("1111111111111111111111111111111111111111")},
			Head: &gh.PullRequestBranch{Ref: gh.String("bump"), SHA: gh.String(head)},
		},
		Installation: &gh.Installation{ID: gh.Int64(testInstallationID)},
	}
}

func deliver(t *testing.T, h http.Handler, event string, deliveryID string, payload any, secret string) int {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Event", event)
	request.Header.Set("X-GitHub-Delivery", deliveryID)
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		request.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, request)
	return recorder.Code
}

// Webhooks are authenticated by signature before anything is parsed, a
// redelivered event is a no-op, and a pull request's scan is queued once.
// Closing or merging it records the state without scanning again.
func TestWebhookIsAuthenticatedIdempotentAndFollowsThePullRequest(t *testing.T) {
	db := storagetest.Open(t, "test_github")
	ctx := context.Background()
	if _, err := db.UpsertInstallation(ctx, models.Installation{
		GitHubInstallationID: testInstallationID, AccountLogin: "devmind2320", AccountID: testAccountID, AccountType: "User",
	}); err != nil {
		t.Fatal(err)
	}
	h := NewWebhookHandler(testWebhookSecret, testAllowedAccounts, db, testQueue(db), discardLogger())
	head := "2222222222222222222222222222222222222222"
	opened := pullRequestEvent("opened", 12, head, false)

	if code := deliver(t, h, "pull_request", "d-unsigned", opened, ""); code != http.StatusUnauthorized {
		t.Errorf("unsigned delivery = %d, want 401", code)
	}
	if code := deliver(t, h, "pull_request", "d-forged", opened, "not-the-secret"); code != http.StatusUnauthorized {
		t.Errorf("wrongly signed delivery = %d, want 401", code)
	}
	if n := scanCount(t, db); n != 0 {
		t.Fatalf("a rejected delivery created %d scans", n)
	}

	for range 2 { // GitHub redelivers; the second is a replay
		if code := deliver(t, h, "pull_request", "d-1", opened, testWebhookSecret); code != http.StatusAccepted {
			t.Fatalf("signed delivery = %d, want 202", code)
		}
	}
	// A different delivery of the same commit (synchronize with no new
	// commits) still makes no second scan.
	if code := deliver(t, h, "pull_request", "d-2", pullRequestEvent("synchronize", 12, head, false), testWebhookSecret); code != http.StatusAccepted {
		t.Fatalf("synchronize delivery = %d", code)
	}
	var scans, jobs int
	if err := db.Pool().QueryRow(ctx, `SELECT (SELECT COUNT(*) FROM scans WHERE trigger = 'pull_request'),
		(SELECT COUNT(*) FROM jobs WHERE kind = 'scan')`).Scan(&scans, &jobs); err != nil {
		t.Fatal(err)
	}
	if scans != 1 || jobs != 1 {
		t.Errorf("after redeliveries: %d pull request scans and %d scan jobs, want 1 and 1", scans, jobs)
	}

	if code := deliver(t, h, "pull_request", "d-3", pullRequestEvent("closed", 12, head, true), testWebhookSecret); code != http.StatusAccepted {
		t.Fatalf("closed delivery = %d", code)
	}
	var state string
	if err := db.Pool().QueryRow(ctx, `SELECT state FROM pull_requests WHERE number = 12`).Scan(&state); err != nil || state != "merged" {
		t.Errorf("pull request state = %q (%v), want merged", state, err)
	}
	if n := scanCount(t, db); n != 1 {
		t.Errorf("closing the pull request changed the scan count to %d", n)
	}

	// Closing a pull request SBOMDelta never saw, in a repository it never
	// stored, is simply ignored.
	unknown := pullRequestEvent("closed", 99, head, false)
	unknown.Repo.ID = gh.Int64(9999)
	if code := deliver(t, h, "pull_request", "d-4", unknown, testWebhookSecret); code != http.StatusAccepted {
		t.Errorf("closed delivery for an unknown repository = %d, want 202", code)
	}
}
