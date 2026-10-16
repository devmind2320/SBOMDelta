package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// sha1Pattern matches a full 40-character git object name.
var sha1Pattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// IsCommitSHA reports whether a string is already a full commit SHA and needs
// no resolution.
func IsCommitSHA(value string) bool {
	return sha1Pattern.MatchString(strings.ToLower(value))
}

// ResolvePublicRef turns a branch, tag or short SHA into a full commit SHA
// using GitHub's public REST API.
//
// This is deliberately unauthenticated: it exists so a public repository can
// be scanned without installing the App. Unauthenticated calls are rate
// limited to 60 per hour per IP, which is ample for hand-triggered scans but
// is why nothing automatic depends on this path.
func ResolvePublicRef(ctx context.Context, owner, name, ref string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", owner, name, ref)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build ref request: %w", err)
	}
	// This media type makes GitHub return just the SHA as the body, so there
	// is no commit payload to parse.
	request.Header.Set("Accept", "application/vnd.github.sha")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("resolve %s in %s/%s: %w", ref, owner, name, err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("read ref response: %w", err)
	}

	switch response.StatusCode {
	case http.StatusOK:
		sha := strings.TrimSpace(string(body))
		if !IsCommitSHA(sha) {
			return "", fmt.Errorf("github returned %q, which is not a commit sha", sha)
		}
		return sha, nil
	case http.StatusNotFound:
		return "", fmt.Errorf("%s/%s has no ref %q, or the repository is private", owner, name, ref)
	case http.StatusForbidden, http.StatusTooManyRequests:
		return "", fmt.Errorf(
			"github rate limited the anonymous ref lookup; pass an exact commitSha instead")
	default:
		return "", fmt.Errorf("github returned %s resolving %q", response.Status, ref)
	}
}
