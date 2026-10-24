package sbom

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"sbomdelta/internal/config"
)

var sha1Pattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// IsCommitSHA reports whether a string is already a full git object name.
func IsCommitSHA(value string) bool {
	return sha1Pattern.MatchString(strings.ToLower(value))
}

// ResolveRef turns a branch or tag into a full commit SHA.
//
// This asks the remote directly with `git ls-remote` rather than going through
// a forge's REST API. That keeps it host-agnostic -- GitLab, Codeberg,
// Bitbucket and self-hosted remotes all work the same way -- and avoids the
// anonymous rate limits an API would impose.
func ResolveRef(ctx context.Context, cfg config.Scanner, cloneURL, ref string) (string, error) {
	if IsCommitSHA(ref) {
		return strings.ToLower(ref), nil
	}
	if ref == "" {
		return "", errors.New("no ref to resolve")
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.CloneTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, cfg.GitPath, "ls-remote", "--exit-code", cloneURL, ref)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=true")

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("timed out resolving %q against the remote", ref)
		}
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = "no matching ref"
		}
		return "", fmt.Errorf("could not resolve %q: %s", ref, redact(detail, cloneURL))
	}

	// ls-remote prints "<sha>\t<refname>" per match. A ref can match both the
	// tag object and the commit it points at (refs/tags/x and refs/tags/x^{});
	// the dereferenced form is the commit we actually want to check out.
	var fallback string
	for _, line := range strings.Split(stdout.String(), "\n") {
		sha, name, found := strings.Cut(strings.TrimSpace(line), "\t")
		if !found || !IsCommitSHA(sha) {
			continue
		}
		if strings.HasSuffix(name, "^{}") {
			return sha, nil
		}
		if fallback == "" {
			fallback = sha
		}
	}
	if fallback == "" {
		return "", fmt.Errorf("remote returned no commit for %q", ref)
	}
	return fallback, nil
}

// CheckGit verifies the configured git is present and new enough for the
// partial clone the scanner relies on.
//
// `--filter=blob:none` landed in git 2.19. An older git on PATH is a real
// hazard: macOS in particular often has a stale /usr/local/bin/git shadowing
// a modern /usr/bin/git, and the failure would otherwise surface as a
// confusing clone error on every scan.
func CheckGit(ctx context.Context, cfg config.Scanner) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	output, err := exec.CommandContext(ctx, cfg.GitPath, "version").Output()
	if err != nil {
		return fmt.Errorf("git is not runnable at %q: %w", cfg.GitPath, err)
	}

	version := strings.TrimSpace(string(output))
	major, minor, ok := parseGitVersion(version)
	if !ok {
		// An unparseable version string is not worth failing a worker over.
		return nil
	}
	if major < 2 || (major == 2 && minor < 19) {
		return fmt.Errorf(
			"%s reports %q, but partial clone (--filter=blob:none) needs git 2.19 or newer; "+
				"set GIT_PATH to a newer binary", cfg.GitPath, version)
	}
	return nil
}

var gitVersionPattern = regexp.MustCompile(`(\d+)\.(\d+)`)

func parseGitVersion(version string) (major, minor int, ok bool) {
	match := gitVersionPattern.FindStringSubmatch(version)
	if len(match) != 3 {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(match[1], "%d", &major); err != nil {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(match[2], "%d", &minor); err != nil {
		return 0, 0, false
	}
	return major, minor, true
}
