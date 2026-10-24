package sbom

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"sbomdelta/internal/config"
)

// Generator produces a CycloneDX SBOM for a checked-out working tree by
// shelling out to syft.
//
// syft is a separate process rather than a library so that upgrading the
// scanner does not mean rebuilding and redeploying this service, and so that a
// scanner crash cannot take a worker down with it.
type Generator struct {
	cfg config.Scanner
}

func NewGenerator(cfg config.Scanner) *Generator {
	return &Generator{cfg: cfg}
}

// Check verifies the syft binary is present and runnable. Workers call this at
// startup so a missing dependency surfaces immediately rather than as a wave
// of failed scans.
func (g *Generator) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	output, err := exec.CommandContext(ctx, g.cfg.SyftPath, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("syft is not runnable at %q: %w", g.cfg.SyftPath, err)
	}
	if !strings.Contains(strings.ToLower(string(output)), "syft") {
		return fmt.Errorf("%q does not look like syft", g.cfg.SyftPath)
	}
	return nil
}

// Generate runs syft over a directory and returns the parsed document. The raw
// CycloneDX bytes are preserved on the result for archival.
func (g *Generator) Generate(ctx context.Context, dir string) (*Document, error) {
	ctx, cancel := context.WithTimeout(ctx, g.cfg.SBOMTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, g.cfg.SyftPath,
		"scan", "dir:"+dir,
		"--output", "cyclonedx-json",
		"--quiet",
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// syft writes its cache under $HOME; without a writable one it falls back
	// to noisy warnings on every invocation.
	cmd.Env = append(os.Environ(), "SYFT_CHECK_FOR_APP_UPDATE=false")

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("syft timed out after %s", g.cfg.SBOMTimeout)
		}
		return nil, fmt.Errorf("syft failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	document, err := ParseCycloneDX(stdout.Bytes())
	if err != nil {
		return nil, err
	}
	return document, nil
}

// Clone fetches a single commit into a fresh directory.
//
// The clone is deliberately shallow and blobless: SBOM generation only needs
// the tree at one commit, and full history on a large repository is both slow
// and a disk-exhaustion risk on a shared worker.
func Clone(ctx context.Context, cfg config.Scanner, cloneURL, commitSHA, dir string) error {
	ctx, cancel := context.WithTimeout(ctx, cfg.CloneTimeout)
	defer cancel()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create clone directory: %w", err)
	}

	steps := [][]string{
		{"init", "--quiet"},
		{"remote", "add", "origin", cloneURL},
		{"fetch", "--quiet", "--depth", "1", "--filter=blob:none", "origin", commitSHA},
		{"checkout", "--quiet", "FETCH_HEAD"},
	}

	for _, args := range steps {
		cmd := exec.CommandContext(ctx, cfg.GitPath, args...)
		cmd.Dir = dir
		// Never let git block a worker waiting for credentials on a repo the
		// installation token does not actually cover.
		cmd.Env = append(os.Environ(),
			"GIT_TERMINAL_PROMPT=0",
			"GIT_ASKPASS=true",
			"GCM_INTERACTIVE=never",
		)

		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("git %s timed out after %s", args[0], cfg.CloneTimeout)
			}
			// The clone URL carries an access token, so report the failing
			// subcommand and git's message but never the command line.
			return fmt.Errorf("git %s failed: %w: %s", args[0], err, redact(stderr.String(), cloneURL))
		}
	}
	return nil
}

// WorkDir creates an isolated directory for one scan.
func WorkDir(cfg config.Scanner, scanID int64) (string, error) {
	dir := filepath.Join(cfg.WorkDir, fmt.Sprintf("sbomdelta-scan-%d", scanID))
	if err := os.RemoveAll(dir); err != nil {
		return "", fmt.Errorf("clear work directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create work directory: %w", err)
	}
	return dir, nil
}

// redact strips an access token out of a message before it reaches a log or a
// GitHub check body.
func redact(message, cloneURL string) string {
	message = strings.TrimSpace(message)
	if token := tokenFrom(cloneURL); token != "" {
		message = strings.ReplaceAll(message, token, "***")
	}
	return message
}

func tokenFrom(cloneURL string) string {
	_, rest, found := strings.Cut(cloneURL, "://")
	if !found {
		return ""
	}
	userinfo, _, found := strings.Cut(rest, "@")
	if !found {
		return ""
	}
	_, token, found := strings.Cut(userinfo, ":")
	if !found {
		return ""
	}
	return token
}
