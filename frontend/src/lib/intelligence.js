// Helpers for vulnerability, risk and impact data, with no Vue or browser
// dependency so Node's runner can test them. They only describe what the API
// returns; nothing here invents a number. "Not analyzed" and "no
// vulnerabilities" are different answers and are always worded differently.

/** The repository's page on GitHub. */
export function githubUrl(owner, name) {
  if (!owner || !name) return null
  return `https://github.com/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`
}

const SEVERITIES = [
  { key: 'critical', label: 'critical', role: 'critical' },
  { key: 'high', label: 'high', role: 'serious' },
  { key: 'medium', label: 'medium', role: 'warning' },
  { key: 'low', label: 'low', role: 'low' },
  { key: 'unrated', label: 'unrated', role: 'unknown' },
]

/** The non-zero severity counts of a vulnerability summary, most severe first. */
export function severityCounts(summary) {
  if (summary?.status !== 'analyzed') return []
  return SEVERITIES.filter(({ key }) => (summary[key] ?? 0) > 0).map(({ key, label, role }) => ({
    key,
    label,
    role,
    count: summary[key],
  }))
}

/**
 * What to say about a scan's vulnerabilities. key is analyzed, pending,
 * failed or none (no completed scan to speak of).
 */
export function vulnerabilityState(summary) {
  switch (summary?.status) {
    case 'analyzed': {
      const total = summary.total ?? 0
      const coverage =
        summary.componentsSkipped > 0
          ? `${summary.componentsSkipped} component(s) could not be checked (no version, or an ecosystem OSV does not cover).`
          : ''
      if (total === 0) {
        return { key: 'analyzed', label: 'No known vulnerabilities', detail: coverage, error: summary.error ?? '' }
      }
      const parts = severityCounts(summary).map(({ count, label }) => `${count} ${label}`)
      return {
        key: 'analyzed',
        label: `${total} known ${total === 1 ? 'vulnerability' : 'vulnerabilities'}`,
        detail: [parts.join(', '), summary.fixable ? `${summary.fixable} fixable by upgrading` : '', coverage]
          .filter(Boolean)
          .join(' · '),
        error: summary.error ?? '',
      }
    }
    case 'pending':
      return { key: 'pending', label: 'Checking for vulnerabilities…', detail: '', error: '' }
    case 'failed':
      return {
        key: 'failed',
        label: 'Vulnerability check unavailable',
        detail: 'The dependency results are complete; the vulnerability lookup is retried automatically.',
        error: summary.error ?? '',
      }
    default:
      return { key: 'none', label: '—', detail: '', error: '' }
  }
}

/** "+2 new · 1 resolved" against the base scan, or '' when not comparable. */
export function vulnerabilityChangeLabel(summary) {
  if (summary?.status !== 'analyzed') return ''
  const introduced = summary.introduced
  const resolved = summary.resolved
  if (typeof introduced !== 'number' || typeof resolved !== 'number') return ''
  if (!introduced && !resolved) return 'No vulnerability changes'
  return [introduced ? `+${introduced} new` : '', resolved ? `${resolved} resolved` : ''].filter(Boolean).join(' · ')
}

const LEVELS = {
  none: { label: 'None', tone: 'good' },
  low: { label: 'Low', tone: 'low' },
  medium: { label: 'Medium', tone: 'warning' },
  high: { label: 'High', tone: 'serious' },
  critical: { label: 'Critical', tone: 'critical' },
}

/** How to show a risk summary; an unscored scan is never shown as 0. */
export function riskState(risk) {
  if (!risk || typeof risk.score !== 'number' || !Number.isFinite(risk.score)) {
    return { scored: false, label: 'Not scored', score: '—', level: '', tone: 'neutral', delta: '' }
  }
  const level = LEVELS[risk.level] ?? { label: risk.level || '—', tone: 'neutral' }
  let delta = ''
  if (typeof risk.delta === 'number' && risk.delta !== 0) {
    delta = `${risk.delta > 0 ? '+' : ''}${formatScore(risk.delta)} vs previous`
  }
  return { scored: true, label: level.label, score: formatScore(risk.score), level: risk.level, tone: level.tone, delta }
}

export function formatScore(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—'
  return Number.isInteger(value) ? String(value) : value.toFixed(1)
}

/**
 * Whether a repository from "All Repositories" can be tracked now, and if
 * not, why: SBOMDelta stores a repository shortly after the App's
 * installation lists it, and cannot track one it has not stored.
 */
export function trackAvailability(repository) {
  if (!repository?.repositoryId) {
    return { ok: false, reason: 'SBOMDelta is still syncing this repository from GitHub. Try again in a minute.' }
  }
  return { ok: true, reason: '' }
}

/** The branch or pull request a scan looked at. */
export function scanRefLabel(scan) {
  if (scan?.pullRequestNumber) return `PR #${scan.pullRequestNumber}`
  const ref = scan?.ref ?? ''
  if (ref.startsWith('refs/heads/')) return ref.slice('refs/heads/'.length)
  return scan?.defaultBranch || ''
}

/** Human description of a scan's dependency changes. */
export function driftLabel(scan) {
  if (!scan || scan.status !== 'completed') return '—'
  if (scan.baseline) return 'Initial inventory'
  const { added = 0, updated = 0, removed = 0 } = scan
  if (!added && !updated && !removed) return 'No changes'
  return `+${added} added · ${updated} changed · −${removed} removed`
}

function isBlocking(finding) {
  const severity = String(finding?.severity ?? '').toUpperCase()
  return severity === 'CRITICAL' || severity === 'HIGH'
}

/**
 * The pull request verdict, mirroring the policy the GitHub check applies
 * (backend internal/github/checks.go): critical or high vulnerabilities
 * introduced fail; other introduced vulnerabilities, dependency changes, or
 * missing vulnerability data ask for review; otherwise it passes.
 */
export function pullRequestVerdict({ scanId, scanStatus, hasDrift, changes }) {
  if (!scanId) {
    return { label: 'Not scanned', tone: 'neutral', note: 'No scan has run for this pull request yet.' }
  }
  if (scanStatus === 'failed') {
    return {
      label: 'Scan failed',
      tone: 'critical',
      note: 'SBOMDelta could not analyze this commit. This reports a broken scan, not a security finding.',
    }
  }
  if (scanStatus !== 'completed') {
    return { label: 'In progress', tone: 'neutral', note: 'The scan is still running.' }
  }
  if (changes?.available) {
    const introduced = changes.comparison?.introduced ?? []
    const blocking = introduced.filter(isBlocking).length
    if (blocking > 0) {
      return {
        label: `Introduces ${blocking} critical/high ${blocking === 1 ? 'vulnerability' : 'vulnerabilities'}`,
        tone: 'critical',
        note: 'The GitHub check fails for this pull request. Upgrade or remove the affected packages before merging.',
      }
    }
    if (introduced.length > 0) {
      return {
        label: `Introduces ${introduced.length} lower-severity ${introduced.length === 1 ? 'vulnerability' : 'vulnerabilities'}`,
        tone: 'warning',
        note: 'Worth reviewing; the GitHub check is neutral rather than failing.',
      }
    }
  }
  if (!changes?.available) {
    return {
      label: hasDrift ? 'Review dependency changes' : 'No dependency changes',
      tone: 'warning',
      note: `Vulnerability comparison unavailable: ${changes?.reason ?? 'not loaded yet.'}`,
    }
  }
  if (hasDrift) {
    return {
      label: 'Review dependency changes',
      tone: 'warning',
      note: 'Dependencies moved, but no new known vulnerabilities were introduced.',
    }
  }
  return { label: 'No dependency changes', tone: 'good', note: 'This pull request does not alter the dependency set.' }
}
