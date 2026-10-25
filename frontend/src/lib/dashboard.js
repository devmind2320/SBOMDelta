// Dashboard helpers with no Vue or browser dependency, so they can be tested
// with Node's own runner. Everything shown comes from the API; these only
// decide how to describe it.

/** The state of a repository's latest scan, as the dashboard names it. */
export function scanState(scan) {
  switch (scan?.status) {
    case undefined:
    case null:
      return { key: 'never', label: 'Never scanned' }
    case 'pending':
      return { key: 'pending', label: 'Queued' }
    case 'running':
      return { key: 'running', label: 'Scanning' }
    case 'completed':
      return { key: 'completed', label: 'Completed' }
    case 'failed':
      return { key: 'failed', label: 'Failed' }
    default:
      return { key: 'unknown', label: String(scan.status) }
  }
}

/** Whether a scan is still waiting or running, so its status will change. */
export function isScanActive(scan) {
  return scan?.status === 'pending' || scan?.status === 'running'
}

/**
 * A date and time with its time zone, e.g. "Oct 25, 2026, 09:42 GMT+5:30".
 * Scans finish on the server's clock; naming the zone avoids a reader
 * mistaking the viewer's local time for it.
 */
export function formatDateTimeWithZone(value, locale = undefined, timeZone = undefined) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString(locale, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
    timeZone,
  })
}

/**
 * The dependency change summary of a tracked repository's last completed
 * scan: an initial inventory has nothing to compare against.
 */
export function changesLabel(tracked) {
  if (!tracked?.lastCompletedScan) return '—'
  if (tracked.baseline) return 'Initial inventory'
  const { added = 0, updated = 0, removed = 0 } = tracked
  if (!added && !updated && !removed) return 'No changes'
  return `+${added} added · ${updated} updated · −${removed} removed`
}

/**
 * Whether a repository from "All Repos" can be scanned now, and if not, why.
 * SBOMDelta stores a repository shortly after the App's installation lists
 * it; until then there is nothing to scan yet.
 */
export function scanAvailability(repository) {
  if (!repository?.repositoryId) {
    return { ok: false, reason: 'SBOMDelta is still syncing this repository from GitHub. Try again in a minute.' }
  }
  if (repository.access && repository.access !== 'active') {
    return { ok: false, reason: "SBOMDelta's GitHub App no longer has access to this repository." }
  }
  return { ok: true, reason: '' }
}

/** What a successful scan request did, in words. */
export function scanOutcomeMessage(outcome) {
  switch (outcome) {
    case 'queued':
      return 'Scan queued. The status updates here as it runs.'
    case 'in_progress':
      return 'A scan of the latest commit is already running.'
    case 'up_to_date':
      return 'The latest commit is already scanned; its results are current.'
    case 'retried':
      return 'The last scan of this commit failed, so it was queued again.'
    default:
      return 'Scan requested.'
  }
}

// Why the repository list from GitHub could not be read, by the code the
// server records. Unknown codes get a generic message, never the code itself.
const LISTING_ERRORS = {
  unauthorized: 'GitHub no longer accepts this sign-in. Sign in again to reload your repositories.',
  rate_limited: 'GitHub is rate limiting requests right now. Refresh your repositories in a few minutes.',
  github: 'GitHub could not list your repositories. Refresh to try again.',
  too_many: 'This account can reach more repositories than SBOMDelta lists at once.',
  auth_disabled:
    'Sign-in is disabled for local development, so this lists every repository SBOMDelta has stored instead of your GitHub list. Tracking needs a signed-in user and is unavailable.',
}

export function listingErrorMessage(code) {
  if (!code) return ''
  return Object.hasOwn(LISTING_ERRORS, code) ? LISTING_ERRORS[code] : 'Your repositories could not be loaded.'
}

/** "Showing 31–60 of 125", for a page of results. */
export function pageRange(page, perPage, total, shown) {
  if (!total || !shown) return total ? `0 of ${total}` : ''
  const first = (page - 1) * perPage + 1
  return `${first}–${first + shown - 1} of ${total}`
}
