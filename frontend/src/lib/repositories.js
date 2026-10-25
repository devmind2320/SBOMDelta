// The repository workflow the Repositories page shows, with no Vue or browser
// dependency so Node's runner can test it. Tracked Repositories and All
// Repositories both describe a repository through repositoryWorkflow(), so a
// repository listed in both reads the same in both.
//
// Four facts are kept apart and never inferred from one another:
//   - accessible: SBOMDelta has stored it and its GitHub App can reach it;
//   - tracked:    the user chose to monitor it (only the API says so);
//   - has report: a branch scan completed, so there is a report to open;
//   - latest scan: queued, running, failed or completed -- a failed or
//     running scan never replaces the last completed one.

/** The viewer's IANA time zone, which every dashboard timestamp uses. */
export function viewerTimeZone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  } catch {
    return 'UTC'
  }
}

/**
 * "DD-MM-YYYY at HH:MM" in the given time zone (24-hour clock), or '' for a
 * missing or unreadable value. Never substitutes the current time.
 */
export function formatScanDate(value, timeZone = viewerTimeZone()) {
  if (!value) return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date)
  const get = (type) => parts.find((part) => part.type === type)?.value ?? ''
  return `${get('day')}-${get('month')}-${get('year')} at ${get('hour')}:${get('minute')}`
}

/** "Last scanned on 25-10-2026 at 18:45", or '' without a usable time. */
export function formatLastScanned(value, timeZone = viewerTimeZone()) {
  const text = formatScanDate(value, timeZone)
  return text ? `Last scanned on ${text}` : ''
}

/** Ends a server message with a full stop, so another sentence can follow it. */
export function asSentence(text) {
  const trimmed = String(text ?? '').trim()
  if (!trimmed) return ''
  return /[.!?]$/.test(trimmed) ? trimmed : `${trimmed}.`
}

/**
 * The SBOMDelta repository id of a row from either list: All Repositories
 * rows carry repositoryId (absent until the installation is synced), Tracked
 * Repositories rows are the repository itself.
 */
export function repositoryKey(repo) {
  return repo?.repositoryId ?? repo?.id ?? null
}

export function isActiveScan(scan) {
  return scan?.status === 'pending' || scan?.status === 'running'
}

/** Whether the row has a completed branch scan, i.e. a report to open. */
export function hasReport(repo) {
  const scan = repo?.lastCompletedScan
  return Boolean(scan?.id) && scan.status === 'completed'
}

const STATUS = {
  pending: { key: 'queued', label: 'Scan queued', tone: 'info' },
  running: { key: 'running', label: 'Scan in progress', tone: 'info' },
}

/**
 * Everything the dashboard needs to show one repository and its actions.
 * busy is true while this page has a request for it in flight.
 */
export function repositoryWorkflow(repo, { busy = false, timeZone = viewerTimeZone() } = {}) {
  const id = repositoryKey(repo)
  const latest = repo?.latestScan ?? null
  const completed = hasReport(repo) ? repo.lastCompletedScan : null
  const active = isActiveScan(latest)
  const failed = latest?.status === 'failed'
  const access = repo?.access ?? (id ? 'active' : null)

  let lastScannedText = 'Not scanned yet'
  if (completed) {
    lastScannedText = formatLastScanned(completed.finishedAt, timeZone) || 'Last scanned (time not recorded)'
  }

  let status = null
  if (active) status = STATUS[latest.status]
  else if (failed) {
    status = completed
      ? { key: 'failed', label: 'Latest scan failed', tone: 'danger' }
      : { key: 'failed', label: 'Scan failed', tone: 'danger' }
  }

  let unavailable = ''
  if (!id) unavailable = 'SBOMDelta is still syncing this repository from GitHub. Try again in a minute.'
  else if (access !== 'active') unavailable = "SBOMDelta's GitHub App no longer has access to this repository."

  let label = completed ? 'Scan again' : 'Scan'
  if (busy) label = 'Requesting…'
  else if (latest?.status === 'pending') label = 'Queued…'
  else if (latest?.status === 'running') label = 'Scanning…'

  return {
    id,
    tracked: Boolean(repo?.tracked ?? repo?.trackedAt),
    hasReport: Boolean(completed),
    reportScanId: completed?.id ?? null,
    lastScannedAt: completed?.finishedAt ?? null,
    lastScannedText,
    status,
    failure: failed ? latest.error || '' : '',
    active,
    scan: {
      label,
      disabled: busy || active || Boolean(unavailable),
      reason: unavailable,
    },
  }
}

/**
 * Tracked Repositories shows a tracked repository once it has a report. A
 * tracked repository that has not completed a scan yet is listed separately
 * rather than shown with an empty report.
 */
export function splitTracked(list) {
  const ready = []
  const awaiting = []
  for (const repo of list ?? []) (hasReport(repo) ? ready : awaiting).push(repo)
  return { ready, awaiting }
}

const SEVERITY_KEYS = ['critical', 'high', 'medium', 'low', 'unrated']

/**
 * The security overview cards, from the tracked repositories' last completed
 * scans. Nothing is estimated: a repository whose vulnerabilities are still
 * being checked, or could not be, is counted as such and never as zero, and
 * the risk card shows the highest persisted score rather than an invented
 * aggregate.
 */
export function securityOverview(trackedList) {
  const list = trackedList ?? []
  const { ready, awaiting } = splitTracked(list)

  let components = 0
  const vulnerabilities = { total: 0, analyzed: 0, pending: 0, failed: 0 }
  for (const key of SEVERITY_KEYS) vulnerabilities[key] = 0
  let top = null
  let scored = 0

  for (const repo of ready) {
    const scan = repo.lastCompletedScan
    components += scan.componentCount ?? 0
    const summary = scan.vulnerabilities
    if (summary?.status === 'analyzed') {
      vulnerabilities.analyzed += 1
      vulnerabilities.total += summary.total ?? 0
      for (const key of SEVERITY_KEYS) vulnerabilities[key] += summary[key] ?? 0
    } else if (summary?.status === 'failed') {
      vulnerabilities.failed += 1
    } else {
      vulnerabilities.pending += 1
    }
    const score = scan.risk?.score
    if (typeof score === 'number' && Number.isFinite(score)) {
      scored += 1
      if (!top || score > top.score) {
        top = {
          score,
          level: scan.risk.level ?? '',
          owner: repo.owner,
          name: repo.name,
          repositoryId: repositoryKey(repo),
          scanId: scan.id,
        }
      }
    }
  }

  let vulnerabilityState = 'none'
  if (vulnerabilities.analyzed > 0) vulnerabilityState = 'analyzed'
  else if (vulnerabilities.pending > 0) vulnerabilityState = 'pending'
  else if (vulnerabilities.failed > 0) vulnerabilityState = 'unavailable'

  return {
    tracked: list.length,
    reporting: ready.length,
    awaitingFirstScan: awaiting.length,
    components: ready.length ? components : null,
    vulnerabilities: { ...vulnerabilities, state: vulnerabilityState },
    risk: { top, scored, unscored: ready.length - scored },
  }
}
