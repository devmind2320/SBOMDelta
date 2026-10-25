import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  asSentence,
  formatLastScanned,
  formatScanDate,
  hasReport,
  repositoryKey,
  repositoryWorkflow,
  securityOverview,
  splitTracked,
} from './repositories.js'

const UTC = 'UTC'

function scan(id, status, extra = {}) {
  return { id, status, commitSha: `sha${id}`, componentCount: 0, createdAt: '2026-10-25T13:00:00Z', ...extra }
}

const completed = scan(10, 'completed', { finishedAt: '2026-10-25T13:15:42Z', componentCount: 40 })

test('the last-scanned text uses DD-MM-YYYY at HH:MM in a stated time zone', () => {
  assert.equal(formatLastScanned('2026-10-25T18:45:10Z', UTC), 'Last scanned on 25-10-2026 at 18:45')
  // Same instant, another zone: the zone is applied, not the server's clock.
  assert.equal(formatLastScanned('2026-10-25T18:45:10Z', 'Asia/Kolkata'), 'Last scanned on 26-10-2026 at 00:15')
  assert.equal(formatScanDate('2026-01-05T07:03:00Z', UTC), '05-01-2026 at 07:03')
})

test('server messages end with exactly one full stop', () => {
  assert.equal(asSentence('Repository not found.'), 'Repository not found.')
  assert.equal(asSentence('no packages found'), 'no packages found.')
  assert.equal(asSentence('  '), '')
  assert.equal(asSentence(null), '')
})

test('a missing or unreadable time is never replaced by the current time', () => {
  assert.equal(formatLastScanned(null, UTC), '')
  assert.equal(formatLastScanned(undefined, UTC), '')
  assert.equal(formatLastScanned('not a date', UTC), '')
})

test('a never-scanned repository offers Scan and no report', () => {
  const state = repositoryWorkflow({ repositoryId: 4, access: 'active', tracked: false }, { timeZone: UTC })
  assert.equal(state.scan.label, 'Scan')
  assert.equal(state.scan.disabled, false)
  assert.equal(state.hasReport, false)
  assert.equal(state.reportScanId, null)
  assert.equal(state.lastScannedText, 'Not scanned yet')
  assert.equal(state.status, null)
})

test('a successfully scanned repository offers Scan again and opens its report', () => {
  const state = repositoryWorkflow(
    { repositoryId: 4, access: 'active', latestScan: completed, lastCompletedScan: completed },
    { timeZone: UTC },
  )
  assert.equal(state.scan.label, 'Scan again')
  assert.equal(state.hasReport, true)
  assert.equal(state.reportScanId, 10)
  assert.equal(state.lastScannedText, 'Last scanned on 25-10-2026 at 13:15')
})

test('the timestamp is the completed scan’s finish time, not when it was queued', () => {
  const state = repositoryWorkflow({ id: 4, lastCompletedScan: completed }, { timeZone: UTC })
  assert.equal(state.lastScannedAt, completed.finishedAt)
  assert.notEqual(state.lastScannedText, formatLastScanned(completed.createdAt, UTC))
})

test('a failed rescan keeps the last successful timestamp and report', () => {
  const failed = scan(11, 'failed', { error: 'clone failed', finishedAt: '2026-10-26T09:00:00Z' })
  const state = repositoryWorkflow({ id: 4, latestScan: failed, lastCompletedScan: completed }, { timeZone: UTC })
  assert.equal(state.lastScannedText, 'Last scanned on 25-10-2026 at 13:15')
  assert.equal(state.hasReport, true)
  assert.equal(state.reportScanId, 10)
  assert.equal(state.scan.label, 'Scan again')
  assert.equal(state.status.label, 'Latest scan failed')
  assert.equal(state.failure, 'clone failed')
})

test('a failed first scan does not unlock the report and can be retried', () => {
  const failed = scan(11, 'failed', { error: 'clone failed' })
  const state = repositoryWorkflow({ repositoryId: 4, access: 'active', latestScan: failed }, { timeZone: UTC })
  assert.equal(state.hasReport, false)
  assert.equal(state.reportScanId, null)
  assert.equal(state.lastScannedText, 'Not scanned yet')
  assert.equal(state.status.label, 'Scan failed')
  assert.equal(state.scan.label, 'Scan')
  assert.equal(state.scan.disabled, false)
})

test('while a rescan runs, the previous report stays open and the button is disabled', () => {
  for (const [status, label, statusLabel] of [
    ['pending', 'Queued…', 'Scan queued'],
    ['running', 'Scanning…', 'Scan in progress'],
  ]) {
    const state = repositoryWorkflow(
      { id: 4, latestScan: scan(12, status), lastCompletedScan: completed },
      { timeZone: UTC },
    )
    assert.equal(state.hasReport, true, status)
    assert.equal(state.reportScanId, 10, status)
    assert.equal(state.lastScannedText, 'Last scanned on 25-10-2026 at 13:15', status)
    assert.equal(state.scan.label, label)
    assert.equal(state.scan.disabled, true)
    assert.equal(state.status.label, statusLabel)
  }
  // A first scan in progress has no timestamp to show yet.
  const first = repositoryWorkflow({ repositoryId: 4, access: 'active', latestScan: scan(12, 'running') }, { timeZone: UTC })
  assert.equal(first.lastScannedText, 'Not scanned yet')
  assert.equal(first.hasReport, false)
})

test('a request in flight disables the button until it answers', () => {
  const state = repositoryWorkflow({ repositoryId: 4, access: 'active' }, { busy: true, timeZone: UTC })
  assert.equal(state.scan.label, 'Requesting…')
  assert.equal(state.scan.disabled, true)
})

test('an unsynced or inaccessible repository cannot be scanned, and says why', () => {
  const unsynced = repositoryWorkflow({ githubRepoId: 9, owner: 'a', name: 'b' }, { timeZone: UTC })
  assert.equal(unsynced.id, null)
  assert.equal(unsynced.scan.disabled, true)
  assert.match(unsynced.scan.reason, /syncing/)
  const revoked = repositoryWorkflow({ repositoryId: 4, access: 'revoked' }, { timeZone: UTC })
  assert.equal(revoked.scan.disabled, true)
  assert.match(revoked.scan.reason, /no longer has access/)
})

test('tracking is read from the API, never inferred from scanning', () => {
  const scannedOnly = repositoryWorkflow(
    { repositoryId: 4, tracked: false, latestScan: completed, lastCompletedScan: completed },
    { timeZone: UTC },
  )
  assert.equal(scannedOnly.tracked, false)
  assert.equal(scannedOnly.hasReport, true)
  const trackedRow = repositoryWorkflow({ id: 4, trackedAt: '2026-10-01T00:00:00Z' }, { timeZone: UTC })
  assert.equal(trackedRow.tracked, true)
  assert.equal(trackedRow.hasReport, false)
})

test('both lists describe the same repository identically', () => {
  const latest = scan(12, 'running')
  const fromAll = { repositoryId: 4, access: 'active', tracked: true, latestScan: latest, lastCompletedScan: completed }
  const fromTracked = { id: 4, access: 'active', trackedAt: '2026-10-01T00:00:00Z', latestScan: latest, lastCompletedScan: completed }
  assert.equal(repositoryKey(fromAll), repositoryKey(fromTracked))
  const a = repositoryWorkflow(fromAll, { timeZone: UTC })
  const b = repositoryWorkflow(fromTracked, { timeZone: UTC })
  assert.deepEqual(a, b)
})

test('Tracked Repositories holds only tracked repositories with a report', () => {
  const ready = { id: 1, lastCompletedScan: completed }
  const never = { id: 2 }
  const failedFirst = { id: 3, latestScan: scan(5, 'failed') }
  const { ready: shown, awaiting } = splitTracked([ready, never, failedFirst])
  assert.deepEqual(shown.map((r) => r.id), [1])
  assert.deepEqual(awaiting.map((r) => r.id), [2, 3])
  assert.equal(hasReport({ lastCompletedScan: scan(6, 'failed') }), false)
  assert.deepEqual(splitTracked(null), { ready: [], awaiting: [] })
})

test('the overview counts vulnerabilities only where they were checked', () => {
  const analyzed = (id, summary, risk) => ({
    id,
    owner: 'acme',
    name: `r${id}`,
    lastCompletedScan: { ...completed, id, componentCount: 10, vulnerabilities: { status: 'analyzed', ...summary }, risk },
  })
  const overview = securityOverview([
    analyzed(1, { total: 3, critical: 1, high: 2 }, { score: 22, level: 'medium' }),
    analyzed(2, { total: 0 }, { score: 0, level: 'none' }),
    { id: 3, lastCompletedScan: { ...completed, id: 3, componentCount: 5, vulnerabilities: { status: 'pending' } } },
    { id: 4, lastCompletedScan: { ...completed, id: 4, componentCount: 5, vulnerabilities: { status: 'failed', error: 'osv down' } } },
    { id: 5 },
  ])
  assert.equal(overview.tracked, 5)
  assert.equal(overview.reporting, 4)
  assert.equal(overview.awaitingFirstScan, 1)
  assert.equal(overview.components, 30)
  assert.equal(overview.vulnerabilities.state, 'analyzed')
  assert.equal(overview.vulnerabilities.total, 3)
  assert.equal(overview.vulnerabilities.critical, 1)
  assert.equal(overview.vulnerabilities.high, 2)
  assert.equal(overview.vulnerabilities.analyzed, 2)
  assert.equal(overview.vulnerabilities.pending, 1)
  assert.equal(overview.vulnerabilities.failed, 1)
  assert.equal(overview.risk.top.score, 22)
  assert.equal(overview.risk.top.name, 'r1')
  assert.equal(overview.risk.scored, 2)
  assert.equal(overview.risk.unscored, 2)
})

test('pending and unavailable are never reported as zero vulnerabilities', () => {
  const pending = securityOverview([{ id: 1, lastCompletedScan: { ...completed, vulnerabilities: { status: 'pending' } } }])
  assert.equal(pending.vulnerabilities.state, 'pending')
  const failed = securityOverview([{ id: 1, lastCompletedScan: { ...completed, vulnerabilities: { status: 'failed' } } }])
  assert.equal(failed.vulnerabilities.state, 'unavailable')
  const none = securityOverview([])
  assert.equal(none.vulnerabilities.state, 'none')
  assert.equal(none.components, null)
  assert.equal(none.risk.top, null)
})
