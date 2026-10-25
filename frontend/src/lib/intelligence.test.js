import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  driftLabel,
  formatScore,
  githubUrl,
  pullRequestVerdict,
  riskState,
  scanRefLabel,
  severityCounts,
  trackAvailability,
  vulnerabilityChangeLabel,
  vulnerabilityState,
} from './intelligence.js'

test('githubUrl encodes owner and name, and needs both', () => {
  assert.equal(githubUrl('acme', 'api'), 'https://github.com/acme/api')
  assert.equal(githubUrl('a b', 'c/d'), 'https://github.com/a%20b/c%2Fd')
  assert.equal(githubUrl('', 'api'), null)
})

test('an unanalyzed scan never reads as clean', () => {
  assert.equal(vulnerabilityState({ status: 'pending' }).key, 'pending')
  const failed = vulnerabilityState({ status: 'failed', error: 'OSV returned HTTP 503' })
  assert.equal(failed.key, 'failed')
  assert.equal(failed.error, 'OSV returned HTTP 503')
  assert.notEqual(failed.label, 'No known vulnerabilities')
  assert.equal(vulnerabilityState(null).key, 'none')
  assert.deepEqual(severityCounts({ status: 'pending', critical: 3 }), [])
})

test('an analyzed scan reports counts, fixes and coverage', () => {
  const clean = vulnerabilityState({ status: 'analyzed', total: 0, componentsSkipped: 0 })
  assert.equal(clean.label, 'No known vulnerabilities')
  assert.equal(clean.detail, '')

  const state = vulnerabilityState({
    status: 'analyzed', total: 3, critical: 1, high: 0, medium: 1, low: 0, unrated: 1, fixable: 2, componentsSkipped: 4,
  })
  assert.equal(state.label, '3 known vulnerabilities')
  assert.match(state.detail, /1 critical, 1 medium, 1 unrated/)
  assert.match(state.detail, /2 fixable/)
  assert.match(state.detail, /4 component\(s\) could not be checked/)
  assert.deepEqual(
    severityCounts({ status: 'analyzed', critical: 1, high: 2, medium: 0, low: 0, unrated: 0 }).map((s) => s.key),
    ['critical', 'high'],
  )
})

test('vulnerability changes need a comparable base', () => {
  assert.equal(vulnerabilityChangeLabel({ status: 'analyzed', introduced: 2, resolved: 1 }), '+2 new · 1 resolved')
  assert.equal(vulnerabilityChangeLabel({ status: 'analyzed', introduced: 0, resolved: 0 }), 'No vulnerability changes')
  assert.equal(vulnerabilityChangeLabel({ status: 'analyzed' }), '')
  assert.equal(vulnerabilityChangeLabel({ status: 'pending', introduced: 1, resolved: 0 }), '')
})

test('risk is shown only when scored, never as a stand-in zero', () => {
  assert.deepEqual(riskState(null).scored, false)
  assert.equal(riskState({ score: null, level: '' }).label, 'Not scored')
  const zero = riskState({ score: 0, level: 'none' })
  assert.equal(zero.scored, true)
  assert.equal(zero.score, '0')
  assert.equal(zero.label, 'None')
  const high = riskState({ score: 27.5, level: 'high', delta: -3 })
  assert.equal(high.score, '27.5')
  assert.equal(high.tone, 'serious')
  assert.equal(high.delta, '-3 vs previous')
  assert.equal(formatScore(undefined), '—')
})

test('only stored repositories can be tracked', () => {
  assert.equal(trackAvailability({ repositoryId: 4 }).ok, true)
  assert.equal(trackAvailability({}).ok, false)
  assert.match(trackAvailability({}).reason, /syncing/)
})

test('scan ref and drift labels', () => {
  assert.equal(scanRefLabel({ pullRequestNumber: 12, ref: 'refs/pull/12/head' }), 'PR #12')
  assert.equal(scanRefLabel({ ref: 'refs/heads/release', defaultBranch: 'main' }), 'release')
  assert.equal(scanRefLabel({ ref: '', defaultBranch: 'main' }), 'main')
  assert.equal(driftLabel({ status: 'completed', baseline: true }), 'Initial inventory')
  assert.equal(driftLabel({ status: 'completed', added: 1, updated: 2, removed: 3 }), '+1 added · 2 changed · −3 removed')
  assert.equal(driftLabel({ status: 'completed' }), 'No changes')
  assert.equal(driftLabel({ status: 'failed' }), '—')
})

test('pull request verdict mirrors the GitHub check policy', () => {
  const base = { scanId: 9, scanStatus: 'completed', hasDrift: true }
  const critical = { severity: 'CRITICAL' }
  const low = { severity: 'LOW' }
  assert.equal(pullRequestVerdict({ ...base, scanId: null }).label, 'Not scanned')
  assert.equal(pullRequestVerdict({ ...base, scanStatus: 'failed' }).tone, 'critical')
  assert.equal(pullRequestVerdict({ ...base, scanStatus: 'running' }).label, 'In progress')
  assert.equal(
    pullRequestVerdict({ ...base, changes: { available: true, comparison: { introduced: [critical, low] } } }).tone,
    'critical',
  )
  assert.equal(
    pullRequestVerdict({ ...base, changes: { available: true, comparison: { introduced: [low] } } }).tone,
    'warning',
  )
  const unavailable = pullRequestVerdict({ ...base, changes: { available: false, reason: 'not checked yet' } })
  assert.equal(unavailable.tone, 'warning')
  assert.match(unavailable.note, /not checked yet/)
  assert.equal(
    pullRequestVerdict({ ...base, hasDrift: false, changes: { available: true, comparison: { introduced: [] } } }).tone,
    'good',
  )
})
