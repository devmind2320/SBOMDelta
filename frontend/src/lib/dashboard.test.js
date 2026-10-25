import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  changesLabel,
  formatDateTimeWithZone,
  isScanActive,
  listingErrorMessage,
  pageRange,
  scanAvailability,
  scanOutcomeMessage,
  scanState,
} from './dashboard.js'

test('scanState names every state the API returns, and never-scanned', () => {
  assert.equal(scanState(null).label, 'Never scanned')
  assert.equal(scanState(undefined).key, 'never')
  assert.equal(scanState({ status: 'pending' }).label, 'Queued')
  assert.equal(scanState({ status: 'running' }).label, 'Scanning')
  assert.equal(scanState({ status: 'completed' }).label, 'Completed')
  assert.equal(scanState({ status: 'failed' }).label, 'Failed')
  assert.equal(scanState({ status: 'weird' }).key, 'unknown')
})

test('only waiting and running scans are active', () => {
  assert.equal(isScanActive({ status: 'pending' }), true)
  assert.equal(isScanActive({ status: 'running' }), true)
  for (const status of ['completed', 'failed']) assert.equal(isScanActive({ status }), false)
  assert.equal(isScanActive(null), false)
})

test('dates carry their time zone', () => {
  const text = formatDateTimeWithZone('2026-10-25T04:12:00Z', 'en-US', 'UTC')
  assert.match(text, /Oct 25, 2026/)
  assert.match(text, /UTC/)
  assert.equal(formatDateTimeWithZone(null), '—')
  assert.equal(formatDateTimeWithZone('not a date'), '—')
})

test('changesLabel separates an initial inventory from a delta', () => {
  assert.equal(changesLabel({ lastCompletedScan: null }), '—')
  assert.equal(changesLabel({ lastCompletedScan: { id: 1 }, baseline: true, added: 0 }), 'Initial inventory')
  assert.equal(changesLabel({ lastCompletedScan: { id: 2 }, baseline: false, added: 0, updated: 0, removed: 0 }), 'No changes')
  assert.equal(
    changesLabel({ lastCompletedScan: { id: 2 }, baseline: false, added: 3, updated: 1, removed: 2 }),
    '+3 added · 1 updated · −2 removed',
  )
})

test('a repository can be scanned only once stored and reachable', () => {
  assert.equal(scanAvailability({ repositoryId: 4, access: 'active' }).ok, true)
  const syncing = scanAvailability({ repositoryId: null })
  assert.equal(syncing.ok, false)
  assert.match(syncing.reason, /syncing/)
  const revoked = scanAvailability({ repositoryId: 4, access: 'revoked' })
  assert.equal(revoked.ok, false)
  assert.match(revoked.reason, /no longer has access/)
})

test('every scan outcome has its own message', () => {
  const outcomes = ['queued', 'in_progress', 'up_to_date', 'retried']
  const messages = outcomes.map(scanOutcomeMessage)
  assert.equal(new Set(messages).size, outcomes.length)
  assert.match(scanOutcomeMessage('up_to_date'), /already scanned/)
})

test('listing errors are explained without echoing unknown codes', () => {
  for (const code of ['unauthorized', 'rate_limited', 'github', 'too_many', 'auth_disabled']) {
    assert.ok(listingErrorMessage(code).length > 0)
    assert.notEqual(listingErrorMessage(code), listingErrorMessage('other'))
  }
  assert.equal(listingErrorMessage('<script>'), 'Your repositories could not be loaded.')
  assert.equal(listingErrorMessage('toString'), 'Your repositories could not be loaded.')
  assert.equal(listingErrorMessage(''), '')
})

test('pageRange describes the visible slice', () => {
  assert.equal(pageRange(1, 30, 125, 30), '1–30 of 125')
  assert.equal(pageRange(5, 30, 125, 5), '121–125 of 125')
  assert.equal(pageRange(6, 30, 125, 0), '0 of 125')
  assert.equal(pageRange(1, 30, 0, 0), '')
})
