// Run with `npm test`. Uses Node's built-in runner so the dashboard needs no
// test dependencies.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { scanTriggerLabel } from './format.js'

test('scanTriggerLabel names every trigger the API can return', () => {
  assert.equal(scanTriggerLabel('push'), 'push')
  assert.equal(scanTriggerLabel('pull_request'), 'pull request')
  assert.equal(scanTriggerLabel('manual'), 'manual')
  assert.equal(scanTriggerLabel('backfill'), 'backfill')
  assert.equal(scanTriggerLabel('initial'), 'initial scan')
})

test('scanTriggerLabel falls back to the raw trigger', () => {
  assert.equal(scanTriggerLabel('some_new_trigger'), 'some new trigger')
  assert.equal(scanTriggerLabel(undefined), '')
  assert.equal(scanTriggerLabel(null), '')
})
