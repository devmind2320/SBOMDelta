import assert from 'node:assert/strict'
import { test } from 'node:test'

import { backDecision } from './navigation.js'

test('Back returns to the previous in-app page when there is one', () => {
  assert.deepEqual(backDecision({ back: '/repos/4' }, '/scans/9'), { kind: 'history' })
  assert.deepEqual(backDecision({ back: '/' }, '/impact'), { kind: 'history' })
})

test('Back falls back to the dashboard on a fresh tab or a direct link', () => {
  const fallback = { kind: 'fallback', to: { name: 'dashboard' } }
  assert.deepEqual(backDecision(null, '/scans/9'), fallback)
  assert.deepEqual(backDecision({}, '/scans/9'), fallback)
  assert.deepEqual(backDecision({ back: null }, '/repos/4'), fallback)
})

test('Back never returns to the sign-in page or loops on the same page', () => {
  const fallback = { kind: 'fallback', to: { name: 'dashboard' } }
  assert.deepEqual(backDecision({ back: '/login?signed_out=1' }, '/impact'), fallback)
  assert.deepEqual(backDecision({ back: '/impact' }, '/impact'), fallback)
  // Not an app path: an external or protocol-relative value is ignored.
  assert.deepEqual(backDecision({ back: '//evil.example/' }, '/impact'), fallback)
  assert.deepEqual(backDecision({ back: 'https://evil.example/' }, '/impact'), fallback)
})

test('on the dashboard with nowhere to go back to, Back does nothing', () => {
  assert.deepEqual(backDecision(null, '/'), { kind: 'none' })
  assert.deepEqual(backDecision({ back: '/login' }, '/?x=1'), { kind: 'none' })
})
