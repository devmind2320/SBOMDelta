import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  LOGIN_PATH,
  loginErrorMessage,
  rememberReturnTo,
  routeDecision,
  safeReturnPath,
  sessionStateFor,
  signOutErrorMessage,
  takeReturnTo,
} from './auth.js'

test('loginErrorMessage explains every code the server sends', () => {
  const codes = [
    'denied',
    'state',
    'expired',
    'github',
    'misconfigured',
    'suspended',
    'unverified_email',
    'not_allowed',
    'server',
  ]
  for (const code of codes) {
    assert.ok(loginErrorMessage(code).length > 0, code)
    assert.notEqual(loginErrorMessage(code), loginErrorMessage('unknown-code'), code)
  }
  assert.equal(new Set(codes.map(loginErrorMessage)).size, codes.length, 'each code has its own message')
  assert.match(loginErrorMessage('not_allowed'), /not allowed/)
  assert.match(loginErrorMessage('misconfigured'), /administrator/)
})

test('loginErrorMessage never echoes an unknown code', () => {
  const crafted = '<img src=x onerror=alert(1)>'
  assert.equal(loginErrorMessage(crafted), 'Sign-in failed. Please try again.')
  assert.equal(loginErrorMessage('access_denied'), 'Sign-in failed. Please try again.')
  assert.equal(loginErrorMessage('toString'), 'Sign-in failed. Please try again.')
  assert.equal(loginErrorMessage(''), '')
  assert.equal(loginErrorMessage(undefined), '')
})

test('sign-in starts on the API under /api, which the proxies forward', () => {
  assert.equal(LOGIN_PATH, '/api/auth/github/login')
})

test('a failed sign-out always says the person is still signed in', () => {
  for (const status of [0, 403, 500, 502, undefined]) {
    const message = signOutErrorMessage(status === undefined ? new Error('x') : { status, message: 'server text' })
    assert.match(message, /still signed in/, String(status))
    assert.doesNotMatch(message, /server text/)
  }
})

test('sessionStateFor reads 401 as signed out and 403 as not allowed', () => {
  assert.equal(sessionStateFor(401), 'signed_out')
  assert.equal(sessionStateFor(403), 'not_allowed')
  for (const status of [0, 404, 500, 502]) assert.equal(sessionStateFor(status), null)
})

test('safeReturnPath keeps only paths inside the dashboard', () => {
  for (const ok of ['/', '/repos/3', '/scans/7?tab=drift', '/pulls/1#top']) {
    assert.equal(safeReturnPath(ok), ok)
  }
  for (const bad of [
    'https://evil.example/',
    '//evil.example/',
    '/\\evil.example',
    '\\\\evil.example',
    'javascript:alert(1)',
    'repos/3',
    '/login',
    '/LOGIN?redirect=/x',
    '/login/',
    '/api/scans/1/sbom',
    '/API/repos',
    '/repos/1\n',
    '/ repos',
    '',
    null,
    undefined,
    ['/repos/1'],
    '/' + 'a'.repeat(3000),
  ]) {
    assert.equal(safeReturnPath(bad), null, JSON.stringify(bad))
  }
})

// A tiny stand-in for the router's table: what routeDecision needs of a route.
function route(path) {
  const [pathname, search = ''] = path.split('?')
  const query = Object.fromEntries(new URLSearchParams(search))
  if (pathname === '/login') return { name: 'login', meta: { public: true }, fullPath: path, query }
  return { name: 'page', meta: {}, fullPath: path, query }
}
function toPath(location) {
  if (location.path) return location.path
  const search = new URLSearchParams(location.query).toString()
  return '/login' + (search ? `?${search}` : '')
}

test('routeDecision sends signed-out visitors to sign in, keeping where they were going', () => {
  assert.deepEqual(routeDecision(route('/scans/7?tab=drift'), { user: null }), {
    name: 'login',
    query: { redirect: '/scans/7?tab=drift' },
  })
  assert.deepEqual(routeDecision(route('/'), { user: null }), { name: 'login', query: {} })
  assert.equal(routeDecision(route('/login'), { user: null }), true)
})

test('routeDecision shows a disallowed account the sign-in page with the reason', () => {
  assert.deepEqual(routeDecision(route('/repos/3'), { user: null, disallowed: true }), {
    name: 'login',
    query: { error: 'not_allowed', redirect: '/repos/3' },
  })
  // ...and lets it stay there, so it can sign out or switch accounts.
  assert.equal(routeDecision(route('/login?error=not_allowed'), { user: null, disallowed: true }), true)
})

test('routeDecision returns a signed-in visitor from the sign-in page to a safe page', () => {
  const user = { login: 'devmind2320' }
  assert.deepEqual(routeDecision(route('/login?redirect=/repos/3'), { user }), { path: '/repos/3' })
  assert.deepEqual(routeDecision(route('/login?redirect=//evil.example'), { user }), { path: '/' })
  assert.deepEqual(routeDecision(route('/login?redirect=/login'), { user }), { path: '/' })
  assert.equal(routeDecision(route('/repos/3'), { user }), true)
})

test('routeDecision never redirects twice, in any session state', () => {
  const states = [
    { user: null, disallowed: false },
    { user: null, disallowed: true },
    { user: { login: 'devmind2320' }, disallowed: false },
  ]
  const starts = ['/', '/repos/3', '/scans/7?tab=drift', '/login', '/login?redirect=/repos/3',
    '/login?redirect=/login', '/login?redirect=https://evil.example', '/login?error=not_allowed']
  for (const state of states) {
    for (const start of starts) {
      let location = route(start)
      let hops = 0
      for (let decision = routeDecision(location, state); decision !== true; decision = routeDecision(location, state)) {
        location = route(toPath(decision))
        hops += 1
        assert.ok(hops <= 1, `${start} (${JSON.stringify(state)}) redirected again to ${location.fullPath}`)
      }
    }
  }
})

function memoryStorage() {
  const items = new Map()
  return {
    getItem: (key) => (items.has(key) ? items.get(key) : null),
    setItem: (key, value) => items.set(key, String(value)),
    removeItem: (key) => items.delete(key),
    items,
  }
}

test('the return path survives the trip to GitHub once', () => {
  const storage = memoryStorage()
  rememberReturnTo(storage, '/scans/7?tab=drift')
  assert.equal(takeReturnTo(storage), '/scans/7?tab=drift')
  assert.equal(takeReturnTo(storage), null, 'used once')
})

test('only safe return paths are remembered or used', () => {
  const storage = memoryStorage()
  rememberReturnTo(storage, 'https://evil.example/')
  assert.equal(storage.items.size, 0)
  rememberReturnTo(storage, '/repos/3')
  rememberReturnTo(storage, '/')
  assert.equal(storage.items.size, 0, 'a plain sign-in clears an older return path')
  storage.setItem('sbomdelta:return-to', '//evil.example')
  assert.equal(takeReturnTo(storage), null, 'a tampered value is refused')
  assert.equal(storage.items.size, 0)
})

test('unavailable storage never breaks signing in', () => {
  const throwing = {
    getItem() {
      throw new Error('denied')
    },
    setItem() {
      throw new Error('denied')
    },
    removeItem() {
      throw new Error('denied')
    },
  }
  assert.doesNotThrow(() => rememberReturnTo(throwing, '/repos/3'))
  assert.equal(takeReturnTo(throwing), null)
  assert.equal(takeReturnTo(undefined), null)
})
