import assert from 'node:assert/strict'
import { test } from 'node:test'

import { THEME_KEY, nextTheme, readStoredTheme, resolveTheme, storeTheme } from './theme.js'

function memoryStorage(initial = {}) {
  const values = new Map(Object.entries(initial))
  return {
    getItem: (key) => (values.has(key) ? values.get(key) : null),
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
  }
}

const blocked = {
  getItem() {
    throw new Error('SecurityError')
  },
  setItem() {
    throw new Error('QuotaExceededError')
  },
}

test('a saved choice wins over the operating system', () => {
  assert.equal(resolveTheme('light', true), 'light')
  assert.equal(resolveTheme('dark', false), 'dark')
})

test('without a saved choice the operating system decides', () => {
  assert.equal(resolveTheme(null, true), 'dark')
  assert.equal(resolveTheme(null, false), 'light')
  // The old three-way toggle saved "system"; it means no explicit choice.
  assert.equal(resolveTheme('system', true), 'dark')
  assert.equal(resolveTheme('purple', false), 'light')
})

test('the choice survives a reload through storage', () => {
  const storage = memoryStorage()
  assert.equal(readStoredTheme(storage), null)
  assert.equal(storeTheme(storage, 'dark'), true)
  assert.equal(storage.getItem(THEME_KEY), 'dark')
  // A "reload": a fresh read of the same storage.
  assert.equal(resolveTheme(readStoredTheme(storage), false), 'dark')
  storeTheme(storage, 'light')
  assert.equal(resolveTheme(readStoredTheme(storage), true), 'light')
})

test('blocked storage never throws and falls back to the OS', () => {
  assert.equal(readStoredTheme(blocked), null)
  assert.equal(storeTheme(blocked, 'dark'), false)
  assert.equal(storeTheme(null, 'dark'), false)
  assert.equal(readStoredTheme(memoryStorage({ [THEME_KEY]: 'system' })), null)
  assert.equal(storeTheme(memoryStorage(), 'neon'), false)
})

test('the toggle alternates between the two themes', () => {
  assert.equal(nextTheme('light'), 'dark')
  assert.equal(nextTheme('dark'), 'light')
})
