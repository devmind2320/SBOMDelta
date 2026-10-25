import { ref } from 'vue'
import { nextTheme, readStoredTheme, resolveTheme, storeTheme } from '../lib/theme.js'

// One theme for the whole app. index.html has already stamped data-theme
// before the first paint; this picks it up and keeps it in step.
const theme = ref('light')
let explicit = false
let started = false

function storage() {
  try {
    return window.localStorage
  } catch {
    return null
  }
}

function apply(next) {
  theme.value = next
  document.documentElement.setAttribute('data-theme', next)
}

function start() {
  if (started || typeof window === 'undefined') return
  started = true
  const media = window.matchMedia?.('(prefers-color-scheme: dark)')
  const saved = readStoredTheme(storage())
  explicit = saved !== null
  apply(resolveTheme(saved, media?.matches ?? false))
  // Without a saved choice the theme follows the OS, live.
  media?.addEventListener?.('change', (event) => {
    if (!explicit) apply(event.matches ? 'dark' : 'light')
  })
}

/** Switches theme now and remembers the choice for later visits. */
function toggle() {
  const next = nextTheme(theme.value)
  explicit = true
  apply(next)
  storeTheme(storage(), next)
}

export function useTheme() {
  start()
  return { theme, toggle }
}
