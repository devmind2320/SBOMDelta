// Theme preference helpers with no Vue or browser dependency, so they can be
// tested with Node's own runner. index.html applies the same rule before the
// app renders, so the first paint is already in the right theme.

export const THEME_KEY = 'sbomdelta:theme'
export const THEMES = ['light', 'dark']

function isTheme(value) {
  return value === 'light' || value === 'dark'
}

/**
 * The theme to show: an explicitly saved choice wins, and without one the
 * operating system's preference decides. Anything else saved (including the
 * old "system" value) counts as no choice.
 */
export function resolveTheme(stored, prefersDark) {
  if (isTheme(stored)) return stored
  return prefersDark ? 'dark' : 'light'
}

/** The saved choice, or null. Blocked storage reads as no choice. */
export function readStoredTheme(storage) {
  try {
    const value = storage?.getItem(THEME_KEY) ?? null
    return isTheme(value) ? value : null
  } catch {
    return null
  }
}

/** Saves a choice and reports whether it stuck (private windows may refuse). */
export function storeTheme(storage, theme) {
  if (!isTheme(theme)) return false
  try {
    storage?.setItem(THEME_KEY, theme)
    return Boolean(storage)
  } catch {
    return false
  }
}

export function nextTheme(current) {
  return current === 'dark' ? 'light' : 'dark'
}
