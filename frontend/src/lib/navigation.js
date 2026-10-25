// Navigation helpers with no Vue or browser dependency, so they can be tested
// with Node's own runner.

/** Where Back goes when there is no useful in-app page to return to. */
export const BACK_FALLBACK = { name: 'dashboard', path: '/' }

/**
 * What the header's Back button should do. Vue Router records the previous
 * in-app path in history.state.back; it is null on a fresh tab, after a full
 * page load (such as returning from GitHub's sign-in) or on a link opened
 * directly. Going back is only useful to another app page: never to the
 * sign-in page (it would bounce straight back, a loop) or to this same page.
 *
 * Returns { kind: 'history' } to call router.back(), { kind: 'fallback', to }
 * to navigate to the dashboard, or { kind: 'none' } when already there.
 */
export function backDecision(historyState, currentPath) {
  const back = historyState?.back
  const usable =
    typeof back === 'string' &&
    back.startsWith('/') &&
    !back.startsWith('//') &&
    back !== currentPath &&
    !isSignInPath(back)
  if (usable) return { kind: 'history' }
  if (samePath(currentPath, BACK_FALLBACK.path)) return { kind: 'none' }
  return { kind: 'fallback', to: { name: BACK_FALLBACK.name } }
}

function pathname(path) {
  return String(path ?? '').split(/[?#]/, 1)[0]
}

function samePath(a, b) {
  return pathname(a) === pathname(b)
}

function isSignInPath(path) {
  const name = pathname(path).toLowerCase()
  return name === '/login' || name.startsWith('/login/')
}
