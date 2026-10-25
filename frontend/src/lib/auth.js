// Sign-in helpers with no Vue or browser dependency, so they can be tested
// with Node's own runner.

/** Where the browser goes to start signing in with GitHub. */
export const LOGIN_PATH = '/api/auth/github/login'

// The server redirects back to /login?error=<code>, always one of these. An
// unknown code gets a generic message rather than being echoed onto the page.
const LOGIN_ERRORS = {
  denied: 'Sign-in was cancelled on GitHub.',
  state: 'That sign-in link expired or did not start here. Please try again.',
  expired: 'The sign-in took too long or was already used. Please try again.',
  github: 'GitHub could not complete the sign-in. Please try again.',
  misconfigured:
    'Sign-in is not set up correctly for this dashboard (GitHub App credentials or callback URL). Please tell the administrator.',
  suspended: "This dashboard's GitHub App is suspended. Please tell the administrator.",
  unverified_email: 'GitHub requires a verified email address on your account before you can sign in.',
  not_allowed: 'This GitHub account is not allowed to use this dashboard.',
  server: 'Something went wrong on our side. Please try again.',
}

export function loginErrorMessage(code) {
  if (!code) return ''
  // Own keys only: ?error=toString must not find Object.prototype.toString.
  return Object.hasOwn(LOGIN_ERRORS, code) ? LOGIN_ERRORS[code] : 'Sign-in failed. Please try again.'
}

export const SIGNED_OUT_MESSAGE = 'You have signed out.'

/**
 * What a failed sign-out tells the person. The session is still valid
 * whenever this is shown, so every message says so; the server's own text is
 * never shown.
 */
export function signOutErrorMessage(error) {
  switch (error?.status) {
    case 0:
      return 'Could not reach the server, so you are still signed in. Please try again.'
    case 403:
      return 'The server refused the sign-out request, so you are still signed in. Reload the page and try again.'
    default:
      return 'Sign-out failed, so you are still signed in. Please try again.'
  }
}

/**
 * How an /api/me failure reads: 401 is nobody signed in, 403 is a session for
 * an account the dashboard does not allow. Anything else is not an answer
 * about the session (the API is down, say) and returns null.
 */
export function sessionStateFor(status) {
  if (status === 401) return 'signed_out'
  if (status === 403) return 'not_allowed'
  return null
}

/**
 * A path inside the dashboard that is safe to return to after signing in, or
 * null. Only same-app paths qualify: no scheme or host (so no open redirect),
 * no protocol-relative or backslash tricks, nothing under /api (not a page),
 * and not the sign-in page itself (which would loop).
 */
export function safeReturnPath(path) {
  if (typeof path !== 'string' || path.length === 0 || path.length > 2048) return null
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('\\')) return null
  // Control characters and whitespace are never part of a path we produce.
  if (/[\u0000- \u007f]/.test(path)) return null
  const pathname = path.split(/[?#]/, 1)[0].toLowerCase()
  if (pathname === '/login' || pathname.startsWith('/login/')) return null
  if (pathname === '/api' || pathname.startsWith('/api/')) return null
  return path
}

/**
 * The router guard's decision for a navigation, given what is known about
 * the session. It returns true to proceed or a location to go to instead, and
 * every location it returns is one it would let through: a sign-in page for
 * someone signed out, or an app page for someone signed in. So a redirect
 * never leads to another redirect.
 */
export function routeDecision(to, { user, disallowed }) {
  if (to.meta?.public) {
    if (user && to.name === 'login') {
      return { path: safeReturnPath(to.query?.redirect) ?? '/' }
    }
    return true
  }
  if (user) return true
  const query = {}
  if (disallowed) query.error = 'not_allowed'
  const back = safeReturnPath(to.fullPath)
  if (back && back !== '/') query.redirect = back
  return { name: 'login', query }
}

// GitHub's consent page and the callback are full page loads, so where to go
// back to after signing in is kept in sessionStorage across them: this tab
// only, and gone when it closes.
const RETURN_KEY = 'sbomdelta:return-to'

export function rememberReturnTo(storage, path) {
  try {
    const safe = safeReturnPath(path)
    if (safe && safe !== '/') storage?.setItem(RETURN_KEY, safe)
    else storage?.removeItem(RETURN_KEY)
  } catch {
    /* storage unavailable: signing in still works, it just lands on / */
  }
}

/** Returns the remembered path once, then forgets it. */
export function takeReturnTo(storage) {
  try {
    const path = storage?.getItem(RETURN_KEY) ?? null
    if (path !== null) storage.removeItem(RETURN_KEY)
    return safeReturnPath(path)
  } catch {
    return null
  }
}
