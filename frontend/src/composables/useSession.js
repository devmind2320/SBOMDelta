import { ref } from 'vue'
import { api } from '../api/client.js'
import { sessionStateFor } from '../lib/auth.js'

// One session for the whole app: the router guard, the header and the login
// page all read the same state.
const user = ref(null)
// The browser has a session, but for an account the dashboard does not allow
// (removed from the allowlist since signing in). It can still sign out.
const disallowed = ref(false)
let pending = null

/**
 * Loads the signed-in user once; later calls reuse the answer until reset()
 * or signOut(). A 401 means nobody is signed in and a 403 a disallowed
 * account; both resolve to null. Other failures (the API is down) reject.
 */
async function loadSession() {
  if (user.value) return user.value
  pending ??= api
    .me()
    .then((me) => {
      user.value = me
      disallowed.value = false
      return me
    })
    .catch((error) => {
      const state = sessionStateFor(error?.status)
      if (!state) throw error
      disallowed.value = state === 'not_allowed'
      return null
    })
    .finally(() => {
      pending = null
    })
  return pending
}

/** Forgets the user, e.g. when the API reports the session is no longer usable. */
function reset(reason) {
  user.value = null
  disallowed.value = reason === 'not_allowed'
}

/**
 * Ends the session on the server. Only once that succeeds is the user
 * forgotten; a failure rejects and leaves everything as it was, because the
 * session is still valid.
 */
async function signOut() {
  await api.logout()
  reset()
}

export function useSession() {
  return { user, disallowed, loadSession, reset, signOut }
}
