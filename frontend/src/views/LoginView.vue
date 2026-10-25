<script setup>
import { computed, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useSession } from '../composables/useSession.js'
import {
  LOGIN_PATH,
  SIGNED_OUT_MESSAGE,
  loginErrorMessage,
  rememberReturnTo,
  signOutErrorMessage,
} from '../lib/auth.js'

const route = useRoute()
const { disallowed, signOut } = useSession()

const error = computed(() => loginErrorMessage(route.query.error))
const signedOut = ref(false)
const signOutError = ref('')
const notice = computed(() => (signedOut.value || route.query.signed_out === '1' ? SIGNED_OUT_MESSAGE : ''))

// GitHub's consent page and the callback are full page loads; keep where the
// person was going so the router can continue there once they are back.
function startSignIn() {
  let storage = null
  try {
    storage = window.sessionStorage
  } catch {
    /* storage unavailable: they land on / after signing in */
  }
  rememberReturnTo(storage, route.query.redirect)
}

// A disallowed account still has a dashboard session. Ending it lets the
// person try another GitHub account instead of being stuck on this one.
async function endDisallowedSession() {
  signOutError.value = ''
  try {
    await signOut()
    signedOut.value = true
  } catch (failure) {
    signOutError.value = signOutErrorMessage(failure)
  }
}
</script>

<template>
  <div class="flex flex-col items-center gap-4 py-20 text-center">
    <h1 class="m-0 text-xl font-semibold text-ink">Sign in to SBOMDelta</h1>
    <p class="m-0 max-w-md text-sm text-ink-muted">
      Dependency data for private repositories is shown only to accounts this dashboard allows.
    </p>
    <p
      v-if="error && !signedOut"
      role="alert"
      class="m-0 max-w-md rounded-md border border-hairline px-3 py-2 text-sm text-ink-secondary"
    >
      {{ error }}
    </p>
    <p v-if="notice" role="status" class="m-0 max-w-md text-sm text-ink-secondary">
      {{ notice }}
    </p>
    <template v-if="disallowed && !signedOut">
      <p class="m-0 max-w-md text-sm text-ink-muted">
        To use a different GitHub account, sign out here, then sign out of GitHub (or switch accounts
        there) before signing in again.
      </p>
      <button
        type="button"
        class="cursor-pointer rounded-md border border-hairline bg-surface-raised px-4 py-2 text-sm text-ink-secondary"
        @click="endDisallowedSession"
      >
        Sign out of this dashboard
      </button>
      <p v-if="signOutError" role="alert" class="m-0 max-w-md text-sm text-ink-secondary">
        {{ signOutError }}
      </p>
    </template>
    <!-- A full navigation, not a fetch: GitHub's consent page must load in
         the window, and the callback sets the session cookie. -->
    <a
      :href="LOGIN_PATH"
      class="rounded-md border border-hairline bg-surface-raised px-4 py-2 text-sm font-medium text-ink no-underline"
      @click="startSignIn"
    >
      Sign in with GitHub
    </a>
  </div>
</template>
