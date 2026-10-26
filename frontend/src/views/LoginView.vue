<script setup>
import { computed, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useSession } from '../composables/useSession.js'
import AppIcon from '../components/AppIcon.vue'
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
  <div class="flex justify-center py-10 sm:py-16">
    <div class="card w-full max-w-md px-6 py-8 text-center sm:px-8">
      <span
        class="mx-auto flex size-11 items-center justify-center rounded-xl bg-accent-solid text-[var(--on-accent)] shadow-[var(--shadow-md)]"
      >
        <AppIcon name="shield" :size="22" />
      </span>
      <h1 class="mt-5 mb-0 text-xl font-semibold tracking-tight text-ink">Sign in to SBOMDelta</h1>
      <p class="mx-auto mt-2 mb-0 max-w-[40ch] text-sm leading-relaxed text-ink-muted">
        Software supply-chain security for your repositories. Sign in with your GitHub account; you see and scan
        only the repositories GitHub lets your account reach through SBOMDelta’s GitHub App.
      </p>

      <div class="mt-6 flex flex-col gap-3 text-left">
        <p v-if="error && !signedOut" role="alert" class="banner banner-danger m-0">
          <AppIcon name="alert-circle" :size="15" class="mt-0.5" />
          <span>{{ error }}</span>
        </p>
        <p v-if="notice" role="status" class="banner banner-success m-0">
          <AppIcon name="check-circle" :size="15" class="mt-0.5" />
          <span>{{ notice }}</span>
        </p>
        <template v-if="disallowed && !signedOut">
          <p class="m-0 text-sm leading-relaxed text-ink-muted">
            To use a different GitHub account, sign out here, then sign out of GitHub (or switch accounts there)
            before signing in again.
          </p>
          <button type="button" class="btn btn-secondary w-full" @click="endDisallowedSession">
            <AppIcon name="log-out" :size="14" />
            Sign out of this dashboard
          </button>
          <p v-if="signOutError" role="alert" class="banner banner-danger m-0">{{ signOutError }}</p>
        </template>
      </div>

      <!-- A full navigation, not a fetch: GitHub's consent page must load in
           the window, and the callback sets the session cookie. -->
      <a :href="LOGIN_PATH" class="btn btn-primary mt-6 min-h-10 w-full text-sm" @click="startSignIn">
        <AppIcon name="github" :size="16" />
        Sign in with GitHub
      </a>
      <p class="mt-4 mb-0 text-xs text-ink-muted">You will be redirected to GitHub to authorize this dashboard.</p>
    </div>
  </div>
</template>
