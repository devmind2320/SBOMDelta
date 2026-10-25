<script setup>
import { onMounted, ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
import { useSession } from '../composables/useSession.js'
import { signOutErrorMessage } from '../lib/auth.js'

const { user, signOut } = useSession()
const router = useRouter()
const signOutError = ref('')

// Only a sign-out the server confirmed leaves the page. A failed one stays
// here and says so: the session is still valid.
async function onSignOut() {
  signOutError.value = ''
  try {
    await signOut()
  } catch (error) {
    signOutError.value = signOutErrorMessage(error)
    return
  }
  router.push({ name: 'login', query: { signed_out: '1' } })
}

// "system" leaves only prefers-color-scheme in play; the explicit modes stamp
// data-theme on the root element, which the token blocks in style.css honour
// in both directions.
const THEMES = ['system', 'light', 'dark']
const theme = ref('system')

function apply(next) {
  theme.value = next
  const root = document.documentElement
  if (next === 'system') root.removeAttribute('data-theme')
  else root.setAttribute('data-theme', next)
  // Private windows and blocked site data make storage throw, and a theme
  // preference is not worth failing a render over.
  try {
    localStorage.setItem('sbomdelta:theme', next)
  } catch {
    /* preference simply will not persist */
  }
}

function cycle() {
  apply(THEMES[(THEMES.indexOf(theme.value) + 1) % THEMES.length])
}

onMounted(() => {
  try {
    const stored = localStorage.getItem('sbomdelta:theme')
    if (THEMES.includes(stored)) apply(stored)
  } catch {
    /* fall back to following the OS */
  }
})
</script>

<template>
  <header class="border-b border-hairline bg-surface">
    <div class="mx-auto flex w-full max-w-[1200px] flex-wrap items-center gap-4 px-4 py-3 sm:px-6">
      <RouterLink
        :to="{ name: 'repositories' }"
        class="flex items-center gap-2 text-ink no-underline"
      >
        <!-- Two offset nodes: the mark reads as a before/after comparison,
             which is what the product does. -->
        <svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true">
          <circle cx="6" cy="6" r="3.25" fill="var(--series-removed)" />
          <circle cx="14" cy="14" r="3.25" fill="var(--series-added)" />
          <path
            d="M6 9.5v3.5a1 1 0 0 0 1 1h3.5"
            fill="none"
            stroke="var(--axis)"
            stroke-width="1.5"
            stroke-linecap="round"
          />
        </svg>
        <span class="text-[15px] font-semibold tracking-tight">SBOMDelta</span>
      </RouterLink>

      <span class="hidden text-xs text-ink-muted sm:inline">
        Dependency drift across your repositories
      </span>

      <span v-if="user" class="ml-auto text-xs text-ink-muted">{{ user.login }}</span>
      <button
        v-if="user && !user.authDisabled"
        type="button"
        class="cursor-pointer rounded-md border border-hairline bg-surface-raised px-2.5 py-1.5 text-xs text-ink-secondary"
        @click="onSignOut"
      >
        Sign out
      </button>
      <span v-if="signOutError" role="alert" class="basis-full text-right text-xs text-ink-secondary">
        {{ signOutError }}
      </span>
      <button
        type="button"
        class="cursor-pointer rounded-md border border-hairline bg-surface-raised px-2.5 py-1.5 text-xs text-ink-secondary capitalize"
        :class="{ 'ml-auto': !user }"
        :aria-label="`Theme: ${theme}. Click to change.`"
        @click="cycle"
      >
        {{ theme }}
      </button>
    </div>
  </header>
</template>
