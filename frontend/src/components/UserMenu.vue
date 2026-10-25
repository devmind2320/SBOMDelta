<script setup>
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useSession } from '../composables/useSession.js'
import { signOutErrorMessage } from '../lib/auth.js'
import AppIcon from './AppIcon.vue'

// The signed-in identity, exactly as /api/me reports it: the GitHub login
// (SBOMDelta stores no display name) and avatar. With sign-in disabled for
// local development there is no GitHub identity at all, and the menu says so
// instead of presenting the placeholder account as one.
const { user, signOut } = useSession()
const router = useRouter()

const open = ref(false)
const signingOut = ref(false)
const error = ref('')
const root = ref(null)
const trigger = ref(null)
const firstItem = ref(null)

const local = computed(() => Boolean(user.value?.authDisabled))
const login = computed(() => user.value?.login ?? '')
const avatar = computed(() => {
  const url = user.value?.avatarUrl ?? ''
  return url.startsWith('https://') ? url : ''
})
const initial = computed(() => (login.value ? login.value[0].toUpperCase() : '?'))
const profileUrl = computed(() => (login.value ? `https://github.com/${encodeURIComponent(login.value)}` : ''))

function close({ focus = false } = {}) {
  open.value = false
  if (focus) trigger.value?.focus()
}

async function toggle() {
  open.value = !open.value
  if (open.value) {
    await nextTick()
    firstItem.value?.focus()
  }
}

function onDocumentPointer(event) {
  if (open.value && root.value && !root.value.contains(event.target)) close()
}
function onKeydown(event) {
  if (event.key === 'Escape' && open.value) close({ focus: true })
}
watch(open, (isOpen) => {
  if (isOpen) {
    document.addEventListener('pointerdown', onDocumentPointer)
    document.addEventListener('keydown', onKeydown)
  } else {
    document.removeEventListener('pointerdown', onDocumentPointer)
    document.removeEventListener('keydown', onKeydown)
  }
})
onBeforeUnmount(() => {
  document.removeEventListener('pointerdown', onDocumentPointer)
  document.removeEventListener('keydown', onKeydown)
})

// Only a sign-out the server confirmed leaves the page. A failed one stays
// here and says so: the session is still valid.
async function onSignOut() {
  if (signingOut.value) return
  error.value = ''
  signingOut.value = true
  try {
    await signOut()
  } catch (failure) {
    error.value = signOutErrorMessage(failure)
    return
  } finally {
    signingOut.value = false
  }
  close()
  router.push({ name: 'login', query: { signed_out: '1' } })
}
</script>

<template>
  <div v-if="user" ref="root" class="relative min-w-0">
    <button
      ref="trigger"
      type="button"
      class="flex max-w-full min-w-0 cursor-pointer items-center gap-2 rounded-lg border border-transparent bg-transparent py-1 pr-1.5 pl-1 text-sm text-ink transition-colors hover:border-hairline hover:bg-surface-muted"
      :aria-expanded="open"
      aria-haspopup="menu"
      :aria-label="local ? 'Local development session' : `Account menu for ${login}`"
      @click="toggle"
    >
      <span
        class="flex size-7 items-center justify-center overflow-hidden rounded-full border border-hairline bg-surface-muted text-xs font-semibold text-ink-secondary"
      >
        <AppIcon v-if="local" name="terminal" :size="14" />
        <img v-else-if="avatar" :src="avatar" alt="" class="size-full object-cover" referrerpolicy="no-referrer" />
        <template v-else>{{ initial }}</template>
      </span>
      <span class="max-w-[7.5rem] truncate font-medium sm:max-w-[16ch]">
        {{ local ? 'Local development' : login }}
      </span>
      <AppIcon name="chevron-down" :size="14" class="text-ink-muted" />
    </button>

    <div
      v-if="open"
      role="menu"
      class="absolute right-0 z-50 mt-2 w-72 rounded-xl border border-hairline bg-surface-overlay p-1.5 shadow-[var(--shadow-lg)]"
    >
      <div class="border-b border-hairline px-3 pt-2 pb-3">
        <template v-if="local">
          <p class="m-0 text-sm font-semibold text-ink">Local development</p>
          <p class="mt-1 mb-0 text-xs leading-relaxed text-ink-muted">
            Sign-in is disabled in this environment, so there is no GitHub identity and nothing to sign out of.
          </p>
        </template>
        <template v-else>
          <p class="eyebrow m-0">Signed in with GitHub</p>
          <p class="mt-1 mb-0 truncate text-sm font-semibold text-ink">{{ login }}</p>
        </template>
      </div>

      <template v-if="!local">
        <a
          ref="firstItem"
          role="menuitem"
          :href="profileUrl"
          target="_blank"
          rel="noopener noreferrer"
          class="mt-1 flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm text-ink-secondary no-underline hover:bg-surface-muted hover:text-ink"
        >
          <AppIcon name="github" :size="15" />
          GitHub profile
          <AppIcon name="external" :size="13" class="ml-auto text-ink-muted" />
        </a>
        <button
          role="menuitem"
          type="button"
          class="flex w-full cursor-pointer items-center gap-2.5 rounded-lg border-0 bg-transparent px-3 py-2 text-left text-sm text-ink-secondary hover:bg-[var(--tone-danger-bg)] hover:text-[var(--tone-danger-fg)] disabled:cursor-wait"
          :disabled="signingOut"
          @click="onSignOut"
        >
          <AppIcon :name="signingOut ? 'loader' : 'log-out'" :size="15" :class="{ spin: signingOut }" />
          {{ signingOut ? 'Signing out…' : 'Sign out' }}
        </button>
        <p v-if="error" role="alert" class="banner banner-danger m-1 mt-1.5 text-xs">{{ error }}</p>
      </template>
      <span v-else ref="firstItem" tabindex="-1" />
    </div>
  </div>
</template>
