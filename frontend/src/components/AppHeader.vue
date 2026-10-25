<script setup>
import { computed, ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { useSession } from '../composables/useSession.js'
import AppIcon from './AppIcon.vue'
import BackButton from './BackButton.vue'
import ThemeToggle from './ThemeToggle.vue'
import UserMenu from './UserMenu.vue'

const { user, unavailable, loadSession } = useSession()
const route = useRoute()

// Each route names the section it belongs to (router meta.section), so a
// scan or pull request page keeps Repositories highlighted.
const NAV = [
  { section: 'dashboard', label: 'Dashboard', icon: 'dashboard', to: { name: 'dashboard' } },
  { section: 'repositories', label: 'Repositories', icon: 'repo', to: { name: 'repositories' } },
  { section: 'scans', label: 'Last Scans', icon: 'history', to: { name: 'last-scans' } },
  { section: 'impact', label: 'Impact', icon: 'impact', to: { name: 'impact' } },
]
const current = computed(() => route.meta?.section ?? '')
const signedIn = computed(() => Boolean(user.value) && route.name !== 'login')

// /api/me failed without answering whether anyone is signed in. Say so, with
// a retry, instead of showing a header that looks signed out.
const retrying = ref(false)
async function retrySession() {
  retrying.value = true
  try {
    await loadSession()
  } catch {
    /* still unavailable; the indicator stays */
  } finally {
    retrying.value = false
  }
}
</script>

<template>
  <header
    class="sticky top-0 z-40 border-b border-hairline bg-[var(--header-bg)] backdrop-blur-md supports-[backdrop-filter]:bg-[var(--header-bg)]"
  >
    <div class="mx-auto flex h-14 w-full max-w-[1280px] items-center gap-2 px-4 sm:gap-3 sm:px-6">
      <BackButton v-if="signedIn" />
      <span v-if="signedIn" class="hidden h-5 w-px bg-hairline sm:block" aria-hidden="true" />

      <RouterLink
        :to="{ name: signedIn ? 'dashboard' : 'login' }"
        class="flex shrink-0 items-center gap-2 text-ink no-underline"
        aria-label="SBOMDelta home"
      >
        <!-- Two offset nodes inside a shield: a before/after comparison, which
             is what the product does, for supply-chain security. -->
        <span
          class="flex size-7 items-center justify-center rounded-lg bg-accent-solid text-[var(--on-accent)] shadow-[var(--shadow-sm)]"
        >
          <svg width="16" height="16" viewBox="0 0 20 20" aria-hidden="true">
            <circle cx="6.5" cy="6.5" r="2.6" fill="currentColor" opacity="0.7" />
            <circle cx="13.5" cy="13.5" r="2.6" fill="currentColor" />
            <path
              d="M6.5 9.4v3a1.2 1.2 0 0 0 1.2 1.2h3"
              fill="none"
              stroke="currentColor"
              stroke-width="1.6"
              stroke-linecap="round"
            />
          </svg>
        </span>
        <span class="text-[15px] font-semibold tracking-tight max-sm:sr-only">SBOMDelta</span>
      </RouterLink>

      <nav v-if="signedIn" class="ml-4 hidden items-center gap-0.5 lg:flex" aria-label="Main">
        <RouterLink
          v-for="item in NAV"
          :key="item.section"
          :to="item.to"
          class="flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[13px] font-medium no-underline transition-colors"
          :class="
            current === item.section
              ? 'bg-accent-soft text-accent'
              : 'text-ink-secondary hover:bg-surface-muted hover:text-ink'
          "
          :aria-current="current === item.section ? 'page' : undefined"
        >
          <AppIcon :name="item.icon" :size="15" />
          {{ item.label }}
        </RouterLink>
      </nav>
      <span v-else class="ml-3 hidden text-xs text-ink-muted lg:inline">Software supply-chain security</span>

      <div class="ml-auto flex min-w-0 items-center gap-2">
        <ThemeToggle />
        <UserMenu v-if="signedIn" />
        <button
          v-else-if="unavailable && route.name !== 'login'"
          type="button"
          class="btn btn-secondary btn-sm"
          :disabled="retrying"
          :title="`Could not check who is signed in: ${unavailable.message}`"
          @click="retrySession"
        >
          <AppIcon :name="retrying ? 'loader' : 'alert'" :size="13" :class="{ spin: retrying }" />
          <span class="hidden sm:inline">API unavailable ·</span> Retry
        </button>
      </div>
    </div>

    <!-- Narrow screens: the same navigation as a scrollable strip, so no item
         is hidden behind a menu or overlaps the account controls. -->
    <nav
      v-if="signedIn"
      class="flex gap-1 overflow-x-auto border-t border-hairline px-3 py-1.5 lg:hidden"
      aria-label="Main"
    >
      <RouterLink
        v-for="item in NAV"
        :key="item.section"
        :to="item.to"
        class="flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium no-underline"
        :class="current === item.section ? 'bg-accent-soft text-accent' : 'text-ink-secondary'"
        :aria-current="current === item.section ? 'page' : undefined"
      >
        <AppIcon :name="item.icon" :size="14" />
        {{ item.label }}
      </RouterLink>
    </nav>
  </header>
</template>
