<script setup>
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { api } from '../api/client.js'
import { useAsyncData } from '../composables/useAsyncData.js'
import { usePolling } from '../composables/usePolling.js'
import { useRepositoryActions } from '../composables/useRepositoryActions.js'
import { useSession } from '../composables/useSession.js'
import { LOGIN_PATH, rememberReturnTo } from '../lib/auth.js'
import { changesLabel, listingErrorMessage, pageRange } from '../lib/dashboard.js'
import { compactNumber } from '../lib/format.js'
import { githubUrl, trackAvailability, vulnerabilityState } from '../lib/intelligence.js'
import {
  asSentence,
  formatScanDate,
  isActiveScan,
  repositoryKey,
  repositoryWorkflow,
  splitTracked,
  viewerTimeZone,
} from '../lib/repositories.js'
import AppIcon from './AppIcon.vue'
import DataCard from './DataCard.vue'
import EmptyState from './EmptyState.vue'
import ErrorState from './ErrorState.vue'
import LoadingState from './LoadingState.vue'
import RepositoryIdentity from './RepositoryIdentity.vue'
import RiskBadge from './RiskBadge.vue'
import RiskExplanation from './RiskExplanation.vue'
import VulnSummary from './VulnSummary.vue'

/**
 * The two repository sections, stacked: Tracked Repositories (tracked, with a
 * completed scan) above All Repositories (everything the user's GitHub
 * account can reach through the App, tracked or not). A repository can be in
 * both; both rows are described by the same repositoryWorkflow() state and
 * reloaded together, so they never disagree.
 *
 * Emits "tracked" with the tracked list's state (for the overview cards) and
 * "changed" whenever an action or a poll reloaded the lists.
 */
const emit = defineEmits(['tracked', 'changed'])

const PER_PAGE = 30
const POLL_MS = 5000
// A finished scan's vulnerability lookup normally lands within seconds;
// polling for it stops after this long so an old unanalyzed scan does not
// keep the page polling forever.
const LOOKUP_WAIT_MS = 15 * 60 * 1000
const timeZone = viewerTimeZone()

// With sign-in disabled for local development there is no user to track for:
// All Repositories lists every stored repository and tracking is hidden.
const { user } = useSession()
// Where to install SBOMDelta's GitHub App on another account or organization,
// or choose more of its repositories. The server builds it from the App's
// slug; anything that is not an https link is not shown.
const installUrl = computed(() => {
  const url = user.value?.installUrl ?? ''
  return url.startsWith('https://') ? url : ''
})
const localDevelopment = computed(() => Boolean(user.value?.authDisabled))

// --- Tracked Repositories ---------------------------------------------------

const tracked = useAsyncData(({ signal }) => api.listTracked({ signal }))
const split = computed(() => splitTracked(tracked.data.value))

watch(
  [tracked.data, tracked.loading, tracked.error],
  ([data, loading, error]) => emit('tracked', { data, loading, error }),
  { immediate: true },
)

// --- All Repositories -------------------------------------------------------

const page = ref(1)
const search = ref('')
const query = ref('')
let debounce = null
watch(search, (value) => {
  clearTimeout(debounce)
  debounce = setTimeout(() => {
    query.value = value.trim()
    page.value = 1
  }, 300)
})
onBeforeUnmount(() => clearTimeout(debounce))

const repositories = useAsyncData(
  ({ signal }) => api.listMyRepositories({ page: page.value, perPage: PER_PAGE, q: query.value, signal }),
  { watch: [page, query] },
)
const rows = computed(() => repositories.data.value?.repositories ?? [])
const total = computed(() => repositories.data.value?.total ?? 0)
const listing = computed(() => repositories.data.value?.listing ?? {})
const lastPage = computed(() => Math.max(1, Math.ceil(total.value / PER_PAGE)))
watch([rows, total], ([list, count]) => {
  if (!list.length && count > 0 && page.value > 1) page.value = Math.min(page.value - 1, lastPage.value)
})

// Reloading the list from GitHub is signing in again: the list is read while
// GitHub's token is in hand, and GitHub skips its prompt for an app already
// authorized. The page it was started from is where it comes back to.
function refreshFromGitHub() {
  let storage = null
  try {
    storage = window.sessionStorage
  } catch {
    /* storage unavailable: it lands on / anyway */
  }
  rememberReturnTo(storage, window.location.pathname)
  window.location.assign(LOGIN_PATH)
}

// --- Shared state and actions -----------------------------------------------

async function reloadAll() {
  await Promise.all([tracked.reload(), repositories.reload()])
}

const actions = useRepositoryActions(async () => {
  await reloadAll()
  emit('changed')
})
const { busy, notices } = actions

function describe(repo) {
  return repositoryWorkflow(repo, { busy: busy.has(repositoryKey(repo)), timeZone })
}
const trackedRows = computed(() => split.value.ready.map((repo) => ({ repo, state: describe(repo) })))
const allRows = computed(() => rows.value.map((repo) => ({ repo, state: describe(repo) })))

const explaining = reactive(new Set())
function toggleExplanation(id) {
  if (explaining.has(id)) explaining.delete(id)
  else explaining.add(id)
}

// --- Polling ----------------------------------------------------------------

function awaitingLookup(scan) {
  if (scan?.vulnerabilities?.status !== 'pending' || !scan.finishedAt) return false
  return Date.now() - new Date(scan.finishedAt).getTime() < LOOKUP_WAIT_MS
}

// While a scan is queued or running, or a finished scan is still being
// checked for vulnerabilities, poll both lists until it settles.
const anyActive = computed(
  () =>
    (tracked.data.value ?? []).some((repo) => isActiveScan(repo.latestScan) || awaitingLookup(repo.lastCompletedScan)) ||
    rows.value.some((repo) => isActiveScan(repo.latestScan)),
)
usePolling(
  () => anyActive.value,
  async () => {
    await reloadAll()
    emit('changed')
  },
  POLL_MS,
)

defineExpose({ reload: reloadAll })
</script>

<template>
  <div class="flex flex-col gap-6">
    <!-- 1. Tracked Repositories ------------------------------------------- -->
    <DataCard
      title="Tracked Repositories"
      icon="bookmark"
      heading-id="tracked-heading"
      flush
      :subtitle="`Repositories you monitor that have a completed scan. Times are shown in ${timeZone}.`"
    >
      <template #title-extra>
        <span v-if="split.ready.length" class="chip nums ml-1.5 align-[2px]">{{ split.ready.length }}</span>
      </template>

      <div v-if="tracked.loading.value" class="p-5"><LoadingState :rows="3" /></div>
      <ErrorState v-else-if="tracked.error.value" :error="tracked.error.value" @retry="tracked.reload" />
      <template v-else>
        <EmptyState
          v-if="localDevelopment"
          icon="bookmark"
          title="Tracking needs sign-in"
          note="Sign-in is disabled for local development, so there is no user to track repositories for. Scan and open reports from All Repositories below."
        />
        <EmptyState
          v-else-if="!split.ready.length && !split.awaiting.length"
          icon="bookmark"
          title="No tracked repositories yet"
          note="Track a repository under All Repositories below, and scan it. It appears here once its first scan completes."
        />
        <EmptyState
          v-else-if="!split.ready.length"
          tone="pending"
          title="Waiting for a first completed scan"
          note="You track repositories that have no completed scan yet, so there is no report to show. Scan them from All Repositories below."
        />

        <template v-else>
          <!-- Column labels for wide screens; narrow screens label each value. -->
          <div
            class="eyebrow hidden border-b border-hairline bg-surface-raised px-5 py-2 lg:grid lg:grid-cols-[minmax(0,2.3fr)_minmax(0,0.8fr)_minmax(0,1.25fr)_minmax(0,1.4fr)_minmax(0,1fr)_minmax(196px,auto)] lg:gap-x-4"
            aria-hidden="true"
          >
            <span>Repository</span>
            <span>Components</span>
            <span>Dependency changes</span>
            <span>Vulnerabilities</span>
            <span>Risk</span>
            <span class="text-right">Actions</span>
          </div>

          <ul class="m-0 list-none p-0" aria-labelledby="tracked-heading">
            <li
              v-for="{ repo, state } in trackedRows"
              :key="state.id"
              class="grid gap-x-4 gap-y-3 border-b border-hairline px-4 py-4 transition-colors last:border-0 hover:bg-surface-raised sm:px-5 lg:grid-cols-[minmax(0,2.3fr)_minmax(0,0.8fr)_minmax(0,1.25fr)_minmax(0,1.4fr)_minmax(0,1fr)_minmax(196px,auto)] lg:items-start"
            >
              <RepositoryIdentity :owner="repo.owner" :name="repo.name" :state="state" :time-zone="timeZone">
                <template #badges>
                  <span class="chip" :title="repo.private ? 'Private repository' : 'Public repository'">
                    <AppIcon :name="repo.private ? 'lock' : 'globe'" :size="11" />
                    {{ repo.private ? 'Private' : 'Public' }}
                  </span>
                  <span v-if="repo.access !== 'active'" class="chip chip-warning">No access</span>
                </template>
                <div class="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-ink-muted">
                  <span v-if="repo.defaultBranch" class="inline-flex items-center gap-1">
                    <AppIcon name="branch" :size="12" />
                    <span class="mono">{{ repo.defaultBranch }}</span>
                  </span>
                  <span class="inline-flex items-center gap-1" title="Commit of the last completed scan">
                    <AppIcon name="commit" :size="12" />
                    <span class="mono">{{ repo.lastCompletedScan.commitSha.slice(0, 7) }}</span>
                  </span>
                </div>
              </RepositoryIdentity>

              <div class="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:contents">
                <div>
                  <p class="eyebrow m-0 mb-1 lg:hidden">Components</p>
                  <span class="nums text-sm font-semibold text-ink">
                    {{ compactNumber(repo.lastCompletedScan.componentCount) }}
                  </span>
                </div>
                <div>
                  <p class="eyebrow m-0 mb-1 lg:hidden">Dependency changes</p>
                  <span class="text-xs text-ink-secondary">{{ changesLabel(repo) }}</span>
                </div>
                <div>
                  <p class="eyebrow m-0 mb-1 lg:hidden">Vulnerabilities</p>
                  <VulnSummary :summary="repo.lastCompletedScan.vulnerabilities ?? null" show-changes />
                </div>
                <div>
                  <p class="eyebrow m-0 mb-1 lg:hidden">Risk</p>
                  <RiskBadge :risk="repo.lastCompletedScan.risk ?? null" />
                  <button
                    v-if="repo.lastCompletedScan.risk"
                    type="button"
                    class="mt-1 inline-flex cursor-pointer items-center gap-1 border-0 bg-transparent p-0 text-[11px] font-medium text-accent hover:underline"
                    :aria-expanded="explaining.has(state.id)"
                    :aria-controls="`why-${state.id}`"
                    @click="toggleExplanation(state.id)"
                  >
                    <AppIcon name="info" :size="12" />
                    {{ explaining.has(state.id) ? 'Hide explanation' : 'Why?' }}
                  </button>
                </div>
              </div>

              <div class="flex flex-wrap items-center gap-2 lg:justify-end">
                <button
                  type="button"
                  class="btn btn-primary btn-sm"
                  :disabled="state.scan.disabled"
                  :title="state.scan.reason || 'Scan the default branch’s latest commit again'"
                  @click="actions.scan(state.id)"
                >
                  <AppIcon
                    :name="state.active || busy.has(state.id) ? 'loader' : 'scan'"
                    :size="13"
                    :class="{ spin: state.active || busy.has(state.id) }"
                  />
                  {{ state.scan.label }}
                </button>
                <button
                  type="button"
                  class="btn btn-danger-ghost btn-sm"
                  :disabled="busy.has(state.id)"
                  title="Stop tracking. Scan history and reports are kept."
                  @click="actions.untrack(state.id)"
                >
                  <AppIcon name="bookmark-minus" :size="13" />
                  Untrack
                </button>
                <a
                  v-if="githubUrl(repo.owner, repo.name)"
                  :href="githubUrl(repo.owner, repo.name)"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="icon-btn size-7"
                  :aria-label="`${repo.owner}/${repo.name} on GitHub`"
                  title="Open on GitHub"
                >
                  <AppIcon name="github" :size="14" />
                </a>
              </div>

              <div
                v-if="
                  state.failure ||
                  state.status?.key === 'failed' ||
                  notices[state.id] ||
                  explaining.has(state.id) ||
                  vulnerabilityState(repo.lastCompletedScan.vulnerabilities).error
                "
                class="flex flex-col gap-2 lg:col-span-full"
              >
                <p v-if="state.status?.key === 'failed'" class="banner banner-danger m-0">
                  <AppIcon name="x-circle" :size="15" class="mt-0.5" />
                  <span>
                    The latest scan failed{{ state.failure ? `: ${asSentence(state.failure)}` : '.' }} The report from the
                    last completed scan stays available.
                  </span>
                </p>
                <p v-if="vulnerabilityState(repo.lastCompletedScan.vulnerabilities).error" class="banner banner-warning m-0">
                  <AppIcon name="alert" :size="15" class="mt-0.5" />
                  <span>
                    Vulnerability lookup: {{ vulnerabilityState(repo.lastCompletedScan.vulnerabilities).error }}
                  </span>
                </p>
                <p
                  v-if="notices[state.id]"
                  :role="notices[state.id].tone === 'danger' ? 'alert' : 'status'"
                  class="banner m-0"
                  :class="notices[state.id].tone === 'danger' ? 'banner-danger' : 'banner-info'"
                >
                  <AppIcon :name="notices[state.id].tone === 'danger' ? 'alert-circle' : 'info'" :size="15" class="mt-0.5" />
                  <span>{{ notices[state.id].text }}</span>
                </p>
                <RiskExplanation
                  v-if="explaining.has(state.id)"
                  :id="`why-${state.id}`"
                  :scan-id="repo.lastCompletedScan.id"
                />
              </div>
            </li>
          </ul>
        </template>

        <div v-if="split.awaiting.length" class="border-t border-hairline px-4 py-3 sm:px-5">
          <p class="banner banner-info m-0" role="note">
            <AppIcon name="clock" :size="15" class="mt-0.5" />
            <span>
              {{ split.awaiting.length }} tracked
              {{ split.awaiting.length === 1 ? 'repository has' : 'repositories have' }} no completed scan yet
              ({{ split.awaiting.slice(0, 4).map((r) => `${r.owner}/${r.name}`).join(', ')
              }}{{ split.awaiting.length > 4 ? ', …' : '' }}), so
              {{ split.awaiting.length === 1 ? 'it appears' : 'they appear' }} here after a scan completes. Scan from
              All Repositories below.
            </span>
          </p>
        </div>
      </template>
    </DataCard>

    <!-- 2. All Repositories ----------------------------------------------- -->
    <DataCard
      title="All Repositories"
      icon="repo"
      heading-id="all-heading"
      flush
      :subtitle="
        localDevelopment
          ? 'Every repository SBOMDelta has stored (local development).'
          : 'Every repository your GitHub account can reach through SBOMDelta’s GitHub App, tracked or not.'
      "
    >
      <template #title-extra>
        <span v-if="total" class="chip nums ml-1.5 align-[2px]">{{ total }}</span>
      </template>
      <template v-if="!localDevelopment" #actions>
        <a v-if="installUrl" :href="installUrl" class="btn btn-secondary btn-sm" target="_blank" rel="noopener noreferrer">
          <AppIcon name="github" :size="13" />
          Add repositories
        </a>
        <button type="button" class="btn btn-secondary btn-sm" @click="refreshFromGitHub">
          <AppIcon name="refresh" :size="13" />
          Refresh from GitHub
        </button>
      </template>

      <div class="flex flex-wrap items-center gap-3 border-b border-hairline px-4 py-3 sm:px-5">
        <label class="relative w-full max-w-sm">
          <span class="sr-only">Search repositories</span>
          <AppIcon
            name="search"
            :size="15"
            class="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-ink-muted"
          />
          <input v-model="search" type="search" placeholder="Search owner/name" class="input pl-9" />
        </label>
        <span v-if="listing.listedAt" class="nums text-xs text-ink-muted">
          Synced from GitHub on {{ formatScanDate(listing.listedAt, timeZone) }}
        </span>
      </div>

      <div v-if="listing.error" class="px-4 pt-3 sm:px-5">
        <p
          :role="listing.error === 'auth_disabled' ? 'note' : 'alert'"
          class="banner m-0"
          :class="listing.error === 'auth_disabled' ? 'banner-info' : 'banner-warning'"
        >
          <AppIcon :name="listing.error === 'auth_disabled' ? 'terminal' : 'alert'" :size="15" class="mt-0.5" />
          <span>{{ listingErrorMessage(listing.error) }}</span>
        </p>
      </div>

      <div v-if="repositories.loading.value" class="p-5"><LoadingState :rows="4" /></div>
      <ErrorState
        v-else-if="repositories.error.value"
        :error="repositories.error.value"
        @retry="repositories.reload"
      />
      <EmptyState
        v-else-if="!rows.length && query"
        icon="search"
        title="No repositories match"
        :note="`Nothing in your repository list matches “${query}”.`"
      />
      <EmptyState
        v-else-if="!rows.length && !listing.error && !listing.listedAt"
        title="Your repositories have not been loaded yet"
        note="SBOMDelta reads your repository list from GitHub when you sign in. Select Refresh from GitHub to load it now."
      />
      <EmptyState
        v-else-if="!rows.length && !listing.error"
        title="No repositories found"
        note="Your GitHub account cannot reach any repository through SBOMDelta’s GitHub App yet. Install the App on your account or organization and choose repositories (or ask their owner to), then select Refresh from GitHub."
      >
        <a v-if="installUrl" :href="installUrl" class="btn btn-primary btn-sm mt-2" target="_blank" rel="noopener noreferrer">
          <AppIcon name="github" :size="14" />
          Install the GitHub App
        </a>
      </EmptyState>

      <ul
        v-else-if="rows.length"
        class="m-0 list-none p-0"
        :class="{ 'is-refetching': repositories.refetching.value && !anyActive }"
        aria-labelledby="all-heading"
      >
        <li
          v-for="{ repo, state } in allRows"
          :key="repo.githubRepoId || `stored-${repo.repositoryId}`"
          class="flex flex-col gap-3 border-b border-hairline px-4 py-3.5 transition-colors last:border-0 hover:bg-surface-raised sm:px-5 md:flex-row md:items-start md:justify-between"
        >
          <RepositoryIdentity :owner="repo.owner" :name="repo.name" :state="state" :time-zone="timeZone">
            <template #badges>
              <span v-if="repo.tracked" class="chip chip-info" title="You track this repository">
                <AppIcon name="bookmark" :size="11" />
                Tracked
              </span>
              <span class="chip" :title="repo.private ? 'Private repository' : 'Public repository'">
                <AppIcon :name="repo.private ? 'lock' : 'globe'" :size="11" />
                {{ repo.private ? 'Private' : 'Public' }}
              </span>
            </template>
            <div class="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-ink-muted">
              <span v-if="repo.defaultBranch" class="inline-flex items-center gap-1">
                <AppIcon name="branch" :size="12" />
                <span class="mono">{{ repo.defaultBranch }}</span>
              </span>
              <span v-if="state.hasReport" class="nums inline-flex items-center gap-1">
                <AppIcon name="package" :size="12" />
                {{ compactNumber(repo.lastCompletedScan.componentCount) }} components
              </span>
            </div>
            <p v-if="state.scan.reason" class="mt-1.5 mb-0 text-xs text-ink-muted">{{ state.scan.reason }}</p>
            <p v-if="state.status?.key === 'failed'" class="mt-1.5 mb-0 text-xs text-[var(--tone-danger-fg)]">
              {{ asSentence(state.failure) || 'The scan failed.' }}
              {{ state.hasReport ? 'The previous report stays available.' : 'Select Scan to try again.' }}
            </p>
            <p
              v-if="notices[state.id]"
              :role="notices[state.id].tone === 'danger' ? 'alert' : 'status'"
              class="banner mt-2 mb-0 text-xs"
              :class="notices[state.id].tone === 'danger' ? 'banner-danger' : 'banner-info'"
            >
              {{ notices[state.id].text }}
            </p>
          </RepositoryIdentity>

          <div class="flex shrink-0 flex-wrap items-center gap-2 md:justify-end">
            <button
              type="button"
              class="btn btn-sm"
              :class="state.hasReport ? 'btn-secondary' : 'btn-primary'"
              :disabled="state.scan.disabled"
              :title="state.scan.reason || (state.hasReport ? 'Scan the default branch’s latest commit again' : 'Scan the default branch’s latest commit')"
              @click="actions.scan(state.id)"
            >
              <AppIcon
                :name="state.active || busy.has(state.id) ? 'loader' : 'scan'"
                :size="13"
                :class="{ spin: state.active || busy.has(state.id) }"
              />
              {{ state.scan.label }}
            </button>
            <button
              v-if="!repo.tracked && !localDevelopment"
              type="button"
              class="btn btn-ghost btn-sm border-hairline"
              :disabled="!trackAvailability(repo).ok || busy.has(state.id)"
              :title="trackAvailability(repo).reason || 'Track this repository'"
              @click="actions.track(state.id, { hasReport: state.hasReport })"
            >
              <AppIcon name="bookmark-plus" :size="13" />
              Track
            </button>
            <button
              v-else-if="repo.tracked"
              type="button"
              class="btn btn-danger-ghost btn-sm"
              :disabled="busy.has(state.id)"
              title="Stop tracking. Scan history and reports are kept."
              @click="actions.untrack(state.id)"
            >
              <AppIcon name="bookmark-minus" :size="13" />
              Untrack
            </button>
            <a
              v-if="githubUrl(repo.owner, repo.name)"
              :href="githubUrl(repo.owner, repo.name)"
              target="_blank"
              rel="noopener noreferrer"
              class="icon-btn size-7"
              :aria-label="`${repo.owner}/${repo.name} on GitHub`"
              title="Open on GitHub"
            >
              <AppIcon name="github" :size="14" />
            </a>
          </div>
        </li>
      </ul>

      <template v-if="total > PER_PAGE" #footer>
        <div class="flex items-center justify-between gap-3">
          <span class="nums">{{ pageRange(page, PER_PAGE, total, rows.length) }}</span>
          <span class="flex gap-2">
            <button
              type="button"
              class="btn btn-secondary btn-sm"
              :disabled="page <= 1 || repositories.refetching.value"
              @click="page -= 1"
            >
              <AppIcon name="chevron-left" :size="13" />
              Previous
            </button>
            <button
              type="button"
              class="btn btn-secondary btn-sm"
              :disabled="page >= lastPage || repositories.refetching.value"
              @click="page += 1"
            >
              Next
              <AppIcon name="chevron-right" :size="13" />
            </button>
          </span>
        </div>
      </template>
    </DataCard>
  </div>
</template>
