<script setup>
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import { api } from '../api/client.js'
import { useAsyncData } from '../composables/useAsyncData.js'
import { usePolling } from '../composables/usePolling.js'
import { useSession } from '../composables/useSession.js'
import { compactNumber } from '../lib/format.js'
import { formatScore } from '../lib/intelligence.js'
import { formatScanDate, isActiveScan, securityOverview, viewerTimeZone } from '../lib/repositories.js'
import AppIcon from '../components/AppIcon.vue'
import MetricCard from '../components/MetricCard.vue'
import PageHeader from '../components/PageHeader.vue'
import RiskBadge from '../components/RiskBadge.vue'
import ScanStatusBadge from '../components/ScanStatusBadge.vue'

// The dashboard is the security overview only: four metric cards computed
// from the tracked repositories' last completed scans, and shortcuts to the
// pages that hold the listings (Repositories, Last Scans, Impact). Nothing
// here repeats those pages' rows.

const { user } = useSession()
const localDevelopment = computed(() => Boolean(user.value?.authDisabled))
const timeZone = viewerTimeZone()

const tracked = useAsyncData(({ signal }) => api.listTracked({ signal }))
// One row of each is enough for the shortcut cards: the total, and the
// newest scan.
const repositories = useAsyncData(({ signal }) => api.listMyRepositories({ page: 1, perPage: 1, signal }))
const latest = useAsyncData(({ signal }) => api.listRecentScans({ limit: 1, signal }))
const latestScan = computed(() => latest.data.value?.[0] ?? null)

const trackedState = computed(() => ({
  data: tracked.data.value,
  loading: tracked.loading.value,
  error: tracked.error.value,
}))

// Keep the cards current while a tracked scan or its vulnerability lookup is
// still running; stop once everything has settled.
const LOOKUP_WAIT_MS = 15 * 60 * 1000
function awaitingLookup(scan) {
  if (scan?.vulnerabilities?.status !== 'pending' || !scan.finishedAt) return false
  return Date.now() - new Date(scan.finishedAt).getTime() < LOOKUP_WAIT_MS
}
usePolling(
  () =>
    (tracked.data.value ?? []).some((repo) => isActiveScan(repo.latestScan) || awaitingLookup(repo.lastCompletedScan)) ||
    isActiveScan(latestScan.value),
  () => Promise.all([tracked.reload(), latest.reload()]),
  5000,
)

const overview = computed(() => securityOverview(trackedState.value.data ?? []))
const cardsLoading = computed(() => trackedState.value.loading && !trackedState.value.data)
const cardsFailed = computed(() => Boolean(trackedState.value.error) && !trackedState.value.data)

const repositoriesNote = computed(() => {
  if (repositories.error.value) return 'Could not load your repository list.'
  const body = repositories.data.value
  if (!body) return ''
  const total = body.total ?? 0
  if (localDevelopment.value) return `${total} stored ${total === 1 ? 'repository' : 'repositories'} to scan and open reports for.`
  if (body.listing?.error) return 'Your repository list from GitHub needs attention. Open Repositories for details.'
  if (!body.listing?.listedAt) return 'Your repository list has not been loaded from GitHub yet.'
  return `${total} ${total === 1 ? 'repository' : 'repositories'} available to scan and track.`
})

const vulnerabilityCard = computed(() => {
  const v = overview.value.vulnerabilities
  const blocking = v.critical + v.high
  switch (v.state) {
    case 'analyzed':
      return {
        value: compactNumber(v.total),
        tone: blocking ? 'danger' : v.total ? 'warning' : 'success',
        muted: false,
      }
    case 'pending':
      return { value: 'Checking…', tone: 'info', muted: true }
    case 'unavailable':
      return { value: 'Unavailable', tone: 'warning', muted: true }
    default:
      return { value: '—', tone: 'neutral', muted: true }
  }
})

const SEVERITY_CHIPS = [
  { key: 'critical', label: 'Critical', chip: 'chip-danger' },
  { key: 'high', label: 'High', chip: 'chip-warning' },
  { key: 'medium', label: 'Medium', chip: '' },
  { key: 'low', label: 'Low', chip: '' },
  { key: 'unrated', label: 'Unrated', chip: '' },
]

const riskTone = computed(() => {
  const level = overview.value.risk.top?.level
  if (level === 'critical') return 'danger'
  if (level === 'high' || level === 'medium') return 'warning'
  if (level === 'none' || level === 'low') return 'success'
  return 'neutral'
})

function plural(count, one, many) {
  return `${count} ${count === 1 ? one : many}`
}
</script>

<template>
  <div class="flex flex-col gap-6 sm:gap-8">
    <PageHeader
      eyebrow="Overview"
      title="Security dashboard"
      description="Dependencies, known vulnerabilities and explainable risk for the repositories you monitor, from their latest completed scans."
    >
      <template #actions>
        <RouterLink :to="{ name: 'impact' }" class="btn btn-secondary">
          <AppIcon name="impact" :size="14" />
          Impact analysis
        </RouterLink>
      </template>
    </PageHeader>

    <!-- 1. Security overview -->
    <section aria-label="Security overview" class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <MetricCard
        label="Tracked repositories"
        icon="bookmark"
        tone="info"
        :loading="cardsLoading"
        :value="cardsFailed || localDevelopment ? '—' : overview.tracked"
        :muted="cardsFailed || localDevelopment"
      >
        <template v-if="cardsFailed">Could not load your tracked repositories.</template>
        <template v-else-if="localDevelopment">Tracking needs sign-in, which is disabled for local development.</template>
        <template v-else-if="!overview.tracked">Track a repository below to start monitoring it.</template>
        <template v-else>
          {{ plural(overview.reporting, 'with a report', 'with reports') }}
          <template v-if="overview.awaitingFirstScan">
            · {{ overview.awaitingFirstScan }} awaiting a first completed scan
          </template>
        </template>
      </MetricCard>

      <MetricCard
        label="Components"
        icon="package"
        :loading="cardsLoading"
        :value="overview.components === null ? '—' : compactNumber(overview.components)"
        :muted="overview.components === null"
      >
        <template v-if="localDevelopment">Counted from tracked repositories, which need sign-in.</template>
        <template v-else-if="overview.components === null">No completed scans of tracked repositories yet.</template>
        <template v-else>
          Packages in the latest completed scan of {{ plural(overview.reporting, 'repository', 'repositories') }}.
        </template>
      </MetricCard>

      <MetricCard
        label="Known vulnerabilities"
        icon="shield-alert"
        :loading="cardsLoading"
        :tone="vulnerabilityCard.tone"
        :value="vulnerabilityCard.value"
        :muted="vulnerabilityCard.muted"
      >
        <template v-if="localDevelopment">Counted from tracked repositories, which need sign-in. Open a report to see a scan's vulnerabilities.</template>
        <template v-else-if="overview.vulnerabilities.state === 'none'">Nothing to check until a tracked scan completes.</template>
        <template v-else-if="overview.vulnerabilities.state === 'pending'">
          Vulnerability analysis is still running for
          {{ plural(overview.vulnerabilities.pending, 'repository', 'repositories') }}.
        </template>
        <template v-else-if="overview.vulnerabilities.state === 'unavailable'">
          The vulnerability lookup failed and is retried automatically. This is not a clean result.
        </template>
        <template v-else>
          <span v-if="!overview.vulnerabilities.total" class="block">
            No known vulnerabilities in {{ plural(overview.vulnerabilities.analyzed, 'analyzed repository', 'analyzed repositories') }}.
          </span>
          <span v-else class="flex flex-wrap gap-1">
            <template v-for="item in SEVERITY_CHIPS" :key="item.key">
              <span v-if="overview.vulnerabilities[item.key]" class="chip nums" :class="item.chip">
                {{ overview.vulnerabilities[item.key] }} {{ item.label }}
              </span>
            </template>
          </span>
          <span
            v-if="overview.vulnerabilities.pending || overview.vulnerabilities.failed"
            class="mt-1 block"
          >
            Not counted:
            <template v-if="overview.vulnerabilities.pending">{{ overview.vulnerabilities.pending }} still being checked</template>
            <template v-if="overview.vulnerabilities.pending && overview.vulnerabilities.failed"> · </template>
            <template v-if="overview.vulnerabilities.failed">{{ overview.vulnerabilities.failed }} unavailable</template>
          </span>
        </template>
      </MetricCard>

      <MetricCard
        label="Highest risk score"
        icon="gauge"
        :loading="cardsLoading"
        :tone="riskTone"
        :value="overview.risk.top ? formatScore(overview.risk.top.score) : 'Not scored'"
        :muted="!overview.risk.top"
      >
        <template v-if="overview.risk.top" #value>
          <span class="flex items-center gap-2">
            {{ formatScore(overview.risk.top.score) }}
            <RiskBadge :risk="{ score: overview.risk.top.score, level: overview.risk.top.level }" />
          </span>
        </template>
        <template v-if="overview.risk.top">
          <span class="block truncate">
            {{ overview.risk.top.owner }}/{{ overview.risk.top.name }}, the highest of
            {{ plural(overview.risk.scored, 'scored repository', 'scored repositories') }}.
          </span>
          <RouterLink
            :to="{ name: 'scan', params: { scanId: overview.risk.top.scanId } }"
            class="link mt-0.5 inline-flex items-center gap-1"
          >
            See the score breakdown
            <AppIcon name="arrow-right" :size="12" />
          </RouterLink>
        </template>
        <template v-else-if="localDevelopment">Scored across tracked repositories, which need sign-in.</template>
        <template v-else-if="overview.reporting">
          Scores appear once the vulnerability analysis of a tracked scan completes.
        </template>
        <template v-else>No completed scans to score yet.</template>
      </MetricCard>
    </section>

    <!-- Shortcuts to the pages that hold the listings, each with one real fact. -->
    <section aria-labelledby="explore-heading" class="flex flex-col gap-3">
      <h2 id="explore-heading" class="eyebrow m-0">Explore</h2>
      <div class="grid gap-4 md:grid-cols-3">
        <RouterLink :to="{ name: 'repositories' }" class="explore-card group">
          <span class="explore-icon"><AppIcon name="repo" :size="17" /></span>
          <span class="min-w-0 flex-1">
            <span class="flex items-center gap-1.5 text-sm font-semibold text-ink">
              Repositories
              <AppIcon name="arrow-right" :size="14" class="explore-arrow" />
            </span>
            <span class="mt-1 block text-xs leading-relaxed text-ink-muted">
              <span v-if="repositories.loading.value" class="skeleton inline-block h-3 w-40 align-middle" aria-hidden="true" />
              <template v-else>{{ repositoriesNote }}</template>
            </span>
          </span>
        </RouterLink>

        <RouterLink :to="{ name: 'last-scans' }" class="explore-card group">
          <span class="explore-icon"><AppIcon name="history" :size="17" /></span>
          <span class="min-w-0 flex-1">
            <span class="flex items-center gap-1.5 text-sm font-semibold text-ink">
              Last Scans
              <AppIcon name="arrow-right" :size="14" class="explore-arrow" />
            </span>
            <span class="mt-1 block text-xs leading-relaxed text-ink-muted">
              <span v-if="latest.loading.value" class="skeleton inline-block h-3 w-40 align-middle" aria-hidden="true" />
              <template v-else-if="latest.error.value">Could not load the scan history.</template>
              <template v-else-if="!latestScan">No scans recorded yet.</template>
              <span v-else class="flex flex-wrap items-center gap-x-2 gap-y-1">
                <ScanStatusBadge :status="latestScan.status" />
                <span class="nums">
                  {{ latestScan.finishedAt ? 'Latest finished' : 'Latest queued' }}
                  {{ formatScanDate(latestScan.finishedAt ?? latestScan.createdAt, timeZone) }}
                </span>
                <span class="truncate">· {{ latestScan.owner }}/{{ latestScan.name }}</span>
              </span>
            </span>
          </span>
        </RouterLink>

        <RouterLink :to="{ name: 'impact' }" class="explore-card group">
          <span class="explore-icon"><AppIcon name="impact" :size="17" /></span>
          <span class="min-w-0 flex-1">
            <span class="flex items-center gap-1.5 text-sm font-semibold text-ink">
              Impact analysis
              <AppIcon name="arrow-right" :size="14" class="explore-arrow" />
            </span>
            <span class="mt-1 block text-xs leading-relaxed text-ink-muted">
              Which repositories an advisory or a dependency reaches, with fixed versions to upgrade to.
            </span>
          </span>
        </RouterLink>
      </div>
      <p class="m-0 text-xs text-ink-muted">Times are shown in {{ timeZone }}.</p>
    </section>
  </div>
</template>
