<script setup>
import { computed, ref, toRef } from 'vue'
import { RouterLink } from 'vue-router'
import { api } from '../api/client.js'
import { useAsyncData } from '../composables/useAsyncData.js'
import { githubUrl } from '../lib/intelligence.js'
import { formatLastScanned } from '../lib/repositories.js'
import {
  accessLabel,
  compactNumber,
  formatDate,
  formatDateTime,
  isAccessible,
  scanTriggerLabel,
  shortSha,
} from '../lib/format.js'
import AppIcon from '../components/AppIcon.vue'
import DataCard from '../components/DataCard.vue'
import DriftTimeline from '../components/DriftTimeline.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import PageHeader from '../components/PageHeader.vue'
import RiskBadge from '../components/RiskBadge.vue'
import RiskExplanation from '../components/RiskExplanation.vue'
import RiskScore from '../components/RiskScore.vue'
import LoadingState from '../components/LoadingState.vue'
import ScanStatusBadge from '../components/ScanStatusBadge.vue'
import StatTile from '../components/StatTile.vue'

const props = defineProps({ repoId: { type: String, required: true } })
const repoId = toRef(props, 'repoId')

const repository = useAsyncData(({ signal }) => api.getRepository(repoId.value, { signal }), {
  watch: [repoId],
})
const timeline = useAsyncData(({ signal }) => api.getDriftTimeline(repoId.value, { signal }), {
  watch: [repoId],
})
const scans = useAsyncData(({ signal }) => api.listScans(repoId.value, { signal, limit: 20 }), {
  watch: [repoId],
})

// The newest completed default-branch scan is the repository's current state.
const current = computed(() => timeline.data.value?.[0] ?? null)
const currentScanId = computed(() => current.value?.scanId ?? null)

// Its full record carries the risk level, delta and, when it has no score,
// why: the vulnerability lookup is pending or failed.
const currentScan = useAsyncData(
  ({ signal }) => (currentScanId.value ? api.getScan(currentScanId.value, { signal }) : null),
  { watch: [currentScanId] },
)
const riskReason = computed(() => {
  const scan = currentScan.data.value
  if (!current.value) return 'No completed scan yet, so there is nothing to score.'
  if (scan?.enrichmentError) return `The vulnerability lookup failed: ${scan.enrichmentError}. It is retried automatically.`
  return ''
})
const showExplanation = ref(false)

// The same rule as the dashboard: the newest completed default-branch scan,
// not a pull request or backfilled base scan, and its finish time. Failed or
// running scans never move it.
const lastScannedText = computed(() => {
  const completed = (scans.data.value ?? []).find(
    (scan) => scan.status === 'completed' && !scan.pullRequestId && scan.trigger !== 'backfill',
  )
  if (completed) return formatLastScanned(completed.finishedAt) || 'Last scanned (time not recorded)'
  if (scans.data.value && !current.value) return 'Not scanned yet'
  return ''
})

function scanRisk(scan) {
  return scan.enrichedAt ? { score: scan.riskScore ?? null, level: scan.riskLevel, delta: scan.riskDelta ?? null } : null
}

const changesThisWeek = computed(() => {
  if (!timeline.data.value) return null
  const cutoff = Date.now() - 7 * 86400 * 1000
  return timeline.data.value
    .filter((point) => new Date(point.createdAt).getTime() >= cutoff)
    .reduce((sum, point) => sum + point.added + point.updated + point.removed, 0)
})

const componentDelta = computed(() => {
  const points = timeline.data.value
  if (!points || points.length < 2) return null
  return points[0].componentCount - points[1].componentCount
})
</script>

<template>
  <div class="flex flex-col gap-6">
    <PageHeader>
      <template #eyebrow>
        <RouterLink :to="{ name: 'repositories' }" class="text-ink-muted no-underline hover:text-ink">Repositories</RouterLink>
        <span class="mx-1.5" aria-hidden="true">/</span>Report
      </template>
      <template #title>
        <template v-if="repository.data.value">
          <span class="font-normal text-ink-secondary">{{ repository.data.value.owner }}/</span>{{ repository.data.value.name }}
        </template>
        <template v-else>Repository</template>
      </template>
      <template v-if="repository.data.value" #description>
        <span class="inline-flex flex-wrap items-center gap-x-3 gap-y-1">
          <span class="inline-flex items-center gap-1">
            <AppIcon name="branch" :size="13" />
            <span class="mono text-ink-secondary">{{ repository.data.value.defaultBranch }}</span>
          </span>
          <span class="nums">{{ lastScannedText }}</span>
        </span>
      </template>
      <template #actions>
        <RouterLink :to="{ name: 'pull-requests', params: { repoId } }" class="btn btn-secondary">
          <AppIcon name="pull-request" :size="14" />
          Pull requests
        </RouterLink>
        <a
          v-if="repository.data.value && githubUrl(repository.data.value.owner, repository.data.value.name)"
          :href="githubUrl(repository.data.value.owner, repository.data.value.name)"
          target="_blank"
          rel="noopener noreferrer"
          class="btn btn-ghost"
        >
          <AppIcon name="github" :size="14" />
          GitHub
          <AppIcon name="external" :size="12" />
        </a>
      </template>
    </PageHeader>

    <ErrorState v-if="repository.error.value" :error="repository.error.value" @retry="repository.reload" />

    <!-- History stays browsable after access is lost, so say plainly that
         what follows is a record, not the repository's current state. -->
    <div
      v-else-if="repository.data.value && !isAccessible(repository.data.value)"
      role="status"
      class="banner banner-warning"
    >
      <AppIcon name="alert" :size="15" class="mt-0.5" />
      <span>
      <span class="font-semibold">No longer accessible</span>
      · {{ accessLabel(repository.data.value.access) }}<template
        v-if="repository.data.value.accessRevokedAt"
      > on {{ formatDate(repository.data.value.accessRevokedAt) }}</template>.
      The history below is kept, but this repository is no longer scanned.
      </span>
    </div>

    <template v-if="!repository.error.value">
      <!-- One hero figure per view: the risk score. Everything else is a tile. -->
      <div class="grid gap-3 lg:grid-cols-[minmax(240px,1fr)_2fr]">
        <RiskScore
          :score="currentScan.data.value?.enrichedAt ? (currentScan.data.value.riskScore ?? null) : null"
          :delta="currentScan.data.value?.riskDelta ?? null"
          :level="currentScan.data.value?.riskLevel ?? ''"
          :reason="riskReason"
        >
          <button
            v-if="currentScan.data.value?.enrichedAt"
            type="button"
            class="mt-3 inline-flex cursor-pointer items-center gap-1 border-0 bg-transparent p-0 text-xs font-medium text-accent hover:underline"
            :aria-expanded="showExplanation"
            @click="showExplanation = !showExplanation"
          >
            {{ showExplanation ? 'Hide explanation' : 'How is this scored?' }}
          </button>
        </RiskScore>

        <div class="grid grid-cols-2 gap-3 sm:grid-cols-3">
          <StatTile
            label="Components"
            :value="compactNumber(current?.componentCount)"
            :delta="componentDelta !== null && componentDelta !== 0
              ? `${componentDelta > 0 ? '+' : ''}${componentDelta} since previous scan`
              : ''"
            delta-direction="none"
            :note="componentDelta === 0 ? 'Unchanged since previous scan' : ''"
          />
          <StatTile
            label="Changes this week"
            :value="changesThisWeek ?? '—'"
            note="Added, updated and removed"
          />
          <StatTile
            label="Completed scans"
            :value="compactNumber(timeline.data.value?.length ?? 0)"
            note="On the default branch"
          />
        </div>
      </div>

      <RiskExplanation v-if="showExplanation && currentScanId" :scan-id="currentScanId" />

      <DataCard
        title="Dependency drift"
        icon="package"
        subtitle="Changes per scan on the default branch, oldest first"
      >

        <LoadingState v-if="timeline.loading.value" />
        <ErrorState
          v-else-if="timeline.error.value"
          :error="timeline.error.value"
          @retry="timeline.reload"
        />
        <DriftTimeline
          v-else
          :timeline="timeline.data.value ?? []"
          :class="{ 'is-refetching': timeline.refetching.value }"
        />
      </DataCard>

      <DataCard title="Scan history" icon="history" flush subtitle="Includes pull request and backfill scans">
        <div v-if="scans.loading.value" class="p-5"><LoadingState /></div>
        <ErrorState v-else-if="scans.error.value" :error="scans.error.value" @retry="scans.reload" />
        <EmptyState v-else-if="!scans.data.value?.length" title="No scans yet" />

        <div v-else class="overflow-x-auto">
          <table class="data-table min-w-[640px]">
            <thead>
              <tr>
                <th class="pl-4 sm:pl-5">Commit</th>
                <th>Trigger</th>
                <th>Status</th>
                <th class="text-right">Components</th>
                <th>Risk</th>
                <th>When</th>
                <th class="pr-4 sm:pr-5"><span class="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="scan in scans.data.value" :key="scan.id">
                <td class="mono pl-4 text-ink sm:pl-5">{{ shortSha(scan.commitSha) }}</td>
                <td class="text-xs text-ink-secondary capitalize">
                  {{ scanTriggerLabel(scan.trigger) }}
                </td>
                <td><ScanStatusBadge :status="scan.status" /></td>
                <td class="nums text-right text-ink-secondary">
                  {{ scan.status === 'completed' ? scan.componentCount : '—' }}
                </td>
                <td>
                  <RiskBadge v-if="scan.status === 'completed'" :risk="scanRisk(scan)" />
                </td>
                <td class="nums text-xs text-ink-muted">
                  {{ formatDateTime(scan.createdAt) }}
                </td>
                <td class="pr-4 text-right sm:pr-5">
                  <RouterLink :to="{ name: 'scan', params: { scanId: scan.id } }" class="btn btn-ghost btn-sm">
                    View
                  </RouterLink>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </DataCard>
    </template>
  </div>
</template>
