<script setup>
import { computed, toRef } from 'vue'
import { RouterLink } from 'vue-router'
import { api } from '../api/client.js'
import { useAsyncData } from '../composables/useAsyncData.js'
import {
  accessLabel,
  compactNumber,
  formatDate,
  formatDateTime,
  isAccessible,
  relativeTime,
  scanTriggerLabel,
  shortSha,
} from '../lib/format.js'
import DataCard from '../components/DataCard.vue'
import DriftTimeline from '../components/DriftTimeline.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import RiskScore from '../components/RiskScore.vue'
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
    <div>
      <RouterLink
        :to="{ name: 'repositories' }"
        class="text-xs text-ink-muted no-underline"
      >
        ← Repositories
      </RouterLink>
      <h1 class="mt-1.5 mb-0 text-xl font-semibold tracking-tight text-ink">
        <template v-if="repository.data.value">
          {{ repository.data.value.owner }}/{{ repository.data.value.name }}
        </template>
        <template v-else>Repository</template>
      </h1>
      <p v-if="repository.data.value" class="mt-1 mb-0 text-sm text-ink-muted">
        Tracking <span class="text-ink-secondary">{{ repository.data.value.defaultBranch }}</span>
        · last scan {{ current ? relativeTime(current.createdAt) : 'never' }}
      </p>
    </div>

    <ErrorState v-if="repository.error.value" :error="repository.error.value" @retry="repository.reload" />

    <!-- History stays browsable after access is lost, so say plainly that
         what follows is a record, not the repository's current state. -->
    <div
      v-else-if="repository.data.value && !isAccessible(repository.data.value)"
      role="status"
      class="rounded-lg border border-hairline bg-surface px-4 py-3 text-sm text-ink-secondary"
    >
      <span class="font-medium text-ink">No longer accessible</span>
      · {{ accessLabel(repository.data.value.access) }}<template
        v-if="repository.data.value.accessRevokedAt"
      > on {{ formatDate(repository.data.value.accessRevokedAt) }}</template>.
      The history below is kept, but this repository is no longer scanned.
    </div>

    <template v-if="!repository.error.value">
      <!-- One hero figure per view: the risk score. Everything else is a tile. -->
      <div class="grid gap-3 lg:grid-cols-[minmax(240px,1fr)_2fr]">
        <RiskScore :score="current?.riskScore ?? null" :delta="null" />

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

      <DataCard
        title="Dependency drift"
        subtitle="Changes per scan on the default branch, oldest first"
      >
        <template #actions>
          <RouterLink
            :to="{ name: 'pull-requests', params: { repoId } }"
            class="rounded-md border border-hairline bg-surface-raised px-2.5 py-1 text-xs text-ink-secondary no-underline"
          >
            Pull requests
          </RouterLink>
        </template>

        <p v-if="timeline.loading.value" class="m-0 py-10 text-center text-sm text-ink-muted">
          Loading…
        </p>
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

      <DataCard title="Scan history" subtitle="Includes pull request and backfill scans">
        <p v-if="scans.loading.value" class="m-0 py-6 text-center text-sm text-ink-muted">
          Loading…
        </p>
        <ErrorState v-else-if="scans.error.value" :error="scans.error.value" @retry="scans.reload" />
        <EmptyState v-else-if="!scans.data.value?.length" title="No scans yet" />

        <div v-else class="overflow-x-auto">
          <table class="w-full border-collapse text-sm">
            <thead>
              <tr class="border-b border-hairline text-left">
                <th class="px-2 py-2 text-xs font-medium text-ink-muted">Commit</th>
                <th class="px-2 py-2 text-xs font-medium text-ink-muted">Trigger</th>
                <th class="px-2 py-2 text-xs font-medium text-ink-muted">Status</th>
                <th class="px-2 py-2 text-right text-xs font-medium text-ink-muted">Components</th>
                <th class="px-2 py-2 text-xs font-medium text-ink-muted">When</th>
                <th class="px-2 py-2"></th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="scan in scans.data.value"
                :key="scan.id"
                class="border-b border-hairline last:border-0"
              >
                <td class="nums px-2 py-2 text-ink">{{ shortSha(scan.commitSha) }}</td>
                <td class="px-2 py-2 text-xs text-ink-secondary">
                  {{ scanTriggerLabel(scan.trigger) }}
                </td>
                <td class="px-2 py-2"><ScanStatusBadge :status="scan.status" /></td>
                <td class="nums px-2 py-2 text-right text-ink-secondary">
                  {{ scan.componentCount }}
                </td>
                <td class="px-2 py-2 text-xs text-ink-muted">
                  {{ formatDateTime(scan.createdAt) }}
                </td>
                <td class="px-2 py-2 text-right">
                  <RouterLink
                    :to="{ name: 'scan', params: { scanId: scan.id } }"
                    class="text-xs text-ink-secondary underline decoration-hairline"
                  >
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
