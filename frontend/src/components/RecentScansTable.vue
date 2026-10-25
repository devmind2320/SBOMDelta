<script setup>
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import { api } from '../api/client.js'
import { useAsyncData } from '../composables/useAsyncData.js'
import { usePolling } from '../composables/usePolling.js'
import { useRepositoryActions } from '../composables/useRepositoryActions.js'
import { compactNumber, scanTriggerLabel, shortSha } from '../lib/format.js'
import { driftLabel, scanRefLabel } from '../lib/intelligence.js'
import { formatScanDate, isActiveScan, viewerTimeZone } from '../lib/repositories.js'
import AppIcon from './AppIcon.vue'
import EmptyState from './EmptyState.vue'
import ErrorState from './ErrorState.vue'
import LoadingState from './LoadingState.vue'
import RiskBadge from './RiskBadge.vue'
import ScanStatusBadge from './ScanStatusBadge.vue'
import VulnSummary from './VulnSummary.vue'

/**
 * Persisted scans of the user's tracked repositories, newest first, across
 * branches and pull requests -- exactly as recorded, failures included (with
 * credentials already removed by the server). compact drops the columns the
 * dashboard preview has no room for.
 */
const props = defineProps({
  limit: { type: Number, default: 50 },
  compact: { type: Boolean, default: false },
})
const emit = defineEmits(['changed'])

const POLL_MS = 5000
const LOOKUP_WAIT_MS = 15 * 60 * 1000
const timeZone = viewerTimeZone()

const recent = useAsyncData(({ signal }) => api.listRecentScans({ limit: props.limit, signal }))
const scans = computed(() => recent.data.value ?? [])

const actions = useRepositoryActions(async () => {
  await recent.reload()
  emit('changed')
})
const { busy, notices } = actions

function awaitingLookup(scan) {
  if (scan?.vulnerabilities?.status !== 'pending' || !scan.finishedAt) return false
  return Date.now() - new Date(scan.finishedAt).getTime() < LOOKUP_WAIT_MS
}
usePolling(() => scans.value.some((scan) => isActiveScan(scan) || awaitingLookup(scan)), recent.reload, POLL_MS)

function when(scan) {
  if (scan.finishedAt) return formatScanDate(scan.finishedAt, timeZone)
  return formatScanDate(scan.createdAt, timeZone)
}
function whenLabel(scan) {
  if (scan.finishedAt) return scan.status === 'failed' ? 'Failed' : 'Finished'
  return 'Queued'
}

defineExpose({ reload: recent.reload })
</script>

<template>
  <div v-if="recent.loading.value" class="p-5"><LoadingState :rows="compact ? 3 : 5" /></div>
  <ErrorState v-else-if="recent.error.value" :error="recent.error.value" @retry="recent.reload" />
  <EmptyState
    v-else-if="!scans.length"
    icon="history"
    title="No scans yet"
    note="Scans of your tracked repositories appear here, newest first, once they are recorded."
  />
  <div v-else class="overflow-x-auto">
    <table class="data-table" :class="compact ? 'min-w-[760px]' : 'min-w-[1080px]'">
      <thead>
        <tr>
          <th class="pl-4 sm:pl-5">Repository</th>
          <th>Commit</th>
          <th>Status</th>
          <th class="text-right">Components</th>
          <th v-if="!compact">Dependency changes</th>
          <th>Vulnerabilities</th>
          <th>Risk</th>
          <th class="pr-4 text-right sm:pr-5">Actions</th>
        </tr>
      </thead>
      <tbody>
        <template v-for="item in scans" :key="item.id">
          <tr>
            <td class="pl-4 sm:pl-5">
              <RouterLink
                :to="{ name: 'repository', params: { repoId: item.repositoryId } }"
                class="font-semibold text-ink no-underline hover:text-accent hover:underline"
              >
                <span class="font-normal text-ink-secondary">{{ item.owner }}/</span>{{ item.name }}
              </RouterLink>
              <div class="mt-0.5 text-[11px] text-ink-muted capitalize">{{ scanTriggerLabel(item.trigger) }}</div>
            </td>
            <td class="text-xs">
              <span class="mono text-ink">{{ shortSha(item.commitSha) }}</span>
              <div class="mt-0.5 flex items-center gap-1 text-[11px] whitespace-nowrap text-ink-muted">
                <AppIcon :name="item.pullRequestId ? 'pull-request' : 'branch'" :size="11" />
                <RouterLink
                  v-if="item.pullRequestId"
                  :to="{ name: 'pull-request', params: { pullId: item.pullRequestId } }"
                  class="text-ink-muted"
                >
                  {{ scanRefLabel(item) }}
                </RouterLink>
                <span v-else class="mono">{{ scanRefLabel(item) }}</span>
              </div>
            </td>
            <td class="text-xs">
              <ScanStatusBadge :status="item.status" />
              <div class="nums mt-1 text-[11px] text-ink-muted" :title="timeZone">
                {{ whenLabel(item) }} {{ when(item) }}
              </div>
            </td>
            <td class="nums text-right text-ink-secondary">
              {{ item.status === 'completed' ? compactNumber(item.componentCount) : '—' }}
            </td>
            <td v-if="!compact" class="text-xs text-ink-secondary">{{ driftLabel(item) }}</td>
            <td><VulnSummary :summary="item.vulnerabilities ?? null" show-changes /></td>
            <td><RiskBadge :risk="item.risk ?? null" /></td>
            <td class="pr-4 sm:pr-5">
              <div class="flex justify-end gap-2">
                <RouterLink :to="{ name: 'scan', params: { scanId: item.id } }" class="btn btn-ghost btn-sm">
                  <AppIcon name="eye" :size="13" />
                  View
                </RouterLink>
                <button
                  type="button"
                  class="btn btn-secondary btn-sm"
                  :disabled="busy.has(item.repositoryId) || isActiveScan(item)"
                  title="Scan the default branch’s latest commit again"
                  @click="actions.scan(item.repositoryId)"
                >
                  <AppIcon
                    :name="busy.has(item.repositoryId) ? 'loader' : 'scan'"
                    :size="13"
                    :class="{ spin: busy.has(item.repositoryId) }"
                  />
                  Scan again
                </button>
              </div>
            </td>
          </tr>
          <tr v-if="(item.status === 'failed' && item.error) || notices[item.repositoryId]">
            <td :colspan="compact ? 7 : 8" class="px-4 pt-0 sm:px-5">
              <p v-if="item.status === 'failed' && item.error" class="banner banner-danger m-0 text-xs">
                <AppIcon name="x-circle" :size="14" class="mt-0.5" />
                <span>Failed: {{ item.error }}</span>
              </p>
              <p
                v-if="notices[item.repositoryId]"
                :role="notices[item.repositoryId].tone === 'danger' ? 'alert' : 'status'"
                class="banner mt-1.5 mb-0 text-xs"
                :class="notices[item.repositoryId].tone === 'danger' ? 'banner-danger' : 'banner-info'"
              >
                {{ notices[item.repositoryId].text }}
              </p>
            </td>
          </tr>
        </template>
      </tbody>
    </table>
  </div>
</template>
