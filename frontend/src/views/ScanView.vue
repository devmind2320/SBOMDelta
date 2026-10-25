<script setup>
import { computed, ref, toRef, watch } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { api } from '../api/client.js'
import { useAsyncData } from '../composables/useAsyncData.js'
import { compactNumber, formatDateTime, scanTriggerLabel, shortSha } from '../lib/format.js'
import ComponentTable from '../components/ComponentTable.vue'
import DataCard from '../components/DataCard.vue'
import DriftList from '../components/DriftList.vue'
import ErrorState from '../components/ErrorState.vue'
import LicenseMatrix from '../components/LicenseMatrix.vue'
import ScanStatusBadge from '../components/ScanStatusBadge.vue'
import SeverityTiles from '../components/SeverityTiles.vue'
import StatTile from '../components/StatTile.vue'
import VulnerabilityTable from '../components/VulnerabilityTable.vue'

const props = defineProps({ scanId: { type: String, required: true } })
const scanId = toRef(props, 'scanId')

const scan = useAsyncData(({ signal }) => api.getScan(scanId.value, { signal }), {
  watch: [scanId],
})
const drift = useAsyncData(({ signal }) => api.listDriftEvents(scanId.value, { signal }), {
  watch: [scanId],
})
const components = useAsyncData(({ signal }) => api.listComponents(scanId.value, { signal }), {
  watch: [scanId],
})
const vulnerabilities = useAsyncData(
  ({ signal }) => api.listVulnerabilities(scanId.value, { signal }),
  { watch: [scanId] },
)

// The download is a plain navigation, which an expired session would turn
// into a page of raw JSON. Check the session first: a 401 or 403 goes to the
// sign-in page like any other request, and comes back here afterwards.
async function downloadSbom(event) {
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
    return
  }
  event.preventDefault()
  const href = event.currentTarget.href
  try {
    await api.checkSession()
  } catch (error) {
    if (error?.status === 401 || error?.status === 403) return
  }
  window.location.assign(href)
}

// A pending or running scan is a moving target, so poll until it settles
// rather than making the reader refresh. The composable holds the previous
// render during each refetch, so nothing flickers.
let poller = null
watch(
  () => scan.data.value?.status,
  (status) => {
    const inFlight = status === 'pending' || status === 'running'
    if (inFlight && !poller) {
      poller = window.setInterval(() => {
        scan.reload()
        drift.reload()
        components.reload()
      }, 4000)
    } else if (!inFlight && poller) {
      window.clearInterval(poller)
      poller = null
    }
  },
  { immediate: true },
)
watch(scanId, () => {
  if (poller) {
    window.clearInterval(poller)
    poller = null
  }
})

const TABS = [
  { key: 'drift', label: 'Changes' },
  { key: 'components', label: 'Components' },
  { key: 'vulnerabilities', label: 'Vulnerabilities' },
  { key: 'licenses', label: 'Licenses' },
]

// The tab lives in the URL so a link can point at a specific view of a scan --
// "look at the licenses on this commit" is a thing people send each other.
const route = useRoute()
const router = useRouter()
const tab = ref(
  TABS.some((item) => item.key === route.query.tab) ? String(route.query.tab) : 'drift',
)
watch(tab, (next) => {
  router.replace({ query: { ...route.query, tab: next === 'drift' ? undefined : next } })
})

// A scan with no base scan is the repository's baseline, which is a different
// thing from a scan that found no changes.
const isBaseline = computed(
  () => scan.data.value?.status === 'completed' && !scan.data.value?.baseScanId,
)
</script>

<template>
  <div class="flex flex-col gap-6">
    <ErrorState v-if="scan.error.value" :error="scan.error.value" @retry="scan.reload" />
    <p v-else-if="scan.loading.value" class="py-10 text-center text-sm text-ink-muted">Loading…</p>

    <template v-else-if="scan.data.value">
      <div>
        <RouterLink
          :to="{ name: 'repository', params: { repoId: scan.data.value.repositoryId } }"
          class="text-xs text-ink-muted no-underline"
        >
          ← Repository
        </RouterLink>
        <h1 class="nums mt-1.5 mb-0 text-xl font-semibold tracking-tight text-ink">
          {{ shortSha(scan.data.value.commitSha) }}
        </h1>
        <p class="mt-1 mb-0 flex flex-wrap items-center gap-2 text-sm text-ink-muted">
          <ScanStatusBadge :status="scan.data.value.status" />
          <span>{{ scanTriggerLabel(scan.data.value.trigger) }}</span>
          <span>· {{ formatDateTime(scan.data.value.createdAt) }}</span>
          <span v-if="scan.data.value.baseCommitSha">
            · base
            <span class="nums">
              {{ shortSha(scan.data.value.baseCommitSha) }}
            </span>
          </span>
        </p>
      </div>

      <div
        v-if="scan.data.value.status === 'failed'"
        class="rounded-lg border border-hairline bg-surface px-4 py-3"
      >
        <p class="m-0 text-sm font-medium text-ink">This scan failed</p>
        <p class="mt-1 mb-0 text-xs leading-relaxed text-ink-muted">
          A failed scan means the analysis could not run — not that a problem was found.
        </p>
        <pre
          v-if="scan.data.value.error"
          class="mt-2 mb-0 overflow-x-auto rounded border border-hairline bg-surface-raised p-2 text-[11px] leading-relaxed text-ink-secondary"
          >{{ scan.data.value.error }}</pre
        >
      </div>

      <div class="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatTile label="Components" :value="compactNumber(scan.data.value.componentCount)" />
        <StatTile
          label="Added"
          :value="(drift.data.value ?? []).filter((e) => e.changeType === 'added').length"
          accent="var(--series-added)"
        />
        <StatTile
          label="Updated"
          :value="(drift.data.value ?? []).filter((e) => e.changeType === 'updated').length"
          accent="var(--series-updated)"
        />
        <StatTile
          label="Removed"
          :value="(drift.data.value ?? []).filter((e) => e.changeType === 'removed').length"
          accent="var(--series-removed)"
        />
      </div>

      <DataCard title="Scan detail">
        <template #actions>
          <a
            v-if="scan.data.value.sbomLocation"
            :href="api.sbomDownloadUrl(scan.data.value.id)"
            class="rounded-md border border-hairline bg-surface-raised px-2.5 py-1 text-xs text-ink-secondary no-underline"
            @click="downloadSbom"
          >
            Download SBOM
          </a>
        </template>

        <div class="mb-4 flex flex-wrap gap-1 border-b border-hairline">
          <button
            v-for="item in TABS"
            :key="item.key"
            type="button"
            class="-mb-px cursor-pointer border-b-2 px-3 py-2 text-xs"
            :class="
              tab === item.key
                ? 'border-[var(--series-added)] text-ink'
                : 'border-transparent text-ink-muted'
            "
            :aria-pressed="tab === item.key"
            @click="tab = item.key"
          >
            {{ item.label }}
          </button>
        </div>

        <div v-if="tab === 'drift'" :class="{ 'is-refetching': drift.refetching.value }">
          <ErrorState v-if="drift.error.value" :error="drift.error.value" @retry="drift.reload" />
          <DriftList v-else :drift-events="drift.data.value ?? []" :baseline="isBaseline" />
        </div>

        <div v-else-if="tab === 'components'" :class="{ 'is-refetching': components.refetching.value }">
          <ErrorState
            v-if="components.error.value"
            :error="components.error.value"
            @retry="components.reload"
          />
          <ComponentTable v-else :components="components.data.value ?? []" />
        </div>

        <div v-else-if="tab === 'vulnerabilities'">
          <SeverityTiles
            class="mb-4"
            :vulnerabilities="vulnerabilities.data.value?.vulnerabilities ?? []"
            :enrichment-available="vulnerabilities.data.value?.enrichmentAvailable ?? false"
          />
          <VulnerabilityTable
            :vulnerabilities="vulnerabilities.data.value?.vulnerabilities ?? []"
            :enrichment-available="vulnerabilities.data.value?.enrichmentAvailable ?? false"
          />
        </div>

        <div v-else>
          <LicenseMatrix :components="components.data.value ?? []" />
        </div>
      </DataCard>

      <p v-if="scan.data.value.sbomSha256" class="nums m-0 text-xs text-ink-muted">
        SBOM sha256 {{ scan.data.value.sbomSha256.slice(0, 16) }}…
      </p>
    </template>
  </div>
</template>
