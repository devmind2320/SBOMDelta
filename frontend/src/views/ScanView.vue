<script setup>
import { computed, ref, toRef, watch } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { api } from '../api/client.js'
import { useAsyncData } from '../composables/useAsyncData.js'
import { compactNumber, scanTriggerLabel, shortSha } from '../lib/format.js'
import { formatScanDate } from '../lib/repositories.js'
import AppIcon from '../components/AppIcon.vue'
import LoadingState from '../components/LoadingState.vue'
import PageHeader from '../components/PageHeader.vue'
import ComponentTable from '../components/ComponentTable.vue'
import DataCard from '../components/DataCard.vue'
import DriftList from '../components/DriftList.vue'
import ErrorState from '../components/ErrorState.vue'
import LicenseMatrix from '../components/LicenseMatrix.vue'
import RiskExplanation from '../components/RiskExplanation.vue'
import ScanStatusBadge from '../components/ScanStatusBadge.vue'
import SeverityPill from '../components/SeverityPill.vue'
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
const changes = useAsyncData(({ signal }) => api.getVulnerabilityChanges(scanId.value, { signal }), {
  watch: [scanId],
})

// The vulnerability lookup finishes after the scan does; when it lands (or
// fails), refresh what depends on it.
watch(
  () => [scan.data.value?.enrichedAt, scan.data.value?.enrichmentError],
  (now, before) => {
    if (before && (now[0] !== before[0] || now[1] !== before[1])) {
      vulnerabilities.reload()
      changes.reload()
    }
  },
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
// rather than making the reader refresh -- and keep polling briefly after it
// completes, until its vulnerability lookup lands. The composable holds the
// previous render during each refetch, so nothing flickers.
const LOOKUP_WAIT_MS = 15 * 60 * 1000
let poller = null
watch(
  () => {
    const current = scan.data.value
    if (!current) return false
    if (current.status === 'pending' || current.status === 'running') return true
    return (
      current.status === 'completed' &&
      !current.enrichedAt &&
      !current.enrichmentError &&
      Date.now() - new Date(current.finishedAt ?? current.createdAt).getTime() < LOOKUP_WAIT_MS
    )
  },
  (inFlight) => {
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
    <div v-else-if="scan.loading.value" class="card p-5"><LoadingState :rows="4" /></div>

    <template v-else-if="scan.data.value">
      <PageHeader>
        <template #eyebrow>
          <RouterLink
            :to="{ name: 'repository', params: { repoId: scan.data.value.repositoryId } }"
            class="text-ink-muted no-underline hover:text-ink"
          >
            Repository report
          </RouterLink>
          <span class="mx-1.5" aria-hidden="true">/</span>Scan
        </template>
        <template #title>
          <span class="inline-flex items-center gap-2">
            <AppIcon name="commit" :size="22" class="text-ink-muted" />
            <span class="mono">{{ shortSha(scan.data.value.commitSha) }}</span>
          </span>
        </template>
        <template #description>
          <span class="flex flex-wrap items-center gap-2">
            <ScanStatusBadge :status="scan.data.value.status" />
            <span class="capitalize">{{ scanTriggerLabel(scan.data.value.trigger) }}</span>
            <span class="nums">· {{ formatScanDate(scan.data.value.finishedAt ?? scan.data.value.createdAt) }}</span>
            <span v-if="scan.data.value.baseCommitSha">
              · compared with <span class="mono">{{ shortSha(scan.data.value.baseCommitSha) }}</span>
            </span>
          </span>
        </template>
        <template #actions>
          <a
            v-if="scan.data.value.sbomLocation"
            :href="api.sbomDownloadUrl(scan.data.value.id)"
            class="btn btn-secondary"
            @click="downloadSbom"
          >
            <AppIcon name="download" :size="14" />
            Download SBOM
          </a>
        </template>
      </PageHeader>

      <div v-if="scan.data.value.status === 'failed'" class="banner banner-danger" role="status">
        <AppIcon name="x-circle" :size="16" class="mt-0.5" />
        <div class="min-w-0 flex-1">
          <p class="m-0 font-semibold">This scan failed</p>
          <p class="mt-0.5 mb-0 text-xs leading-relaxed">
            A failed scan means the analysis could not run, not that a problem was found.
          </p>
          <pre
            v-if="scan.data.value.error"
            class="mono mt-2 mb-0 overflow-x-auto rounded-md border border-hairline bg-surface p-2 text-[11px] leading-relaxed text-ink-secondary"
            >{{ scan.data.value.error }}</pre
          >
        </div>
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

      <div v-if="scan.data.value.status === 'completed'" class="grid gap-3 lg:grid-cols-2">
        <RiskExplanation :scan-id="scan.data.value.id" />
        <div class="card px-4 py-3 text-xs">
          <p class="m-0 text-sm font-semibold text-ink">Vulnerability changes against the base scan</p>
          <p v-if="changes.loading.value" class="mt-1 mb-0 text-ink-muted">Loading…</p>
          <ErrorState v-else-if="changes.error.value" :error="changes.error.value" @retry="changes.reload" />
          <p v-else-if="changes.data.value && !changes.data.value.available" class="mt-1 mb-0 text-ink-secondary">
            {{ changes.data.value.reason }}
          </p>
          <template v-else-if="changes.data.value">
            <p class="mt-1 mb-0 text-ink-secondary">
              {{ changes.data.value.comparison.introduced.length }} introduced ·
              {{ changes.data.value.comparison.resolved.length }} resolved ·
              {{ changes.data.value.comparison.unchanged }} unchanged
            </p>
            <template v-for="group in ['introduced', 'resolved']" :key="group">
              <template v-if="changes.data.value.comparison[group].length">
                <p class="mt-2 mb-1 text-ink-muted capitalize">{{ group }}</p>
                <ul class="m-0 flex list-none flex-col gap-1 p-0">
                  <li
                    v-for="item in changes.data.value.comparison[group].slice(0, 20)"
                    :key="`${group}-${item.identity}-${item.osvId}`"
                    class="flex flex-wrap items-center gap-2"
                  >
                    <SeverityPill :severity="item.severity" />
                    <span class="nums text-ink">{{ item.osvId }}</span>
                    <span class="text-ink-secondary">{{ item.package }} {{ item.version }}</span>
                    <span v-if="group === 'introduced'" class="text-ink-muted">
                      {{ item.fixedVersion ? `fixed in ${item.fixedVersion}` : 'no fix published' }}
                    </span>
                  </li>
                </ul>
              </template>
            </template>
          </template>
        </div>
      </div>

      <DataCard title="Scan detail" icon="package">

        <div class="mb-4 flex gap-1 overflow-x-auto border-b border-hairline">
          <button
            v-for="item in TABS"
            :key="item.key"
            type="button"
            class="-mb-px shrink-0 cursor-pointer border-x-0 border-t-0 border-b-2 bg-transparent px-3 py-2 text-[13px] font-medium transition-colors"
            :class="
              tab === item.key
                ? 'border-accent-solid text-ink'
                : 'border-transparent text-ink-muted hover:text-ink'
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
          <ErrorState
            v-if="vulnerabilities.error.value"
            :error="vulnerabilities.error.value"
            @retry="vulnerabilities.reload"
          />
          <template v-else>
            <SeverityTiles
              class="mb-4"
              :vulnerabilities="vulnerabilities.data.value?.vulnerabilities ?? []"
              :enrichment-available="vulnerabilities.data.value?.enrichmentAvailable ?? false"
              :summary="vulnerabilities.data.value?.summary ?? null"
            />
            <VulnerabilityTable
              :vulnerabilities="vulnerabilities.data.value?.vulnerabilities ?? []"
              :enrichment-available="vulnerabilities.data.value?.enrichmentAvailable ?? false"
              :summary="vulnerabilities.data.value?.summary ?? null"
            />
          </template>
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
