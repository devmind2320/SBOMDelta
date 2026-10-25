<script setup>
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { api } from '../api/client.js'
import { useAsyncData } from '../composables/useAsyncData.js'
import { shortSha } from '../lib/format.js'
import DataCard from '../components/DataCard.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import SeverityPill from '../components/SeverityPill.vue'
import AppIcon from '../components/AppIcon.vue'
import LoadingState from '../components/LoadingState.vue'
import MetricCard from '../components/MetricCard.vue'
import PageHeader from '../components/PageHeader.vue'

// Multi-repository impact: which of your tracked repositories an advisory or
// a dependency reaches, at each repository's latest default-branch scan.

const vulnerabilities = useAsyncData(({ signal }) => api.impactVulnerabilities({ signal }))
const vulnRows = computed(() => vulnerabilities.data.value?.vulnerabilities ?? [])
const coverage = computed(() => vulnerabilities.data.value?.coverage ?? null)
const expanded = ref(new Set())

function toggle(osvId) {
  const next = new Set(expanded.value)
  if (next.has(osvId)) next.delete(osvId)
  else next.add(osvId)
  expanded.value = next
}

const search = ref('')
const query = ref('')
let debounce = null
watch(search, (value) => {
  clearTimeout(debounce)
  debounce = setTimeout(() => {
    query.value = value.trim()
  }, 300)
})
onBeforeUnmount(() => clearTimeout(debounce))

const components = useAsyncData(
  ({ signal }) => (query.value.length >= 2 ? api.impactComponents(query.value, { signal }) : null),
  { watch: [query] },
)
const componentRows = computed(() => components.data.value?.components ?? [])

// Headline counts, straight from the rows the API returned.
const affectedRepositories = computed(() => {
  const ids = new Set()
  for (const vuln of vulnRows.value) for (const o of vuln.occurrences ?? []) ids.add(`${o.owner}/${o.name}`)
  return ids.size
})
const blockingCount = computed(
  () => vulnRows.value.filter((v) => ['CRITICAL', 'HIGH'].includes(String(v.severity ?? '').toUpperCase())).length,
)
const sharedCount = computed(() => vulnRows.value.filter((v) => v.repositoryCount > 1).length)

const coverageNote = computed(() => {
  const c = coverage.value
  if (!c) return ''
  if (c.repositories === 0) return ''
  const gaps = []
  const unscanned = c.repositories - c.scanned
  const unanalyzed = c.scanned - c.analyzed
  if (unscanned > 0) gaps.push(`${unscanned} ${unscanned === 1 ? 'has' : 'have'} no completed scan`)
  if (unanalyzed > 0) gaps.push(`${unanalyzed} ${unanalyzed === 1 ? 'has' : 'have'} not been checked for vulnerabilities yet`)
  const base = `Covers the latest scan of ${c.analyzed} of your ${c.repositories} tracked repositories.`
  return gaps.length ? `${base} Of the rest, ${gaps.join(' and ')}, so ${unscanned + unanalyzed === 1 ? 'it' : 'they'} cannot appear here.` : base
})
</script>

<template>
  <div class="flex flex-col gap-6 sm:gap-8">
    <PageHeader
      eyebrow="Investigation"
      title="Impact across repositories"
      description="Which of your tracked repositories a vulnerability or a dependency reaches, at each one's latest completed default-branch scan."
    />

    <section aria-label="Impact summary" class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <MetricCard
        label="Advisories found"
        icon="shield-alert"
        :loading="vulnerabilities.loading.value"
        :value="coverage && coverage.analyzed ? vulnRows.length : '—'"
        :muted="!coverage || !coverage.analyzed"
        :tone="blockingCount ? 'danger' : vulnRows.length ? 'warning' : 'neutral'"
      >
        {{ coverage && coverage.analyzed ? `${blockingCount} critical or high` : 'Nothing analyzed yet' }}
      </MetricCard>
      <MetricCard
        label="Shared advisories"
        icon="impact"
        :loading="vulnerabilities.loading.value"
        :value="coverage && coverage.analyzed ? sharedCount : '—'"
        :muted="!coverage || !coverage.analyzed"
      >
        Affecting more than one repository
      </MetricCard>
      <MetricCard
        label="Affected repositories"
        icon="repo"
        :loading="vulnerabilities.loading.value"
        :value="coverage && coverage.analyzed ? affectedRepositories : '—'"
        :muted="!coverage || !coverage.analyzed"
      >
        With at least one known vulnerability
      </MetricCard>
      <MetricCard
        label="Coverage"
        icon="check-circle"
        :loading="vulnerabilities.loading.value"
        :value="coverage ? `${coverage.analyzed}/${coverage.repositories}` : '—'"
        :muted="!coverage"
        :tone="coverage && coverage.repositories && coverage.analyzed < coverage.repositories ? 'warning' : 'neutral'"
      >
        Tracked repositories analyzed
      </MetricCard>
    </section>

    <DataCard
      title="Vulnerabilities across tracked repositories"
      icon="shield-alert"
      flush
      subtitle="Most severe first, then by how many repositories they affect"
    >
      <div v-if="vulnerabilities.loading.value" class="p-5"><LoadingState :rows="4" /></div>
      <ErrorState
        v-else-if="vulnerabilities.error.value"
        :error="vulnerabilities.error.value"
        @retry="vulnerabilities.reload"
      />
      <template v-else>
        <div v-if="coverageNote" class="px-4 pt-4 sm:px-5">
          <p
            class="banner m-0"
            :class="coverage && coverage.analyzed < coverage.repositories ? 'banner-warning' : 'banner-info'"
            role="note"
          >
            <AppIcon name="info" :size="15" class="mt-0.5" />
            <span>{{ coverageNote }}</span>
          </p>
        </div>
        <EmptyState
          v-if="coverage && coverage.repositories === 0"
          icon="bookmark"
          title="No tracked repositories"
          note="Track repositories on the dashboard to see which of them a vulnerability affects."
        />
        <EmptyState
          v-else-if="coverage && coverage.analyzed === 0"
          tone="pending"
          title="Nothing analyzed yet"
          note="None of your tracked repositories has a scan checked for vulnerabilities yet, so there is nothing to compare."
        />
        <EmptyState
          v-else-if="!vulnRows.length"
          icon="check-circle"
          title="No known vulnerabilities"
          note="None of the analyzed latest scans contains a component with a published advisory."
        />
        <div v-else class="mt-4 overflow-x-auto border-t border-hairline">
          <table class="data-table min-w-[820px]">
            <thead>
              <tr>
                <th class="pl-4 sm:pl-5">Severity</th>
                <th>Advisory</th>
                <th>Summary</th>
                <th class="text-right">Repositories</th>
                <th class="pr-4 sm:pr-5"><span class="sr-only">Details</span></th>
              </tr>
            </thead>
            <tbody>
              <template v-for="vuln in vulnRows" :key="vuln.osvId">
                <tr>
                  <td class="pl-4 sm:pl-5"><SeverityPill :severity="vuln.severity" /></td>
                  <td class="text-xs">
                    <a
                      :href="vuln.advisoryUrl || `https://osv.dev/vulnerability/${encodeURIComponent(vuln.osvId)}`"
                      target="_blank"
                      rel="noopener noreferrer"
                      class="link mono inline-flex items-center gap-1"
                    >
                      {{ vuln.osvId }}
                      <AppIcon name="external" :size="11" />
                    </a>
                    <div v-if="vuln.aliases?.length" class="mono mt-0.5 text-[11px] text-ink-muted">
                      {{ vuln.aliases.slice(0, 2).join(', ') }}
                    </div>
                  </td>
                  <td class="max-w-[52ch] text-xs leading-relaxed text-ink-secondary">
                    {{ vuln.summary || '—' }}
                  </td>
                  <td class="nums text-right text-sm font-semibold text-ink">
                    {{ vuln.repositoryCount }}
                    <span v-if="vuln.repositoryCount > 1" class="chip chip-info ml-1 font-medium">shared</span>
                  </td>
                  <td class="pr-4 text-right sm:pr-5">
                    <button
                      type="button"
                      class="btn btn-ghost btn-sm"
                      :aria-expanded="expanded.has(vuln.osvId)"
                      :aria-controls="`affected-${vuln.osvId}`"
                      @click="toggle(vuln.osvId)"
                    >
                      {{ expanded.has(vuln.osvId) ? 'Hide' : 'Show' }} affected
                      <AppIcon
                        name="chevron-down"
                        :size="13"
                        class="transition-transform"
                        :class="{ 'rotate-180': expanded.has(vuln.osvId) }"
                      />
                    </button>
                  </td>
                </tr>
                <tr v-if="expanded.has(vuln.osvId)" :id="`affected-${vuln.osvId}`">
                  <td colspan="5" class="bg-surface-raised px-4 sm:px-5">
                    <ul class="m-0 grid list-none gap-2 p-0 text-xs md:grid-cols-2">
                      <li
                        v-for="o in vuln.occurrences"
                        :key="`${o.scanId}-${o.purl}`"
                        class="rounded-lg border border-hairline bg-surface px-3 py-2"
                      >
                        <RouterLink
                          :to="{ name: 'scan', params: { scanId: o.scanId }, query: { tab: 'vulnerabilities' } }"
                          class="font-semibold text-ink no-underline hover:text-accent"
                        >
                          <span class="font-normal text-ink-secondary">{{ o.owner }}/</span>{{ o.name }}
                        </RouterLink>
                        <div class="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-ink-secondary">
                          <span class="mono">{{ o.package }} {{ o.version }}</span>
                          <span
                            class="chip"
                            :class="o.fixedVersion ? 'chip-success' : ''"
                          >
                            {{ o.fixedVersion ? `Upgrade to ${o.fixedVersion}` : 'No fix published' }}
                          </span>
                          <span v-if="o.direct" class="chip">Direct dependency</span>
                          <span class="mono text-ink-muted">@ {{ shortSha(o.commitSha) }}</span>
                        </div>
                      </li>
                    </ul>
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>
      </template>
    </DataCard>

    <DataCard
      title="Find a dependency"
      icon="search"
      subtitle="Where a package is used across your tracked repositories, and at which versions"
    >
      <label class="relative mb-4 block w-full max-w-md">
        <span class="sr-only">Package name or package URL</span>
        <AppIcon
          name="search"
          :size="15"
          class="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-ink-muted"
        />
        <input v-model="search" type="search" placeholder="e.g. lodash or pkg:npm/lodash" class="input pl-9" />
      </label>
      <p v-if="query.length < 2" class="m-0 text-xs text-ink-muted">Type at least two characters.</p>
      <LoadingState v-else-if="components.loading.value" :rows="2" label="Searching…" />
      <ErrorState v-else-if="components.error.value" :error="components.error.value" @retry="components.reload" />
      <EmptyState
        v-else-if="!componentRows.length"
        icon="search"
        title="Not found"
        :note="`No tracked repository's latest scan contains a package matching “${query}”.`"
      />
      <ul v-else class="m-0 flex list-none flex-col gap-3 p-0">
        <li v-for="c in componentRows" :key="c.identity" class="rounded-lg border border-hairline">
          <div class="flex flex-wrap items-center gap-2 border-b border-hairline bg-surface-raised px-3 py-2">
            <AppIcon name="package" :size="14" class="text-ink-muted" />
            <span class="text-sm font-semibold text-ink">{{ c.name }}</span>
            <span class="chip">{{ c.ecosystem }}</span>
            <span class="text-xs text-ink-secondary">
              in {{ c.repositoryCount }} {{ c.repositoryCount === 1 ? 'repository' : 'repositories' }} ·
              {{ c.versions.length }} {{ c.versions.length === 1 ? 'version' : 'versions' }}
            </span>
          </div>
          <ul class="m-0 flex list-none flex-col p-0 text-xs">
            <li
              v-for="o in c.occurrences"
              :key="`${o.scanId}-${o.purl}`"
              class="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-hairline px-3 py-2 last:border-0"
            >
              <RouterLink
                :to="{ name: 'scan', params: { scanId: o.scanId }, query: { tab: 'components' } }"
                class="font-medium text-ink no-underline hover:text-accent"
              >
                {{ o.owner }}/{{ o.name }}
              </RouterLink>
              <span class="mono text-ink-secondary">{{ o.version }}</span>
              <span v-if="!o.analyzed" class="chip">Not checked for vulnerabilities yet</span>
              <span v-else-if="o.vulnerabilities" class="chip chip-danger">
                {{ o.vulnerabilities }} known {{ o.vulnerabilities === 1 ? 'vulnerability' : 'vulnerabilities' }}
              </span>
              <span v-else class="chip chip-success">No known vulnerabilities</span>
              <span v-if="o.direct" class="chip">Direct dependency</span>
            </li>
          </ul>
        </li>
      </ul>
    </DataCard>
  </div>
</template>
