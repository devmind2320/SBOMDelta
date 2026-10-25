<script setup>
import { computed, toRef } from 'vue'
import { RouterLink } from 'vue-router'
import { api } from '../api/client.js'
import { useAsyncData } from '../composables/useAsyncData.js'
import { shortSha, signedNumber } from '../lib/format.js'
import { pullRequestVerdict } from '../lib/intelligence.js'
import DataCard from '../components/DataCard.vue'
import DriftList from '../components/DriftList.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LicenseMatrix from '../components/LicenseMatrix.vue'
import RiskExplanation from '../components/RiskExplanation.vue'
import AppIcon from '../components/AppIcon.vue'
import LoadingState from '../components/LoadingState.vue'
import PageHeader from '../components/PageHeader.vue'
import ScanStatusBadge from '../components/ScanStatusBadge.vue'
import SeverityPill from '../components/SeverityPill.vue'
import SeverityTiles from '../components/SeverityTiles.vue'
import StatTile from '../components/StatTile.vue'
import VulnerabilityTable from '../components/VulnerabilityTable.vue'

const props = defineProps({ pullId: { type: String, required: true } })
const pullId = toRef(props, 'pullId')

const pull = useAsyncData(({ signal }) => api.getPullRequest(pullId.value, { signal }), {
  watch: [pullId],
})

// Everything below depends on which scan the pull request resolved to, so these
// loaders watch that id and no-op until it exists.
const scanId = computed(() => pull.data.value?.scanId ?? null)

const drift = useAsyncData(
  ({ signal }) => (scanId.value ? api.listDriftEvents(scanId.value, { signal }) : []),
  { watch: [scanId] },
)
const components = useAsyncData(
  ({ signal }) => (scanId.value ? api.listComponents(scanId.value, { signal }) : []),
  { watch: [scanId] },
)
const vulnerabilities = useAsyncData(
  ({ signal }) =>
    scanId.value
      ? api.listVulnerabilities(scanId.value, { signal })
      : { vulnerabilities: [], enrichmentAvailable: false },
  { watch: [scanId] },
)

const changes = useAsyncData(
  ({ signal }) =>
    scanId.value && pull.data.value?.scanStatus === 'completed'
      ? api.getVulnerabilityChanges(scanId.value, { signal })
      : null,
  { watch: [scanId, () => pull.data.value?.scanStatus] },
)

const hasDrift = computed(() => (drift.data.value?.length ?? 0) > 0)

/**
 * The verdict mirrors what the GitHub check run reports (see
 * pullRequestVerdict): critical or high vulnerabilities introduced fail,
 * anything else that moved asks for review, and nothing is claimed about
 * vulnerabilities that have not been looked up.
 */
const verdict = computed(() =>
  pullRequestVerdict({
    scanId: pull.data.value?.scanId,
    scanStatus: pull.data.value?.scanStatus,
    hasDrift: hasDrift.value,
    changes: changes.data.value,
  }),
)

// The verdict surface takes the tone's background; the icon and sentence
// still carry the meaning.
const VERDICT_SURFACES = {
  good: 'border-[var(--tone-success-border)] bg-[var(--tone-success-bg)]',
  warning: 'border-[var(--tone-warning-border)] bg-[var(--tone-warning-bg)]',
  critical: 'border-[var(--tone-danger-border)] bg-[var(--tone-danger-bg)]',
  neutral: 'border-hairline bg-surface',
}

const TONES = {
  good: { color: 'var(--status-good)', glyph: 'check' },
  warning: { color: 'var(--status-warning)', glyph: 'warn' },
  critical: { color: 'var(--status-critical)', glyph: 'cross' },
  neutral: { color: 'var(--ink-muted)', glyph: 'dot' },
}
</script>

<template>
  <div class="flex flex-col gap-6">
    <ErrorState v-if="pull.error.value" :error="pull.error.value" @retry="pull.reload" />
    <div v-else-if="pull.loading.value" class="card p-5"><LoadingState :rows="4" /></div>

    <template v-else-if="pull.data.value">
      <PageHeader>
        <template #eyebrow>
          <RouterLink
            :to="{ name: 'pull-requests', params: { repoId: pull.data.value.repositoryId } }"
            class="text-ink-muted no-underline hover:text-ink"
          >
            Pull requests
          </RouterLink>
          <span class="mx-1.5" aria-hidden="true">/</span>#{{ pull.data.value.number }}
        </template>
        <template #title>
          <span class="nums font-normal text-ink-muted">#{{ pull.data.value.number }}</span>
          {{ pull.data.value.title || 'Untitled pull request' }}
        </template>
        <template #description>
          <span class="flex flex-wrap items-center gap-2">
            <span class="inline-flex items-center gap-1">
              <AppIcon name="user" :size="13" />
              {{ pull.data.value.authorLogin || 'unknown author' }}
            </span>
            <span class="inline-flex items-center gap-1">
              <AppIcon name="pull-request" :size="13" />
              <span class="mono">{{ shortSha(pull.data.value.baseSha) }}</span> →
              <span class="mono">{{ shortSha(pull.data.value.headSha) }}</span>
            </span>
            <ScanStatusBadge v-if="pull.data.value.scanStatus" :status="pull.data.value.scanStatus" />
            <span v-if="pull.data.value.state && pull.data.value.state !== 'open'" class="chip capitalize">
              {{ pull.data.value.state }}
            </span>
          </span>
        </template>
      </PageHeader>

      <!-- Hero: the risk delta is the number this page is about. -->
      <div class="grid gap-3 lg:grid-cols-[minmax(260px,1fr)_2fr]">
        <div class="card px-5 py-4">
          <p class="eyebrow m-0">Risk delta against the base</p>
          <template v-if="typeof pull.data.value.riskDelta === 'number'">
            <p class="mt-1 mb-0 text-5xl leading-none font-semibold tracking-tight text-ink">
              {{ signedNumber(Math.round(pull.data.value.riskDelta * 10) / 10) }}
            </p>
            <p v-if="typeof pull.data.value.riskScore === 'number'" class="mt-2 mb-0 text-xs text-ink-muted">
              Score {{ pull.data.value.riskScore }} ({{ pull.data.value.riskLevel }}) at the head commit
            </p>
          </template>
          <template v-else>
            <p class="mt-1.5 mb-0 text-xl leading-none font-medium text-ink-secondary">
              Not scored
            </p>
            <p class="mt-2 mb-0 max-w-[34ch] text-xs leading-relaxed text-ink-muted">
              <template v-if="pull.data.value.vulnerabilities?.status === 'failed'">
                The vulnerability lookup failed: {{ pull.data.value.vulnerabilities.error }}
              </template>
              <template v-else-if="typeof pull.data.value.riskScore === 'number'">
                The head commit scores {{ pull.data.value.riskScore }} ({{ pull.data.value.riskLevel }}); the
                base commit has no score to compare with yet.
              </template>
              <template v-else>
                This pull request's scan has not been checked for vulnerabilities yet, so there is no risk to
                compare.
              </template>
            </p>
          </template>
        </div>

        <div class="grid grid-cols-3 gap-3">
          <StatTile
            label="Added"
            :value="pull.data.value.added"
            accent="var(--series-added)"
            note="New dependencies"
          />
          <StatTile
            label="Updated"
            :value="pull.data.value.updated"
            accent="var(--series-updated)"
            note="Version changes"
          />
          <StatTile
            label="Removed"
            :value="pull.data.value.removed"
            accent="var(--series-removed)"
            note="Dropped dependencies"
          />
        </div>
      </div>

      <!-- Verdict carries an icon and a sentence, never colour alone. -->
      <div
        class="flex items-start gap-2.5 rounded-xl border px-4 py-3"
        :class="VERDICT_SURFACES[verdict.tone]"
        role="status"
      >
        <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" class="mt-0.5 shrink-0">
          <template v-if="TONES[verdict.tone].glyph === 'check'">
            <circle cx="8" cy="8" r="6.75" fill="none" :stroke="TONES[verdict.tone].color" stroke-width="1.5" />
            <path d="M5 8.4 7 10.4 11 5.8" fill="none" :stroke="TONES[verdict.tone].color" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" />
          </template>
          <template v-else-if="TONES[verdict.tone].glyph === 'warn'">
            <path d="M8 1.5 15 14H1z" :fill="TONES[verdict.tone].color" />
            <path d="M8 6v3.6" stroke="var(--surface)" stroke-width="1.5" stroke-linecap="round" />
            <circle cx="8" cy="11.8" r="0.8" fill="var(--surface)" />
          </template>
          <template v-else-if="TONES[verdict.tone].glyph === 'cross'">
            <circle cx="8" cy="8" r="6.75" fill="none" :stroke="TONES[verdict.tone].color" stroke-width="1.5" />
            <path d="M5.5 5.5l5 5M10.5 5.5l-5 5" :stroke="TONES[verdict.tone].color" stroke-width="1.75" stroke-linecap="round" />
          </template>
          <circle v-else cx="8" cy="8" r="4" :fill="TONES[verdict.tone].color" />
        </svg>
        <div>
          <p class="m-0 text-sm font-medium text-ink">{{ verdict.label }}</p>
          <p class="mt-0.5 mb-0 text-xs leading-relaxed text-ink-muted">{{ verdict.note }}</p>
        </div>
      </div>

      <EmptyState
        v-if="!pull.data.value.scanId"
        tone="pending"
        title="No scan for this pull request"
        note="A scan is created when GitHub delivers an opened or synchronize event. If the pull request is a draft, SBOMDelta waits until it is marked ready for review."
      />

      <template v-else>
        <DataCard title="What this pull request changes" icon="package" subtitle="Compared against its base commit">
          <p v-if="drift.loading.value" class="m-0 py-6 text-center text-sm text-ink-muted">
            Loading…
          </p>
          <ErrorState v-else-if="drift.error.value" :error="drift.error.value" @retry="drift.reload" />
          <DriftList v-else :drift-events="drift.data.value ?? []" />
        </DataCard>

        <DataCard
          title="Vulnerability changes"
          icon="shield-alert"
          subtitle="Advisories this pull request introduces and resolves, compared with its base commit"
        >
          <p v-if="changes.loading.value" class="m-0 py-4 text-center text-sm text-ink-muted">Loading…</p>
          <ErrorState v-else-if="changes.error.value" :error="changes.error.value" @retry="changes.reload" />
          <EmptyState
            v-else-if="!changes.data.value || !changes.data.value.available"
            tone="pending"
            title="No comparison yet"
            :note="changes.data.value?.reason ?? 'The scan has not completed.'"
          />
          <template v-else>
            <p class="mt-0 mb-3 text-sm text-ink-secondary">
              {{ changes.data.value.comparison.introduced.length }} introduced ·
              {{ changes.data.value.comparison.resolved.length }} resolved ·
              {{ changes.data.value.comparison.unchanged }} already present in the base
            </p>
            <template v-for="group in ['introduced', 'resolved']" :key="group">
              <template v-if="changes.data.value.comparison[group].length">
                <p class="mt-3 mb-1.5 text-xs font-medium text-ink-muted capitalize">{{ group }}</p>
                <ul class="m-0 flex list-none flex-col gap-1.5 p-0 text-xs">
                  <li
                    v-for="item in changes.data.value.comparison[group]"
                    :key="`${group}-${item.identity}-${item.osvId}`"
                    class="flex flex-wrap items-center gap-2"
                  >
                    <SeverityPill :severity="item.severity" />
                    <a
                      :href="`https://osv.dev/vulnerability/${encodeURIComponent(item.osvId)}`"
                      target="_blank"
                      rel="noopener noreferrer"
                      class="nums text-ink underline decoration-hairline"
                    >
                      {{ item.osvId }}
                    </a>
                    <span class="text-ink-secondary">{{ item.package }} {{ item.version }}</span>
                    <span v-if="group === 'introduced'" class="text-ink-muted">
                      {{ item.fixedVersion ? `fixed in ${item.fixedVersion}` : 'no fix published' }}
                    </span>
                  </li>
                </ul>
              </template>
            </template>
          </template>
        </DataCard>

        <RiskExplanation v-if="pull.data.value.scanStatus === 'completed'" :scan-id="pull.data.value.scanId" />

        <DataCard title="Vulnerabilities" icon="shield" subtitle="All advisories affecting this pull request's dependencies">
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
        </DataCard>

        <DataCard title="Licenses" subtitle="What the SBOM declares for this commit">
          <p v-if="components.loading.value" class="m-0 py-6 text-center text-sm text-ink-muted">
            Loading…
          </p>
          <ErrorState
            v-else-if="components.error.value"
            :error="components.error.value"
            @retry="components.reload"
          />
          <LicenseMatrix v-else :components="components.data.value ?? []" />
        </DataCard>
      </template>
    </template>
  </div>
</template>
