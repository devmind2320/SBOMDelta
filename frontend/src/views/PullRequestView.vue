<script setup>
import { computed, toRef } from 'vue'
import { RouterLink } from 'vue-router'
import { api } from '../api/client.js'
import { useAsyncData } from '../composables/useAsyncData.js'
import { shortSha, signedNumber } from '../lib/format.js'
import DataCard from '../components/DataCard.vue'
import DriftList from '../components/DriftList.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LicenseMatrix from '../components/LicenseMatrix.vue'
import ScanStatusBadge from '../components/ScanStatusBadge.vue'
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

const hasDrift = computed(() => (drift.data.value?.length ?? 0) > 0)

/**
 * The verdict mirrors what the GitHub check run actually reports, and nothing
 * more. Drift is "review" rather than "block" because there is no risk model
 * yet to justify blocking a merge -- and a check that blocks on any dependency
 * change is a check people learn to ignore.
 */
const verdict = computed(() => {
  if (!pull.data.value?.scanId) {
    return { label: 'Not scanned', tone: 'neutral', note: 'No scan has run for this pull request yet.' }
  }
  if (pull.data.value.scanStatus === 'failed') {
    return {
      label: 'Scan failed',
      tone: 'critical',
      note: 'SBOMDelta could not analyze this commit. This reports a broken scan, not a security finding.',
    }
  }
  if (pull.data.value.scanStatus !== 'completed') {
    return { label: 'In progress', tone: 'neutral', note: 'The scan is still running.' }
  }
  if (!hasDrift.value) {
    return {
      label: 'No dependency changes',
      tone: 'good',
      note: 'This pull request does not alter the dependency set.',
    }
  }
  return {
    label: 'Review dependency changes',
    tone: 'warning',
    note: 'Dependencies moved. Blocking decisions need the risk policy from Phase 5.',
  }
})

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
    <p v-else-if="pull.loading.value" class="py-10 text-center text-sm text-ink-muted">Loading…</p>

    <template v-else-if="pull.data.value">
      <div>
        <RouterLink
          :to="{ name: 'pull-requests', params: { repoId: pull.data.value.repositoryId } }"
          class="text-xs text-ink-muted no-underline"
        >
          ← Pull requests
        </RouterLink>
        <h1 class="mt-1.5 mb-0 text-xl font-semibold tracking-tight text-ink">
          <span class="nums text-ink-muted">#{{ pull.data.value.number }}</span>
          {{ pull.data.value.title || 'Untitled pull request' }}
        </h1>
        <p class="mt-1 mb-0 text-sm text-ink-muted">
          {{ pull.data.value.authorLogin || 'unknown author' }} ·
          <span class="nums">{{ shortSha(pull.data.value.baseSha) }}</span> →
          <span class="nums">{{ shortSha(pull.data.value.headSha) }}</span>
          <template v-if="pull.data.value.scanStatus">
            · <ScanStatusBadge :status="pull.data.value.scanStatus" />
          </template>
        </p>
      </div>

      <!-- Hero: the risk delta is the number this page is about. -->
      <div class="grid gap-3 lg:grid-cols-[minmax(260px,1fr)_2fr]">
        <div class="rounded-lg border border-hairline bg-surface px-5 py-4">
          <p class="m-0 text-xs text-ink-muted">Risk delta</p>
          <template v-if="typeof pull.data.value.riskDelta === 'number'">
            <p class="mt-1 mb-0 text-5xl leading-none font-semibold tracking-tight text-ink">
              {{ signedNumber(pull.data.value.riskDelta) }}
            </p>
          </template>
          <template v-else>
            <p class="mt-1.5 mb-0 text-xl leading-none font-medium text-ink-secondary">
              Not scored
            </p>
            <p class="mt-2 mb-0 max-w-[34ch] text-xs leading-relaxed text-ink-muted">
              Not scored. The risk engine is Phase&nbsp;5 — this page reports the dependency
              changes it would score.
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
      <div class="flex items-start gap-2.5 rounded-lg border border-hairline bg-surface px-4 py-3">
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
        <DataCard title="What this pull request changes" subtitle="Compared against its base commit">
          <p v-if="drift.loading.value" class="m-0 py-6 text-center text-sm text-ink-muted">
            Loading…
          </p>
          <ErrorState v-else-if="drift.error.value" :error="drift.error.value" @retry="drift.reload" />
          <DriftList v-else :drift-events="drift.data.value ?? []" />
        </DataCard>

        <DataCard title="Vulnerabilities" subtitle="Advisories affecting this pull request's dependencies">
          <SeverityTiles
            class="mb-4"
            :vulnerabilities="vulnerabilities.data.value?.vulnerabilities ?? []"
            :enrichment-available="vulnerabilities.data.value?.enrichmentAvailable ?? false"
          />
          <VulnerabilityTable
            :vulnerabilities="vulnerabilities.data.value?.vulnerabilities ?? []"
            :enrichment-available="vulnerabilities.data.value?.enrichmentAvailable ?? false"
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
