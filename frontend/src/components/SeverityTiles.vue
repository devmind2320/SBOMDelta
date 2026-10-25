<script setup>
import { computed } from 'vue'
import { severityRole } from '../lib/format.js'

/**
 * A KPI row of severity counts -- four headline numbers, so stat tiles rather
 * than a grouped bar chart of four single bars.
 *
 * Status colours are reserved for state and always ship with an icon and a
 * written label, because two of the four sit below 3:1 against the light
 * surface by design.
 */
const props = defineProps({
  vulnerabilities: { type: Array, default: () => [] },
  // False until the scan has been checked against OSV. Drives the
  // honest-empty distinction: "nothing found" and "never looked" must not
  // render the same.
  enrichmentAvailable: { type: Boolean, default: false },
  // The API's summary: why the lookup failed, and coverage.
  summary: { type: Object, default: null },
})

const ROLES = [
  { role: 'critical', label: 'Critical', color: 'var(--status-critical)', glyph: 'alert' },
  { role: 'serious', label: 'High', color: 'var(--status-serious)', glyph: 'alert' },
  { role: 'warning', label: 'Medium', color: 'var(--status-warning)', glyph: 'warn' },
  { role: 'low', label: 'Low', color: 'var(--ink-muted)', glyph: 'info' },
]

const counts = computed(() => {
  const tally = { critical: 0, serious: 0, warning: 0, low: 0, unknown: 0 }
  for (const vulnerability of props.vulnerabilities) {
    const role = severityRole(vulnerability.severity)
    tally[role] = (tally[role] ?? 0) + 1
  }
  return tally
})
</script>

<template>
  <div>
    <div class="grid grid-cols-2 gap-3 sm:grid-cols-4">
      <div
        v-for="tile in ROLES"
        :key="tile.role"
        class="card px-3.5 py-3"
      >
        <div class="flex items-center gap-1.5">
          <svg width="11" height="11" viewBox="0 0 11 11" aria-hidden="true">
            <template v-if="tile.glyph === 'alert'">
              <circle cx="5.5" cy="5.5" r="4.5" :fill="tile.color" />
              <path d="M5.5 3v3.1" stroke="var(--surface)" stroke-width="1.4" stroke-linecap="round" />
              <circle cx="5.5" cy="8.1" r="0.75" fill="var(--surface)" />
            </template>
            <template v-else-if="tile.glyph === 'warn'">
              <path d="M5.5 1 10.4 9.7H0.6z" :fill="tile.color" />
              <path d="M5.5 4.2v2.6" stroke="var(--surface)" stroke-width="1.3" stroke-linecap="round" />
              <circle cx="5.5" cy="8.4" r="0.65" fill="var(--surface)" />
            </template>
            <template v-else>
              <circle cx="5.5" cy="5.5" r="4.5" fill="none" :stroke="tile.color" stroke-width="1.4" />
              <path d="M5.5 5v3" :stroke="tile.color" stroke-width="1.4" stroke-linecap="round" />
              <circle cx="5.5" cy="3.2" r="0.7" :fill="tile.color" />
            </template>
          </svg>
          <p class="m-0 text-xs text-ink-muted">{{ tile.label }}</p>
        </div>
        <p
          class="mt-1.5 mb-0 text-2xl leading-none font-semibold"
          :class="enrichmentAvailable ? 'text-ink' : 'text-ink-muted'"
        >
          {{ enrichmentAvailable ? counts[tile.role] : '—' }}
        </p>
      </div>
    </div>

    <p
      v-if="!enrichmentAvailable"
      class="banner banner-warning mt-3 mb-0 block text-xs"
    >
      <template v-if="summary?.status === 'failed'">
        <strong class="font-semibold">Vulnerability check unavailable.</strong>
        {{ summary.error }} It is retried automatically.
      </template>
      <template v-else>
        <strong class="font-semibold">Not analyzed yet.</strong>
        This scan's components have not been checked against OSV.dev yet.
      </template>
      These are dashes rather than zeroes on purpose — a zero here would read as “no known
      vulnerabilities”, which this scan has not established.
    </p>
    <p
      v-else-if="summary?.componentsSkipped > 0"
      class="mt-3 mb-0 text-xs text-ink-muted"
    >
      {{ summary.componentsChecked }} components checked against OSV.dev;
      {{ summary.componentsSkipped }} could not be (no version, or an ecosystem OSV does not cover).
    </p>
    <p
      v-else-if="counts.unknown > 0"
      class="mt-3 mb-0 text-xs text-ink-muted"
    >
      {{ counts.unknown }} advisory(s) carry no severity rating and are excluded from the
      counts above.
    </p>
  </div>
</template>
