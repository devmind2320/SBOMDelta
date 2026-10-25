<script setup>
import { computed } from 'vue'
import { severityCounts, vulnerabilityChangeLabel, vulnerabilityState } from '../lib/intelligence.js'

/**
 * A scan's vulnerability picture in a table cell: severity counts once the
 * scan has been checked, and otherwise an explicit "checking" or
 * "unavailable" -- never a zero standing in for "not looked at".
 */
const props = defineProps({
  summary: { type: Object, default: null },
  showChanges: { type: Boolean, default: false },
})

const state = computed(() => vulnerabilityState(props.summary))
const counts = computed(() => severityCounts(props.summary))
const changes = computed(() => (props.showChanges ? vulnerabilityChangeLabel(props.summary) : ''))

const COLORS = {
  critical: 'var(--status-critical)',
  serious: 'var(--status-serious)',
  warning: 'var(--status-warning)',
  low: 'var(--ink-muted)',
  unknown: 'var(--axis)',
}
</script>

<template>
  <div class="flex flex-col gap-1 text-xs">
    <template v-if="state.key === 'analyzed' && counts.length">
      <div class="flex flex-wrap gap-1">
        <span
          v-for="item in counts"
          :key="item.key"
          class="nums chip gap-1"
          :title="`${item.count} ${item.label}-severity`"
        >
          <svg width="8" height="8" viewBox="0 0 8 8" aria-hidden="true">
            <circle cx="4" cy="4" r="3.5" :fill="COLORS[item.role]" />
          </svg>
          {{ item.count }} {{ item.label }}
        </span>
      </div>
      <span v-if="summary.fixable" class="text-[11px] text-ink-muted">{{ summary.fixable }} fixable</span>
    </template>
    <span v-else-if="state.key === 'analyzed'" class="text-ink-secondary">{{ state.label }}</span>
    <span v-else-if="state.key === 'pending'" class="text-ink-muted">{{ state.label }}</span>
    <span v-else-if="state.key === 'failed'" class="text-ink-secondary" :title="state.error || undefined">
      {{ state.label }}
    </span>
    <span v-else class="text-ink-muted">—</span>
    <span v-if="changes" class="text-[11px] text-ink-muted">{{ changes }}</span>
  </div>
</template>
