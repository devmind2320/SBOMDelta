<script setup>
import { computed } from 'vue'
import { riskState } from '../lib/intelligence.js'

/** A risk score and level for a list cell. Unscored scans say so. */
const props = defineProps({
  risk: { type: Object, default: null },
})

const state = computed(() => riskState(props.risk))

const TONES = {
  good: 'var(--status-good)',
  low: 'var(--ink-muted)',
  warning: 'var(--status-warning)',
  serious: 'var(--status-serious)',
  critical: 'var(--status-critical)',
  neutral: 'var(--axis)',
}

const CHIPS = {
  good: 'chip-success',
  low: '',
  warning: 'chip-warning',
  serious: 'chip-warning',
  critical: 'chip-danger',
  neutral: '',
}
</script>

<template>
  <div class="flex flex-col gap-0.5 text-xs">
    <span v-if="state.scored" class="chip w-fit gap-1.5" :class="CHIPS[state.tone]">
      <svg width="8" height="8" viewBox="0 0 9 9" aria-hidden="true">
        <rect x="0.5" y="0.5" width="8" height="8" rx="2" :fill="TONES[state.tone]" />
      </svg>
      <span class="nums font-semibold">{{ state.score }}</span>
      <span>{{ state.label }}</span>
    </span>
    <span v-else class="text-ink-muted">{{ state.label }}</span>
    <span v-if="state.delta" class="nums text-[11px] text-ink-muted">{{ state.delta }}</span>
  </div>
</template>
