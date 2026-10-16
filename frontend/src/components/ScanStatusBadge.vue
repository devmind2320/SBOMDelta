<script setup>
import { computed } from 'vue'

const props = defineProps({
  status: { type: String, default: '' },
})

// Each state ships a shape as well as a colour, so the badge survives
// greyscale printing and colour-vision deficiency.
const STATES = {
  completed: { label: 'Completed', color: 'var(--status-good)', glyph: 'check' },
  running: { label: 'Running', color: 'var(--series-added)', glyph: 'spinner' },
  pending: { label: 'Queued', color: 'var(--ink-muted)', glyph: 'dot' },
  failed: { label: 'Failed', color: 'var(--status-critical)', glyph: 'cross' },
}

const state = computed(() => STATES[props.status] ?? {
  label: props.status || 'Unknown',
  color: 'var(--ink-muted)',
  glyph: 'dot',
})
</script>

<template>
  <span
    class="inline-flex items-center gap-1.5 rounded-full border border-hairline px-2 py-0.5 text-xs text-ink-secondary"
  >
    <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
      <path
        v-if="state.glyph === 'check'"
        d="M2 5.4 4 7.4 8 3"
        fill="none"
        :stroke="state.color"
        stroke-width="1.75"
        stroke-linecap="round"
        stroke-linejoin="round"
      />
      <path
        v-else-if="state.glyph === 'cross'"
        d="M2.6 2.6l4.8 4.8M7.4 2.6 2.6 7.4"
        fill="none"
        :stroke="state.color"
        stroke-width="1.75"
        stroke-linecap="round"
      />
      <g v-else-if="state.glyph === 'spinner'">
        <circle cx="5" cy="5" r="3.5" fill="none" :stroke="state.color" stroke-width="1.5" opacity="0.3" />
        <path
          d="M5 1.5A3.5 3.5 0 0 1 8.5 5"
          fill="none"
          :stroke="state.color"
          stroke-width="1.5"
          stroke-linecap="round"
        />
      </g>
      <circle v-else cx="5" cy="5" r="3" :fill="state.color" />
    </svg>
    {{ state.label }}
  </span>
</template>
