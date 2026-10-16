<script setup>
// Stat tile contract: label (sentence case, no colon), value, optional signed
// delta against a named period. The value uses proportional figures -- tabular
// spacing makes a standalone number read loose at this size.
defineProps({
  label: { type: String, required: true },
  value: { type: [String, Number], default: '—' },
  delta: { type: String, default: '' },
  deltaDirection: {
    type: String,
    default: 'none',
    validator: (value) => ['up-good', 'up-bad', 'down-good', 'down-bad', 'none'].includes(value),
  },
  note: { type: String, default: '' },
  accent: { type: String, default: '' },
})

const DELTA_TONE = {
  'up-good': { color: 'var(--delta-good)', arrow: 'M5 1.5 8.5 6H1.5z' },
  'down-good': { color: 'var(--delta-good)', arrow: 'M5 8.5 1.5 4h7z' },
  'up-bad': { color: 'var(--status-critical)', arrow: 'M5 1.5 8.5 6H1.5z' },
  'down-bad': { color: 'var(--status-critical)', arrow: 'M5 8.5 1.5 4h7z' },
}
</script>

<template>
  <div class="rounded-lg border border-hairline bg-surface px-4 py-3.5">
    <div class="flex items-center gap-1.5">
      <span v-if="accent" class="size-2 shrink-0 rounded-full" :style="{ background: accent }" />
      <p class="m-0 text-xs text-ink-muted">{{ label }}</p>
    </div>

    <p class="mt-1.5 mb-0 text-2xl leading-none font-semibold text-ink">{{ value }}</p>

    <div v-if="delta" class="mt-1.5 flex items-center gap-1">
      <svg
        v-if="DELTA_TONE[deltaDirection]"
        width="10"
        height="10"
        viewBox="0 0 10 10"
        aria-hidden="true"
      >
        <path :d="DELTA_TONE[deltaDirection].arrow" :fill="DELTA_TONE[deltaDirection].color" />
      </svg>
      <span class="nums text-xs text-ink-secondary">{{ delta }}</span>
    </div>

    <p v-else-if="note" class="mt-1.5 mb-0 text-xs text-ink-muted">{{ note }}</p>
  </div>
</template>
