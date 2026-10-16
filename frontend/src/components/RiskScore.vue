<script setup>
import { computed } from 'vue'
import { signedNumber } from '../lib/format.js'

/**
 * The hero figure -- the one number the repository view leads with. Exactly one
 * per view, >=48px, in the same sans as everything else.
 *
 * Risk scoring is Phase 5, so `score` is null today. That is rendered as an
 * explicit "not scored" state rather than a zero: a zero would claim this
 * repository carries no risk, which is a much stronger statement than "we have
 * not computed it".
 */
const props = defineProps({
  score: { type: Number, default: null },
  delta: { type: Number, default: null },
})

const hasScore = computed(() => typeof props.score === 'number' && Number.isFinite(props.score))

// A rising risk score is bad, so the arrow colour follows direction x meaning,
// and an icon carries it alongside the colour.
const deltaTone = computed(() => {
  if (typeof props.delta !== 'number' || props.delta === 0) return null
  return props.delta > 0
    ? { color: 'var(--status-critical)', arrow: 'M6 2 10 7.5H2z', label: 'risk increased' }
    : { color: 'var(--delta-good)', arrow: 'M6 11 2 5.5h8z', label: 'risk decreased' }
})
</script>

<template>
  <div class="rounded-lg border border-hairline bg-surface px-5 py-4">
    <p class="m-0 text-xs text-ink-muted">Supply-chain risk score</p>

    <template v-if="hasScore">
      <p class="mt-1 mb-0 text-5xl leading-none font-semibold tracking-tight text-ink">
        {{ Math.round(score) }}
      </p>
      <div v-if="deltaTone" class="mt-2 flex items-center gap-1.5">
        <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
          <path :d="deltaTone.arrow" :fill="deltaTone.color" />
        </svg>
        <span class="nums text-xs text-ink-secondary">
          {{ signedNumber(delta) }} since the previous scan
        </span>
      </div>
      <p v-else class="mt-2 mb-0 text-xs text-ink-muted">Unchanged since the previous scan</p>
    </template>

    <template v-else>
      <p class="mt-1.5 mb-0 text-xl leading-none font-medium text-ink-secondary">Not scored</p>
      <p class="mt-2 mb-0 max-w-[34ch] text-xs leading-relaxed text-ink-muted">
        Not scored yet. The risk engine lands in Phase&nbsp;5; until then this dashboard
        reports dependency movement, not risk.
      </p>
    </template>
  </div>
</template>
