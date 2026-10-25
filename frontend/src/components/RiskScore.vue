<script setup>
import { computed } from 'vue'
import { signedNumber } from '../lib/format.js'

/**
 * The hero figure -- the one number the repository view leads with. Exactly one
 * per view, >=48px, in the same sans as everything else.
 *
 * A scan that has not been checked for vulnerabilities has no score, and that
 * is rendered as an explicit "not scored" state with the reason rather than a
 * zero: a zero would claim this repository carries no known risk, which is a
 * much stronger statement than "we have not computed it".
 */
const props = defineProps({
  score: { type: Number, default: null },
  delta: { type: Number, default: null },
  level: { type: String, default: '' },
  // Why there is no score, shown when score is null.
  reason: { type: String, default: '' },
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
  <div class="card px-5 py-4">
    <p class="eyebrow m-0">Supply-chain risk score</p>

    <template v-if="hasScore">
      <p class="mt-1 mb-0 text-5xl leading-none font-semibold tracking-tight text-ink">
        {{ Number.isInteger(score) ? score : score.toFixed(1) }}
        <span v-if="level" class="text-base font-medium text-ink-secondary capitalize">{{ level }}</span>
      </p>
      <div v-if="deltaTone" class="mt-2 flex items-center gap-1.5">
        <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
          <path :d="deltaTone.arrow" :fill="deltaTone.color" />
        </svg>
        <span class="nums text-xs text-ink-secondary">
          {{ signedNumber(Math.round(delta * 10) / 10) }} since the previous scan
        </span>
      </div>
      <p v-else-if="delta === 0" class="mt-2 mb-0 text-xs text-ink-muted">Unchanged since the previous scan</p>
      <slot />
    </template>

    <template v-else>
      <p class="mt-1.5 mb-0 text-xl leading-none font-medium text-ink-secondary">Not scored</p>
      <p class="mt-2 mb-0 max-w-[34ch] text-xs leading-relaxed text-ink-muted">
        {{ reason || 'The latest scan has not been checked for vulnerabilities yet, so it has no risk score.' }}
      </p>
    </template>
  </div>
</template>
