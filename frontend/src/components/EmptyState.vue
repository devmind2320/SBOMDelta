<script setup>
import AppIcon from './AppIcon.vue'

// Used for both "nothing here yet" and "not analyzed yet". The distinction
// matters: an empty vulnerability table must never be mistaken for a clean
// bill of health, so callers pass an explicit note and the pending tone.
defineProps({
  title: { type: String, required: true },
  note: { type: String, default: '' },
  icon: { type: String, default: '' },
  tone: {
    type: String,
    default: 'neutral',
    validator: (value) => ['neutral', 'pending'].includes(value),
  },
})
</script>

<template>
  <div class="flex flex-col items-center gap-2 px-4 py-10 text-center">
    <span
      class="mb-1 flex size-10 items-center justify-center rounded-xl border border-hairline bg-surface-raised text-ink-muted"
    >
      <AppIcon :name="icon || (tone === 'pending' ? 'clock' : 'inbox')" :size="18" />
    </span>
    <p class="m-0 text-sm font-semibold text-ink">{{ title }}</p>
    <p v-if="note" class="m-0 max-w-[52ch] text-[13px] leading-relaxed text-ink-muted">{{ note }}</p>
    <slot />
  </div>
</template>
