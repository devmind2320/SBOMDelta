<script setup>
// Used for both "nothing here yet" and "this feature is not built yet". The
// distinction matters: an empty vulnerability table must never be mistaken for
// a clean bill of health, so callers pass an explicit note.
defineProps({
  title: { type: String, required: true },
  note: { type: String, default: '' },
  tone: {
    type: String,
    default: 'neutral',
    validator: (value) => ['neutral', 'pending'].includes(value),
  },
})
</script>

<template>
  <div class="flex flex-col items-center gap-2 px-4 py-10 text-center">
    <svg
      v-if="tone === 'pending'"
      width="22"
      height="22"
      viewBox="0 0 22 22"
      aria-hidden="true"
      class="opacity-70"
    >
      <circle cx="11" cy="11" r="8.25" fill="none" stroke="var(--axis)" stroke-width="1.5" />
      <path
        d="M11 6.5V11l3 2"
        fill="none"
        stroke="var(--ink-muted)"
        stroke-width="1.5"
        stroke-linecap="round"
      />
    </svg>
    <svg v-else width="22" height="22" viewBox="0 0 22 22" aria-hidden="true" class="opacity-70">
      <rect
        x="3.75"
        y="4.75"
        width="14.5"
        height="12.5"
        rx="2"
        fill="none"
        stroke="var(--axis)"
        stroke-width="1.5"
      />
      <path d="M7 9.5h8M7 13h5" stroke="var(--grid)" stroke-width="1.5" stroke-linecap="round" />
    </svg>

    <p class="m-0 text-sm font-medium text-ink-secondary">{{ title }}</p>
    <p v-if="note" class="m-0 max-w-[46ch] text-xs leading-relaxed text-ink-muted">{{ note }}</p>
    <slot />
  </div>
</template>
