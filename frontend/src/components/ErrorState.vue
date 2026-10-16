<script setup>
defineProps({
  error: { type: Object, default: null },
})
defineEmits(['retry'])
</script>

<template>
  <div class="flex flex-col items-center gap-3 px-4 py-10 text-center">
    <!-- Icon plus label, so the failure never depends on the colour alone. -->
    <div class="flex items-center gap-2">
      <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true">
        <circle cx="9" cy="9" r="7.25" fill="none" stroke="var(--status-critical)" stroke-width="1.5" />
        <path
          d="M9 5.25v4.5"
          stroke="var(--status-critical)"
          stroke-width="1.5"
          stroke-linecap="round"
        />
        <circle cx="9" cy="12.4" r="0.9" fill="var(--status-critical)" />
      </svg>
      <p class="m-0 text-sm font-medium text-ink">Could not load this</p>
    </div>
    <p class="m-0 max-w-[52ch] text-xs leading-relaxed text-ink-muted">
      {{ error?.message ?? 'Something went wrong.' }}
    </p>
    <button
      type="button"
      class="cursor-pointer rounded-md border border-hairline bg-surface-raised px-3 py-1.5 text-xs text-ink-secondary"
      @click="$emit('retry')"
    >
      Try again
    </button>
  </div>
</template>
