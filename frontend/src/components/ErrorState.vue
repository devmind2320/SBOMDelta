<script setup>
import AppIcon from './AppIcon.vue'

defineProps({
  error: { type: Object, default: null },
  compact: { type: Boolean, default: false },
})
defineEmits(['retry'])
</script>

<template>
  <!-- Icon plus label, so the failure never depends on the colour alone. -->
  <div
    role="alert"
    class="flex flex-col items-center gap-2 text-center"
    :class="compact ? 'px-2 py-4' : 'px-4 py-10'"
  >
    <span
      class="mb-1 flex size-10 items-center justify-center rounded-xl border border-[var(--tone-danger-border)] bg-[var(--tone-danger-bg)] text-[var(--tone-danger-fg)]"
    >
      <AppIcon name="alert-circle" :size="18" />
    </span>
    <p class="m-0 text-sm font-semibold text-ink">Could not load this</p>
    <p class="m-0 max-w-[56ch] text-[13px] leading-relaxed text-ink-muted">
      {{ error?.message ?? 'Something went wrong.' }}
    </p>
    <button type="button" class="btn btn-secondary btn-sm mt-1" @click="$emit('retry')">
      <AppIcon name="refresh" :size="13" />
      Try again
    </button>
  </div>
</template>
