<script setup>
import AppIcon from './AppIcon.vue'

// One security overview card: an icon, a label, the headline value and a
// line of context. tone tints the icon only; the value and note carry the
// meaning in words.
defineProps({
  label: { type: String, required: true },
  value: { type: [String, Number], default: '—' },
  icon: { type: String, default: 'info' },
  tone: {
    type: String,
    default: 'neutral',
    validator: (value) => ['neutral', 'info', 'success', 'warning', 'danger'].includes(value),
  },
  muted: { type: Boolean, default: false },
  loading: { type: Boolean, default: false },
})

const TONES = {
  neutral: 'border-hairline bg-surface-raised text-ink-secondary',
  info: 'border-[var(--tone-info-border)] bg-[var(--tone-info-bg)] text-[var(--tone-info-fg)]',
  success: 'border-[var(--tone-success-border)] bg-[var(--tone-success-bg)] text-[var(--tone-success-fg)]',
  warning: 'border-[var(--tone-warning-border)] bg-[var(--tone-warning-bg)] text-[var(--tone-warning-fg)]',
  danger: 'border-[var(--tone-danger-border)] bg-[var(--tone-danger-bg)] text-[var(--tone-danger-fg)]',
}
</script>

<template>
  <div class="card flex min-h-[148px] flex-col px-4 py-4 sm:px-5">
    <div class="flex items-center justify-between gap-3">
      <p class="m-0 text-[13px] font-medium text-ink-secondary">{{ label }}</p>
      <span class="flex size-8 items-center justify-center rounded-lg border" :class="TONES[tone]">
        <AppIcon :name="icon" :size="16" />
      </span>
    </div>
    <template v-if="loading">
      <div class="skeleton mt-3 h-8 w-20" aria-hidden="true" />
      <div class="skeleton mt-3 h-3 w-3/4" aria-hidden="true" />
      <span class="sr-only">Loading</span>
    </template>
    <template v-else>
      <p
        class="mt-2 mb-0 text-[28px] leading-tight font-semibold tracking-tight"
        :class="muted ? 'text-ink-muted' : 'text-ink'"
      >
        <slot name="value">{{ value }}</slot>
      </p>
      <div class="mt-auto pt-2 text-xs leading-relaxed text-ink-muted">
        <slot />
      </div>
    </template>
  </div>
</template>
