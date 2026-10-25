<script setup>
import AppIcon from './AppIcon.vue'

// A titled surface with optional actions and a footnote. Charts and tables sit
// in one of these so every block on the page shares the same chrome. flush
// drops the body padding for tables that run edge to edge.
defineProps({
  title: { type: String, required: true },
  subtitle: { type: String, default: '' },
  icon: { type: String, default: '' },
  flush: { type: Boolean, default: false },
  headingId: { type: String, default: '' },
})
</script>

<template>
  <section class="card overflow-hidden" :aria-labelledby="headingId || undefined">
    <header class="flex flex-wrap items-start justify-between gap-3 border-b border-hairline px-4 py-3.5 sm:px-5">
      <div class="flex min-w-0 items-start gap-2.5">
        <span
          v-if="icon"
          class="mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-lg border border-hairline bg-surface-raised text-ink-secondary"
        >
          <AppIcon :name="icon" :size="15" />
        </span>
        <div class="min-w-0">
          <h2 :id="headingId || undefined" class="m-0 text-[15px] font-semibold tracking-tight text-ink">
            {{ title }}
            <slot name="title-extra" />
          </h2>
          <p v-if="subtitle" class="mt-0.5 mb-0 text-xs leading-relaxed text-ink-muted">{{ subtitle }}</p>
        </div>
      </div>
      <div v-if="$slots.actions" class="flex flex-wrap items-center gap-2">
        <slot name="actions" />
      </div>
    </header>

    <div :class="flush ? '' : 'p-4 sm:p-5'">
      <slot />
    </div>

    <footer
      v-if="$slots.footer"
      class="border-t border-hairline bg-surface-raised px-4 py-2.5 text-xs text-ink-muted sm:px-5"
    >
      <slot name="footer" />
    </footer>
  </section>
</template>
