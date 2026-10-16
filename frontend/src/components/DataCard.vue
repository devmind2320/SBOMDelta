<script setup>
// A titled surface with optional actions and a footnote. Charts and tables sit
// in one of these so every block on the page shares the same chrome.
defineProps({
  title: { type: String, required: true },
  subtitle: { type: String, default: '' },
})
</script>

<template>
  <section class="rounded-lg border border-hairline bg-surface">
    <header
      class="flex flex-wrap items-start justify-between gap-3 border-b border-hairline px-4 py-3"
    >
      <div>
        <h2 class="m-0 text-sm font-semibold text-ink">{{ title }}</h2>
        <p v-if="subtitle" class="mt-0.5 mb-0 text-xs text-ink-muted">{{ subtitle }}</p>
      </div>
      <div v-if="$slots.actions" class="flex items-center gap-2">
        <slot name="actions" />
      </div>
    </header>

    <div class="p-4">
      <slot />
    </div>

    <footer v-if="$slots.footer" class="border-t border-hairline px-4 py-2.5 text-xs text-ink-muted">
      <slot name="footer" />
    </footer>
  </section>
</template>
