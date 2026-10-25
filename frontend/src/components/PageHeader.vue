<script setup>
// The title block every page opens with: an optional breadcrumb-style
// eyebrow, the title, a one-line description and page-level actions.
defineProps({
  title: { type: String, default: '' },
  eyebrow: { type: String, default: '' },
  description: { type: String, default: '' },
})
</script>

<template>
  <div class="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
    <div class="min-w-0">
      <p v-if="eyebrow || $slots.eyebrow" class="eyebrow m-0 mb-1.5">
        <slot name="eyebrow">{{ eyebrow }}</slot>
      </p>
      <h1 class="m-0 text-2xl font-semibold tracking-tight break-words text-ink">
        <slot name="title">{{ title }}</slot>
      </h1>
      <p v-if="description || $slots.description" class="mt-1.5 mb-0 max-w-[72ch] text-sm leading-relaxed text-ink-muted">
        <slot name="description">{{ description }}</slot>
      </p>
    </div>
    <div v-if="$slots.actions" class="flex flex-wrap items-center gap-2">
      <slot name="actions" />
    </div>
  </div>
</template>
