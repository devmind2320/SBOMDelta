<script setup>
// Skeleton rows while the first load is in flight. Later refetches keep the
// previous data on screen instead (see useAsyncData), so this shows once.
defineProps({
  rows: { type: Number, default: 3 },
  label: { type: String, default: 'Loading…' },
})
</script>

<template>
  <div role="status" aria-live="polite" class="flex flex-col gap-3 py-2">
    <span class="sr-only">{{ label }}</span>
    <div v-for="row in rows" :key="row" class="flex items-center gap-3" aria-hidden="true">
      <div class="skeleton size-8 shrink-0 rounded-lg" />
      <div class="flex flex-1 flex-col gap-1.5">
        <div class="skeleton h-3" :style="{ width: `${62 - row * 9}%` }" />
        <div class="skeleton h-2.5" :style="{ width: `${34 - row * 4}%` }" />
      </div>
    </div>
  </div>
</template>
