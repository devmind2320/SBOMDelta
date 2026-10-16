<script setup>
import { RouterLink } from 'vue-router'
</script>

<template>
  <div class="flex flex-col items-center gap-3 py-20 text-center">
    <h1 class="m-0 text-xl font-semibold text-ink">Page not found</h1>
    <p class="m-0 text-sm text-ink-muted">That route does not exist.</p>
    <RouterLink
      :to="{ name: 'repositories' }"
      class="rounded-md border border-hairline bg-surface-raised px-3 py-1.5 text-sm text-ink-secondary no-underline"
    >
      Back to repositories
    </RouterLink>
  </div>
</template>
