<script setup>
import { RouterLink } from 'vue-router'
import AppIcon from '../components/AppIcon.vue'
</script>

<template>
  <div class="flex justify-center py-16">
    <div class="card w-full max-w-md px-6 py-10 text-center">
      <span class="mx-auto flex size-11 items-center justify-center rounded-xl border border-hairline bg-surface-raised text-ink-muted">
        <AppIcon name="search" :size="20" />
      </span>
      <p class="eyebrow mt-5 mb-0">Error 404</p>
      <h1 class="mt-1 mb-0 text-xl font-semibold tracking-tight text-ink">Page not found</h1>
      <p class="mt-2 mb-0 text-sm text-ink-muted">That page does not exist, or the link is out of date.</p>
      <RouterLink :to="{ name: 'dashboard' }" class="btn btn-primary mt-6">
        <AppIcon name="dashboard" :size="14" />
        Go to the dashboard
      </RouterLink>
    </div>
  </div>
</template>
