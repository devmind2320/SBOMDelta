<script setup>
import { RouterView } from 'vue-router'
import AppHeader from './components/AppHeader.vue'
</script>

<template>
  <div class="min-h-screen bg-plane">
    <a
      href="#main"
      class="sr-only rounded-md bg-surface px-3 py-2 text-sm text-ink focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50"
    >
      Skip to content
    </a>
    <AppHeader />
    <main id="main" class="mx-auto w-full max-w-[1280px] px-4 pt-6 pb-16 sm:px-6 sm:pt-8">
      <RouterView />
    </main>
  </div>
</template>
