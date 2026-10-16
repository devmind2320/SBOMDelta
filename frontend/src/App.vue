<script setup>
import { RouterView } from 'vue-router'
import AppHeader from './components/AppHeader.vue'
</script>

<template>
  <div class="min-h-screen bg-plane">
    <AppHeader />
    <main class="mx-auto w-full max-w-[1200px] px-4 py-8 sm:px-6">
      <RouterView />
    </main>
  </div>
</template>
