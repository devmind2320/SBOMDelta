<script setup>
import { computed } from 'vue'
import { useTheme } from '../composables/useTheme.js'
import AppIcon from './AppIcon.vue'

const { theme, toggle } = useTheme()

// The icon shows the theme a click switches to, and the label says so.
const label = computed(() => (theme.value === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'))
</script>

<template>
  <button type="button" class="icon-btn" :aria-label="label" :title="label" @click="toggle">
    <AppIcon :name="theme === 'dark' ? 'sun' : 'moon'" :size="16" />
  </button>
</template>
