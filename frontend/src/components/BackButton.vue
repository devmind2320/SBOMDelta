<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { backDecision } from '../lib/navigation.js'
import AppIcon from './AppIcon.vue'

// Back follows the browser history when the previous entry is another app
// page, and otherwise goes to the dashboard (see backDecision). On the
// dashboard with nowhere to return to, it is shown but inert.
const route = useRoute()
const router = useRouter()

// history.state changes with every navigation; reading route.fullPath makes
// this recompute then.
const decision = computed(() => {
  void route.fullPath
  return backDecision(typeof window === 'undefined' ? null : window.history.state, route.fullPath)
})

function goBack() {
  const next = decision.value
  if (next.kind === 'history') router.back()
  else if (next.kind === 'fallback') router.push(next.to)
}
</script>

<template>
  <button
    type="button"
    class="btn btn-ghost btn-sm -ml-1.5 gap-1.5 px-2"
    :aria-disabled="decision.kind === 'none' ? 'true' : undefined"
    :title="decision.kind === 'fallback' ? 'Back to the dashboard' : 'Go back'"
    @click="goBack"
  >
    <AppIcon name="arrow-left" :size="16" />
    <span>Back</span>
  </button>
</template>
