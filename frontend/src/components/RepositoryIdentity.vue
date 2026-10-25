<script setup>
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import { formatDateTimeWithZone } from '../lib/dashboard.js'
import AppIcon from './AppIcon.vue'

/**
 * A repository's name with its last successful scan time directly beneath it,
 * and the current scan status beside that. The name opens the report only
 * when a completed scan exists; until then it is plain text, so there is
 * never a link to an empty report. Both dashboard sections render this with
 * the same repositoryWorkflow() state, so they always agree.
 */
const props = defineProps({
  owner: { type: String, required: true },
  name: { type: String, required: true },
  state: { type: Object, required: true },
  timeZone: { type: String, required: true },
})

const exactTime = computed(() =>
  props.state.lastScannedAt ? `${formatDateTimeWithZone(props.state.lastScannedAt)} (${props.timeZone})` : undefined,
)

const STATUS_ICONS = { queued: 'clock', running: 'loader', failed: 'x-circle' }
const STATUS_CHIPS = { info: 'chip-info', danger: 'chip-danger' }
</script>

<template>
  <div class="min-w-0">
    <div class="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
      <RouterLink
        v-if="state.hasReport"
        :to="{ name: 'repository', params: { repoId: String(state.id) } }"
        class="min-w-0 truncate text-sm font-semibold text-ink no-underline decoration-accent underline-offset-2 hover:text-accent hover:underline"
        :title="`Open the report for ${owner}/${name}`"
      >
        <span class="font-normal text-ink-secondary">{{ owner }}/</span>{{ name }}
      </RouterLink>
      <span
        v-else
        class="min-w-0 cursor-default truncate text-sm font-semibold text-ink"
        title="Scan this repository to view its reports"
      >
        <span class="font-normal text-ink-secondary">{{ owner }}/</span>{{ name }}
        <span class="sr-only">(no report yet: scan this repository to view its reports)</span>
      </span>
      <slot name="badges" />
    </div>

    <div class="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1">
      <!-- The last successful scan, never a queued, running or failed one. -->
      <span class="nums text-xs text-ink-muted" :title="exactTime">{{ state.lastScannedText }}</span>
      <span v-if="state.status" class="chip" :class="STATUS_CHIPS[state.status.tone]" role="status">
        <AppIcon
          :name="STATUS_ICONS[state.status.key] ?? 'info'"
          :size="11"
          :stroke-width="2.25"
          :class="{ spin: state.status.key === 'running' }"
        />
        {{ state.status.label }}
      </span>
    </div>
    <slot />
  </div>
</template>
