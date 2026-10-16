<script setup>
import { computed } from 'vue'
import EmptyState from './EmptyState.vue'

/** The added / updated / removed breakdown for one scan, grouped by change
 *  type so the three answers stay visually separate. */
const props = defineProps({
  driftEvents: { type: Array, default: () => [] },
  baseline: { type: Boolean, default: false },
})

const GROUPS = [
  { type: 'added', label: 'Added', color: 'var(--series-added)', sign: '+' },
  { type: 'updated', label: 'Updated', color: 'var(--series-updated)', sign: '~' },
  { type: 'removed', label: 'Removed', color: 'var(--series-removed)', sign: '−' },
]

const grouped = computed(() =>
  GROUPS.map((group) => ({
    ...group,
    events: props.driftEvents.filter((event) => event.changeType === group.type),
  })).filter((group) => group.events.length > 0),
)

function arrow(event) {
  return event.direction === 'downgrade' ? '↓' : '→'
}
</script>

<template>
  <EmptyState
    v-if="baseline"
    title="Baseline scan"
    note="This is the first scan of the repository, so there is nothing to compare against yet. The next commit will be measured against this one."
  />
  <EmptyState
    v-else-if="!grouped.length"
    title="No dependency changes"
    note="The dependency set is identical to the base scan."
  />

  <div v-else class="flex flex-col gap-5">
    <div v-for="group in grouped" :key="group.type">
      <div class="mb-2 flex items-center gap-2">
        <span class="h-2.5 w-3 rounded-[2px]" :style="{ background: group.color }" />
        <h3 class="m-0 text-xs font-semibold text-ink-secondary">{{ group.label }}</h3>
        <span class="nums text-xs text-ink-muted">{{ group.events.length }}</span>
      </div>

      <ul class="m-0 flex list-none flex-col gap-0 p-0">
        <li
          v-for="event in group.events"
          :key="`${event.changeType}-${event.purl}`"
          class="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 border-b border-hairline py-1.5 last:border-0"
        >
          <span class="nums w-4 shrink-0 text-xs text-ink-muted">{{ group.sign }}</span>
          <span
            class="rounded border border-hairline px-1.5 py-px text-[11px] text-ink-muted"
          >
            {{ event.ecosystem }}
          </span>
          <span class="text-sm font-medium text-ink">{{ event.name }}</span>

          <span v-if="group.type === 'updated'" class="nums text-xs text-ink-secondary">
            {{ event.oldVersion }} {{ arrow(event) }} {{ event.newVersion }}
          </span>
          <span v-else class="nums text-xs text-ink-secondary">
            {{ event.newVersion || event.oldVersion }}
          </span>

          <span
            v-if="event.direction === 'downgrade'"
            class="text-[11px] text-ink-muted"
            title="The new version is lower than the old one"
          >
            downgrade
          </span>
          <span
            v-else-if="event.direction === 'unknown' && group.type === 'updated'"
            class="text-[11px] text-ink-muted"
            title="This ecosystem does not use semantic versioning, so the direction cannot be determined"
          >
            direction unknown
          </span>
        </li>
      </ul>
    </div>
  </div>
</template>
