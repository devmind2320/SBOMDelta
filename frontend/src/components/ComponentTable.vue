<script setup>
import { computed, ref } from 'vue'
import EmptyState from './EmptyState.vue'

const props = defineProps({
  components: { type: Array, default: () => [] },
})

const query = ref('')
const ecosystem = ref('all')
const directOnly = ref(false)

const ecosystems = computed(() => {
  const seen = new Set(props.components.map((component) => component.ecosystem).filter(Boolean))
  return ['all', ...[...seen].sort()]
})

const filtered = computed(() => {
  const needle = query.value.trim().toLowerCase()
  return props.components.filter((component) => {
    if (ecosystem.value !== 'all' && component.ecosystem !== ecosystem.value) return false
    if (directOnly.value && !component.direct) return false
    if (!needle) return true
    return (
      component.name.toLowerCase().includes(needle) ||
      (component.version ?? '').toLowerCase().includes(needle)
    )
  })
})

function licenseLabel(component) {
  if (component.licenseExpression) return component.licenseExpression
  if (component.licenses?.length) return component.licenses.join(', ')
  return ''
}
</script>

<template>
  <div>
    <!-- Filters sit in one row above the content they scope. -->
    <div class="mb-3 flex flex-wrap items-center gap-2">
      <input
        v-model="query"
        type="search"
        placeholder="Filter by name or version"
        class="input min-w-[180px] flex-1"
      />
      <select
        v-model="ecosystem"
        class="input w-auto"
        aria-label="Filter by ecosystem"
      >
        <option v-for="option in ecosystems" :key="option" :value="option">
          {{ option === 'all' ? 'All ecosystems' : option }}
        </option>
      </select>
      <label class="flex items-center gap-1.5 text-xs text-ink-secondary">
        <input v-model="directOnly" type="checkbox" class="accent-[var(--series-added)]" />
        Direct only
      </label>
      <span class="nums ml-auto text-xs text-ink-muted">
        {{ filtered.length }} of {{ components.length }}
      </span>
    </div>

    <EmptyState
      v-if="!components.length"
      title="No components recorded"
      note="This scan produced no SBOM entries. That usually means the repository has no recognizable dependency manifests."
    />
    <EmptyState
      v-else-if="!filtered.length"
      title="Nothing matches those filters"
    />

    <div v-else class="overflow-x-auto">
      <table class="w-full border-collapse text-sm">
        <thead>
          <tr class="border-b border-hairline text-left">
            <th class="px-2 py-2 text-xs font-medium text-ink-muted">Package</th>
            <th class="px-2 py-2 text-xs font-medium text-ink-muted">Version</th>
            <th class="px-2 py-2 text-xs font-medium text-ink-muted">Ecosystem</th>
            <th class="px-2 py-2 text-xs font-medium text-ink-muted">License</th>
            <th class="px-2 py-2 text-xs font-medium text-ink-muted">Scope</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="component in filtered"
            :key="component.purl"
            class="border-b border-hairline last:border-0"
          >
            <td class="px-2 py-2 font-medium text-ink">{{ component.name }}</td>
            <td class="nums px-2 py-2 text-ink-secondary">{{ component.version }}</td>
            <td class="px-2 py-2">
              <span class="rounded border border-hairline px-1.5 py-px text-[11px] text-ink-muted">
                {{ component.ecosystem }}
              </span>
            </td>
            <td class="px-2 py-2 text-xs text-ink-secondary">
              {{ licenseLabel(component) || '—' }}
            </td>
            <td class="px-2 py-2 text-xs text-ink-muted">
              {{ component.direct ? 'Direct' : 'Transitive' }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
