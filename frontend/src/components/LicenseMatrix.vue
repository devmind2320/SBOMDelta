<script setup>
import { computed } from 'vue'
import EmptyState from './EmptyState.vue'

/**
 * Which licenses appear in this scan, and which packages carry each.
 *
 * Deliberately a table rather than a coloured grid: license identifiers run
 * well past the ~7 classes at which colour categories start to blur, and
 * "allowed vs prohibited" is a policy question SBOMDelta does not answer. Until there is
 * a policy to check against, this reports composition and flags only the
 * licenses that are genuinely missing.
 */
const props = defineProps({
  components: { type: Array, default: () => [] },
})

// Copyleft families worth surfacing. This is an observation, not a verdict:
// whether a license is acceptable depends on a policy this app does not have
// yet, and how the dependency is linked.
const COPYLEFT = /^(GPL|AGPL|LGPL|SSPL|OSL|EUPL|CDDL|MPL)/i

const rows = computed(() => {
  const tally = new Map()

  for (const component of props.components) {
    const labels = component.licenseExpression
      ? [component.licenseExpression]
      : component.licenses?.length
        ? component.licenses
        : ['Unknown']

    for (const label of labels) {
      if (!tally.has(label)) tally.set(label, [])
      tally.get(label).push(component)
    }
  }

  return [...tally.entries()]
    .map(([license, packages]) => ({
      license,
      count: packages.length,
      // Only a handful are listed inline; the rest stay in the component table.
      sample: packages.slice(0, 4).map((component) => component.name),
      more: Math.max(0, packages.length - 4),
      copyleft: COPYLEFT.test(license),
      unknown: license === 'Unknown',
    }))
    .sort((a, b) => b.count - a.count || a.license.localeCompare(b.license))
})

const unknownCount = computed(() => rows.value.find((row) => row.unknown)?.count ?? 0)
</script>

<template>
  <EmptyState
    v-if="!components.length"
    title="No components to report licenses for"
  />

  <div v-else>
    <div class="overflow-x-auto">
      <table class="w-full border-collapse text-sm">
        <thead>
          <tr class="border-b border-hairline text-left">
            <th class="px-2 py-2 text-xs font-medium text-ink-muted">License</th>
            <th class="px-2 py-2 text-right text-xs font-medium text-ink-muted">Packages</th>
            <th class="px-2 py-2 text-xs font-medium text-ink-muted">Examples</th>
            <th class="px-2 py-2 text-xs font-medium text-ink-muted">Note</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.license" class="border-b border-hairline last:border-0">
            <td class="px-2 py-2 font-medium text-ink">{{ row.license }}</td>
            <td class="nums px-2 py-2 text-right text-ink-secondary">{{ row.count }}</td>
            <td class="px-2 py-2 text-xs text-ink-secondary">
              {{ row.sample.join(', ') }}<span v-if="row.more" class="text-ink-muted">
                and {{ row.more }} more</span>
            </td>
            <td class="px-2 py-2 text-xs">
              <!-- Icon plus words; never a bare coloured dot. -->
              <span v-if="row.unknown" class="flex items-center gap-1.5 text-ink-muted">
                <svg width="11" height="11" viewBox="0 0 11 11" aria-hidden="true">
                  <circle cx="5.5" cy="5.5" r="4.5" fill="none" stroke="var(--ink-muted)" stroke-width="1.4" />
                  <path d="M5.5 5v3" stroke="var(--ink-muted)" stroke-width="1.4" stroke-linecap="round" />
                  <circle cx="5.5" cy="3.2" r="0.7" fill="var(--ink-muted)" />
                </svg>
                Not declared in the SBOM
              </span>
              <span v-else-if="row.copyleft" class="flex items-center gap-1.5 text-ink-secondary">
                <svg width="11" height="11" viewBox="0 0 11 11" aria-hidden="true">
                  <path d="M5.5 1 10.4 9.7H0.6z" fill="var(--status-warning)" />
                  <path d="M5.5 4.2v2.6" stroke="var(--surface)" stroke-width="1.3" stroke-linecap="round" />
                  <circle cx="5.5" cy="8.4" r="0.65" fill="var(--surface)" />
                </svg>
                Copyleft family — review against your policy
              </span>
              <span v-else class="text-ink-muted">—</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <p class="mt-3 mb-0 text-xs leading-relaxed text-ink-muted">
      This table reports what the SBOM declares; SBOMDelta does not evaluate a license policy
      or decide whether a license is permitted.
      <template v-if="unknownCount">
        {{ unknownCount }} component(s) declare no license at all, which is a gap in the
        SBOM rather than a permissive default.
      </template>
    </p>
  </div>
</template>
