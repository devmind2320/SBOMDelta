<script setup>
import { computed } from 'vue'
import { severityRole } from '../lib/format.js'

const props = defineProps({
  severity: { type: String, default: '' },
})

// Status colours are sub-3:1 against the light surface by design, so the glyph
// and the written label carry the meaning and the colour only reinforces it.
const ROLES = {
  critical: { label: 'Critical', color: 'var(--status-critical)', glyph: 'alert' },
  serious: { label: 'High', color: 'var(--status-serious)', glyph: 'alert' },
  warning: { label: 'Medium', color: 'var(--status-warning)', glyph: 'warn' },
  low: { label: 'Low', color: 'var(--ink-muted)', glyph: 'info' },
  unknown: { label: 'Unscored', color: 'var(--ink-muted)', glyph: 'info' },
}

const role = computed(() => ROLES[severityRole(props.severity)] ?? ROLES.unknown)
</script>

<template>
  <span
    class="inline-flex items-center gap-1.5 rounded-full border border-hairline px-2 py-0.5 text-xs font-medium text-ink-secondary"
  >
    <svg width="11" height="11" viewBox="0 0 11 11" aria-hidden="true">
      <template v-if="role.glyph === 'alert'">
        <circle cx="5.5" cy="5.5" r="4.5" :fill="role.color" />
        <path d="M5.5 3v3.1" stroke="var(--surface)" stroke-width="1.4" stroke-linecap="round" />
        <circle cx="5.5" cy="8.1" r="0.75" fill="var(--surface)" />
      </template>
      <template v-else-if="role.glyph === 'warn'">
        <path d="M5.5 1 10.4 9.7H0.6z" :fill="role.color" />
        <path d="M5.5 4.2v2.6" stroke="var(--surface)" stroke-width="1.3" stroke-linecap="round" />
        <circle cx="5.5" cy="8.4" r="0.65" fill="var(--surface)" />
      </template>
      <template v-else>
        <circle cx="5.5" cy="5.5" r="4.5" fill="none" :stroke="role.color" stroke-width="1.4" />
        <path d="M5.5 5v3" :stroke="role.color" stroke-width="1.4" stroke-linecap="round" />
        <circle cx="5.5" cy="3.2" r="0.7" :fill="role.color" />
      </template>
    </svg>
    {{ role.label }}
  </span>
</template>
