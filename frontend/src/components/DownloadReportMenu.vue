<script setup>
import { nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { api } from '../api/client.js'
import AppIcon from './AppIcon.vue'

// Downloads a scan's SBOM report, as CSV for spreadsheets or PDF for people.
// The server sends each as an attachment, so following the link saves the
// file and leaves this page where it is.
const props = defineProps({ scanId: { type: [Number, String], required: true } })

const FORMATS = [
  { key: 'csv', label: 'CSV', description: 'One row per component, for spreadsheets' },
  { key: 'pdf', label: 'PDF', description: 'Summary, vulnerabilities and components' },
]

const open = ref(false)
const root = ref(null)
const trigger = ref(null)
const firstItem = ref(null)

function close({ focus = false } = {}) {
  open.value = false
  if (focus) trigger.value?.focus()
}

async function toggle() {
  open.value = !open.value
  if (open.value) {
    await nextTick()
    firstItem.value?.[0]?.focus()
  }
}

function onDocumentPointer(event) {
  if (open.value && root.value && !root.value.contains(event.target)) close()
}
function onKeydown(event) {
  if (event.key === 'Escape' && open.value) close({ focus: true })
}
watch(open, (isOpen) => {
  if (isOpen) {
    document.addEventListener('pointerdown', onDocumentPointer)
    document.addEventListener('keydown', onKeydown)
  } else {
    document.removeEventListener('pointerdown', onDocumentPointer)
    document.removeEventListener('keydown', onKeydown)
  }
})
onBeforeUnmount(() => {
  document.removeEventListener('pointerdown', onDocumentPointer)
  document.removeEventListener('keydown', onKeydown)
})

// The download is a plain navigation, which an expired session would turn
// into a page of raw JSON. Check the session first: a 401 or 403 goes to the
// sign-in page like any other request, and comes back here afterwards.
async function download(event) {
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
    return
  }
  event.preventDefault()
  const href = event.currentTarget.href
  close()
  try {
    await api.checkSession()
  } catch (error) {
    if (error?.status === 401 || error?.status === 403) return
  }
  window.location.assign(href)
}
</script>

<template>
  <div ref="root" class="relative">
    <button
      ref="trigger"
      type="button"
      class="btn btn-secondary"
      :aria-expanded="open"
      aria-haspopup="menu"
      @click="toggle"
    >
      <AppIcon name="download" :size="14" />
      Download SBOM report
      <AppIcon name="chevron-down" :size="14" class="text-ink-muted" />
    </button>

    <div
      v-if="open"
      role="menu"
      aria-label="Report format"
      class="absolute right-0 z-50 mt-2 w-72 rounded-xl border border-hairline bg-surface-overlay p-1.5 shadow-[var(--shadow-lg)]"
    >
      <a
        v-for="format in FORMATS"
        :key="format.key"
        ref="firstItem"
        role="menuitem"
        :href="api.reportDownloadUrl(props.scanId, format.key)"
        class="flex flex-col rounded-lg px-3 py-2 text-sm text-ink-secondary no-underline hover:bg-surface-muted hover:text-ink"
        @click="download"
      >
        <span class="font-medium text-ink">{{ format.label }}</span>
        <span class="text-xs text-ink-muted">{{ format.description }}</span>
      </a>
    </div>
  </div>
</template>
