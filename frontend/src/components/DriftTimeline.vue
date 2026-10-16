<script setup>
import { computed, onBeforeUnmount, onMounted, ref, shallowRef } from 'vue'
import { formatDateTime, shortSha } from '../lib/format.js'
import EmptyState from './EmptyState.vue'

/**
 * Dependency drift over time: one stacked column per scan, split into added,
 * updated and removed.
 *
 * Deliberately NOT plotted here: the total component count. It lives in the
 * hundreds while the change counts live in single digits, and putting them on
 * one plot would need a second y-axis -- which invents a correlation that is
 * not in the data. It is a stat tile instead.
 */
const props = defineProps({
  // Newest-first, as the API returns it.
  timeline: { type: Array, default: () => [] },
})

const SERIES = [
  { key: 'added', label: 'Added', color: 'var(--series-added)' },
  { key: 'updated', label: 'Updated', color: 'var(--series-updated)' },
  { key: 'removed', label: 'Removed', color: 'var(--series-removed)' },
]

const BAR_MAX = 24 // Never fill the band; the leftover is air.
const GAP = 2 // Surface gap separating touching marks.
const CAP = 4 // Rounded data-end, square at the baseline.
const PAD = { top: 16, right: 12, bottom: 30, left: 38 }
const PLOT_HEIGHT = 190

const view = ref('chart')
const activeIndex = ref(null)
const container = shallowRef(null)
const width = ref(720)

// The bar-thickness cap is in real pixels, so the layout is measured rather
// than scaled by a viewBox.
let observer = null
onMounted(() => {
  if (!container.value) return
  observer = new ResizeObserver((entries) => {
    const measured = entries[0]?.contentRect?.width
    if (measured) width.value = Math.max(320, measured)
  })
  observer.observe(container.value)
})
onBeforeUnmount(() => observer?.disconnect())

// Oldest on the left is how a timeline reads.
const points = computed(() =>
  [...props.timeline].reverse().map((point) => ({
    ...point,
    total: (point.added ?? 0) + (point.updated ?? 0) + (point.removed ?? 0),
  })),
)

const plotWidth = computed(() => Math.max(10, width.value - PAD.left - PAD.right))
const band = computed(() => (points.value.length ? plotWidth.value / points.value.length : 0))
const barWidth = computed(() => Math.max(3, Math.min(BAR_MAX, band.value - 8)))
const baseline = computed(() => PAD.top + PLOT_HEIGHT)

/** Rounds a maximum up to a clean tick value so the axis reads in whole steps. */
const ticks = computed(() => {
  const peak = Math.max(1, ...points.value.map((point) => point.total))
  const step = peak <= 4 ? 1 : peak <= 8 ? 2 : peak <= 20 ? 5 : Math.ceil(peak / 4 / 10) * 10
  const top = Math.ceil(peak / step) * step
  const values = []
  for (let value = 0; value <= top; value += step) values.push(value)
  return { values, top }
})

const scale = computed(() => PLOT_HEIGHT / (ticks.value.top || 1))

function bandX(index) {
  return PAD.left + band.value * index
}

function barX(index) {
  return bandX(index) + (band.value - barWidth.value) / 2
}

/** Square at the baseline, rounded only on the data-end. */
function capPath(x, y, w, h, round) {
  const radius = round ? Math.min(CAP, h / 2, w / 2) : 0
  if (radius <= 0) return `M${x} ${y}h${w}v${h}h${-w}Z`
  return (
    `M${x} ${y + radius}` +
    `a${radius} ${radius} 0 0 1 ${radius} ${-radius}` +
    `h${w - radius * 2}` +
    `a${radius} ${radius} 0 0 1 ${radius} ${radius}` +
    `v${h - radius}h${-w}Z`
  )
}

/** Stacks each column from the baseline up, inserting the surface gap between
 *  segments and rounding only the topmost one. */
const columns = computed(() =>
  points.value.map((point, index) => {
    const present = SERIES.filter((series) => (point[series.key] ?? 0) > 0)
    let cumulative = 0
    const segments = []

    present.forEach((series, position) => {
      const value = point[series.key] ?? 0
      const bottom = baseline.value - cumulative * scale.value
      const full = value * scale.value
      // Every segment above the first gives up 2px at its base for the gap.
      const height = position === 0 ? full : full - GAP
      cumulative += value

      if (height > 0.5) {
        segments.push({
          key: series.key,
          label: series.label,
          color: series.color,
          value,
          path: capPath(
            barX(index),
            bottom - full,
            barWidth.value,
            height,
            position === present.length - 1,
          ),
        })
      }
    })

    return { point, index, segments, topY: baseline.value - point.total * scale.value }
  }),
)

// Label the endpoint only. A number on every column is chaos and goes unread;
// the axis and the tooltip carry the rest.
const endpointLabel = computed(() => {
  const last = columns.value.at(-1)
  if (!last || last.point.total === 0) return null
  if (barWidth.value < 14) return null // Would not fit without clipping.
  return { x: barX(last.index) + barWidth.value / 2, y: last.topY - 6, total: last.point.total }
})

/** Shows roughly five date labels, so ticks never collide. */
const xLabels = computed(() => {
  const count = points.value.length
  if (!count) return []
  const stride = Math.max(1, Math.ceil(count / Math.max(2, Math.floor(plotWidth.value / 110))))
  return columns.value
    .filter((column) => column.index % stride === 0 || column.index === count - 1)
    .map((column) => ({
      x: bandX(column.index) + band.value / 2,
      label: new Date(column.point.createdAt).toLocaleDateString(undefined, {
        month: 'short',
        day: 'numeric',
      }),
    }))
})

const active = computed(() =>
  activeIndex.value === null ? null : (columns.value[activeIndex.value] ?? null),
)

// Keeps the tooltip inside the plot instead of letting it run off an edge.
const tooltipStyle = computed(() => {
  if (!active.value) return {}
  const center = bandX(active.value.index) + band.value / 2
  const clamped = Math.min(Math.max(center, 90), width.value - 90)
  return { left: `${clamped}px`, top: `${PAD.top}px` }
})

const totals = computed(() =>
  SERIES.map((series) => ({
    ...series,
    total: points.value.reduce((sum, point) => sum + (point[series.key] ?? 0), 0),
  })),
)
</script>

<template>
  <div>
    <!-- The table view is this chart's relief for a series hue that sits below
         3:1 against the light surface, and its keyboard-free path to every
         value. It is not optional chrome. -->
    <div class="mb-3 flex items-center justify-between gap-3">
      <div class="flex flex-wrap items-center gap-x-4 gap-y-1.5">
        <span v-for="series in totals" :key="series.key" class="flex items-center gap-1.5">
          <!-- Legend mirrors the mark: a rect for bars. -->
          <span class="h-2.5 w-3 rounded-[2px]" :style="{ background: series.color }" />
          <span class="text-xs text-ink-secondary">{{ series.label }}</span>
          <span class="nums text-xs text-ink-muted">{{ series.total }}</span>
        </span>
      </div>

      <div class="flex shrink-0 overflow-hidden rounded-md border border-hairline">
        <button
          v-for="mode in ['chart', 'table']"
          :key="mode"
          type="button"
          class="cursor-pointer px-2.5 py-1 text-xs capitalize"
          :class="
            view === mode ? 'bg-surface-raised text-ink' : 'bg-transparent text-ink-muted'
          "
          :aria-pressed="view === mode"
          @click="view = mode"
        >
          {{ mode }}
        </button>
      </div>
    </div>

    <EmptyState
      v-if="!points.length"
      title="No completed scans yet"
      note="Push a dependency change to a tracked repository and the timeline will fill in."
    />

    <div v-else-if="view === 'chart'" ref="container" class="relative">
      <svg
        :width="width"
        :height="PAD.top + PLOT_HEIGHT + PAD.bottom"
        role="img"
        :aria-label="`Dependency changes across the last ${points.length} scans`"
        class="block max-w-full"
      >
        <!-- Gridlines: solid hairlines one step off the surface, recessive. -->
        <g>
          <line
            v-for="tick in ticks.values"
            :key="`grid-${tick}`"
            :x1="PAD.left"
            :x2="width - PAD.right"
            :y1="baseline - tick * scale"
            :y2="baseline - tick * scale"
            :stroke="tick === 0 ? 'var(--axis)' : 'var(--grid)'"
            stroke-width="1"
          />
          <text
            v-for="tick in ticks.values"
            :key="`tick-${tick}`"
            :x="PAD.left - 8"
            :y="baseline - tick * scale + 3.5"
            text-anchor="end"
            class="nums"
            font-size="10"
            fill="var(--ink-muted)"
          >
            {{ tick }}
          </text>
        </g>

        <!-- Marks. Non-hovered columns recede so the hovered one reads as lifted. -->
        <g>
          <g
            v-for="column in columns"
            :key="column.point.scanId"
            :opacity="activeIndex === null || activeIndex === column.index ? 1 : 0.45"
          >
            <path
              v-for="segment in column.segments"
              :key="segment.key"
              :d="segment.path"
              :fill="segment.color"
            />
          </g>
        </g>

        <!-- Endpoint label only, in an ink token rather than a series colour. -->
        <text
          v-if="endpointLabel"
          :x="endpointLabel.x"
          :y="endpointLabel.y"
          text-anchor="middle"
          class="nums"
          font-size="10"
          font-weight="600"
          fill="var(--ink-secondary)"
        >
          {{ endpointLabel.total }}
        </text>

        <g>
          <text
            v-for="label in xLabels"
            :key="label.x"
            :x="label.x"
            :y="baseline + 16"
            text-anchor="middle"
            font-size="10"
            fill="var(--ink-muted)"
          >
            {{ label.label }}
          </text>
        </g>

        <!-- On bars the mark is the hit target, and the target is the whole
             band so nobody has to aim at a 3px column. -->
        <g>
          <rect
            v-for="column in columns"
            :key="`hit-${column.point.scanId}`"
            :x="bandX(column.index)"
            :y="PAD.top"
            :width="Math.max(band, 24)"
            :height="PLOT_HEIGHT"
            fill="transparent"
            tabindex="0"
            class="cursor-pointer outline-none"
            :aria-label="`${formatDateTime(column.point.createdAt)}: ${column.point.added} added, ${column.point.updated} updated, ${column.point.removed} removed`"
            @pointerenter="activeIndex = column.index"
            @pointermove="activeIndex = column.index"
            @pointerleave="activeIndex = null"
            @focus="activeIndex = column.index"
            @blur="activeIndex = null"
          />
        </g>
      </svg>

      <!-- One tooltip lists every series, so the pointer never has to land on
           a specific segment to read its value. -->
      <div
        v-if="active"
        class="pointer-events-none absolute w-[180px] -translate-x-1/2 rounded-md border border-hairline bg-surface-raised px-2.5 py-2 shadow-sm"
        :style="tooltipStyle"
      >
        <p class="m-0 text-[11px] text-ink-muted">
          {{ formatDateTime(active.point.createdAt) }}
        </p>
        <p class="nums m-0 text-[11px] text-ink-muted">
          {{ shortSha(active.point.commitSha) }}
        </p>
        <div class="mt-1.5 flex flex-col gap-1">
          <!-- Values lead, labels follow: here the reader has the series and
               wants the number. -->
          <div v-for="series in SERIES" :key="series.key" class="flex items-center gap-1.5">
            <span class="h-0.5 w-3 rounded-full" :style="{ background: series.color }" />
            <span class="nums text-xs font-semibold text-ink">{{ active.point[series.key] }}</span>
            <span class="text-[11px] text-ink-muted">{{ series.label }}</span>
          </div>
        </div>
        <p class="mt-1.5 mb-0 border-t border-hairline pt-1.5 text-[11px] text-ink-secondary">
          {{ active.point.componentCount }} components total
        </p>
      </div>
    </div>

    <div v-else class="overflow-x-auto">
      <table class="w-full border-collapse text-sm">
        <thead>
          <tr class="border-b border-hairline text-left">
            <th class="px-2 py-2 text-xs font-medium text-ink-muted">Scan</th>
            <th class="px-2 py-2 text-xs font-medium text-ink-muted">Commit</th>
            <th class="px-2 py-2 text-right text-xs font-medium text-ink-muted">Added</th>
            <th class="px-2 py-2 text-right text-xs font-medium text-ink-muted">Updated</th>
            <th class="px-2 py-2 text-right text-xs font-medium text-ink-muted">Removed</th>
            <th class="px-2 py-2 text-right text-xs font-medium text-ink-muted">Components</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="point in timeline"
            :key="point.scanId"
            class="border-b border-hairline last:border-0"
          >
            <td class="px-2 py-2 text-xs text-ink-secondary">
              {{ formatDateTime(point.createdAt) }}
            </td>
            <td class="nums px-2 py-2 text-xs text-ink-secondary">
              {{ shortSha(point.commitSha) }}
            </td>
            <td class="nums px-2 py-2 text-right text-ink">{{ point.added }}</td>
            <td class="nums px-2 py-2 text-right text-ink">{{ point.updated }}</td>
            <td class="nums px-2 py-2 text-right text-ink">{{ point.removed }}</td>
            <td class="nums px-2 py-2 text-right text-ink-secondary">
              {{ point.componentCount }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
