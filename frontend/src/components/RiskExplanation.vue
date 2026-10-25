<script setup>
import { toRef } from 'vue'
import { api } from '../api/client.js'
import { useAsyncData } from '../composables/useAsyncData.js'
import { formatScore } from '../lib/intelligence.js'
import ErrorState from './ErrorState.vue'
import SeverityPill from './SeverityPill.vue'

/**
 * Why a scan has the risk score it has: every factor with its points, the
 * findings that contribute most, and the rule that turns them into a score.
 * Loaded when shown, so a dashboard of many repositories stays one request.
 */
const props = defineProps({ scanId: { type: Number, required: true } })
const scanId = toRef(props, 'scanId')

const risk = useAsyncData(({ signal }) => api.getRisk(scanId.value, { signal }), { watch: [scanId] })
</script>

<template>
  <div class="rounded-lg border border-hairline bg-surface-raised px-4 py-3 text-xs">
    <p v-if="risk.loading.value" class="m-0 text-ink-muted">Loading the explanation…</p>
    <ErrorState v-else-if="risk.error.value" compact :error="risk.error.value" @retry="risk.reload" />
    <template v-else-if="risk.data.value && !risk.data.value.scored">
      <p class="m-0 text-ink-secondary">Not scored. {{ risk.data.value.reason }}</p>
    </template>
    <template v-else-if="risk.data.value">
      <p class="m-0 text-ink">
        Score <strong class="nums">{{ formatScore(risk.data.value.assessment.score) }}</strong>
        ({{ risk.data.value.assessment.level }})
        <template v-if="risk.data.value.assessment.uncapped > risk.data.value.assessment.score">
          — capped from <span class="nums">{{ formatScore(risk.data.value.assessment.uncapped) }}</span>
        </template>
      </p>
      <p v-if="!risk.data.value.assessment.factors.length" class="mt-1 mb-0 text-ink-secondary">
        No known vulnerabilities in the checked components, so nothing adds to the score.
      </p>
      <ul v-else class="mt-1.5 mb-0 flex list-none flex-col gap-1 p-0">
        <li v-for="factor in risk.data.value.assessment.factors" :key="factor.key" class="flex gap-2">
          <span class="nums w-12 shrink-0 text-right text-ink">+{{ formatScore(factor.points) }}</span>
          <span class="text-ink-secondary">
            {{ factor.label }} <span class="text-ink-muted">— {{ factor.explanation }}</span>
          </span>
        </li>
      </ul>
      <template v-if="risk.data.value.assessment.top.length">
        <p class="mt-2.5 mb-1 text-ink-muted">Largest contributors</p>
        <ul class="m-0 flex list-none flex-col gap-1 p-0">
          <li
            v-for="item in risk.data.value.assessment.top.slice(0, 5)"
            :key="`${item.purl}-${item.osvId}`"
            class="flex flex-wrap items-center gap-2"
          >
            <span class="nums w-12 shrink-0 text-right text-ink">+{{ formatScore(item.points) }}</span>
            <SeverityPill :severity="item.severity" />
            <span class="nums text-ink">{{ item.osvId }}</span>
            <span class="text-ink-secondary">{{ item.package }} {{ item.version }}</span>
            <span class="text-ink-muted">
              {{ item.fixedVersion ? `fixed in ${item.fixedVersion}` : 'no fix published' }}
              {{ item.direct ? '· direct dependency' : '' }}
            </span>
          </li>
        </ul>
      </template>
      <p class="mt-2.5 mb-0 leading-relaxed text-ink-muted">{{ risk.data.value.method }}</p>
    </template>
  </div>
</template>
