<script setup>
import { toRef } from 'vue'
import { RouterLink } from 'vue-router'
import { api } from '../api/client.js'
import { useAsyncData } from '../composables/useAsyncData.js'
import DataCard from '../components/DataCard.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import ScanStatusBadge from '../components/ScanStatusBadge.vue'

const props = defineProps({ repoId: { type: String, required: true } })
const repoId = toRef(props, 'repoId')

const { data: pulls, error, loading, reload } = useAsyncData(
  ({ signal }) => api.listPullRequests(repoId.value, { signal }),
  { watch: [repoId] },
)
</script>

<template>
  <div class="flex flex-col gap-6">
    <div>
      <RouterLink
        :to="{ name: 'repository', params: { repoId } }"
        class="text-xs text-ink-muted no-underline"
      >
        ← Repository
      </RouterLink>
      <h1 class="mt-1.5 mb-0 text-xl font-semibold tracking-tight text-ink">Pull requests</h1>
      <p class="mt-1 mb-0 text-sm text-ink-muted">
        Each pull request is compared against its base commit, so the numbers show only
        what that pull request changes.
      </p>
    </div>

    <DataCard title="Open and recent pull requests">
      <p v-if="loading" class="m-0 py-6 text-center text-sm text-ink-muted">Loading…</p>
      <ErrorState v-else-if="error" :error="error" @retry="reload" />
      <EmptyState
        v-else-if="!pulls?.length"
        title="No pull requests seen yet"
        note="SBOMDelta records a pull request the first time it receives an opened or synchronize event for it."
      />

      <div v-else class="overflow-x-auto">
        <table class="w-full border-collapse text-sm">
          <thead>
            <tr class="border-b border-hairline text-left">
              <th class="px-2 py-2 text-xs font-medium text-ink-muted">PR</th>
              <th class="px-2 py-2 text-xs font-medium text-ink-muted">Title</th>
              <th class="px-2 py-2 text-xs font-medium text-ink-muted">Author</th>
              <th class="px-2 py-2 text-xs font-medium text-ink-muted">Scan</th>
              <th class="px-2 py-2 text-right text-xs font-medium text-ink-muted">Changes</th>
              <th class="px-2 py-2"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="pull in pulls" :key="pull.id" class="border-b border-hairline last:border-0">
              <td class="nums px-2 py-2 text-ink">#{{ pull.number }}</td>
              <td class="max-w-[34ch] px-2 py-2 text-ink-secondary">{{ pull.title || '—' }}</td>
              <td class="px-2 py-2 text-xs text-ink-muted">{{ pull.authorLogin || '—' }}</td>
              <td class="px-2 py-2">
                <ScanStatusBadge v-if="pull.scanStatus" :status="pull.scanStatus" />
                <span v-else class="text-xs text-ink-muted">Not scanned</span>
              </td>
              <td class="nums px-2 py-2 text-right text-xs text-ink-secondary">
                <template v-if="pull.scanId">
                  +{{ pull.added }} ~{{ pull.updated }} −{{ pull.removed }}
                </template>
                <template v-else>—</template>
              </td>
              <td class="px-2 py-2 text-right">
                <RouterLink
                  :to="{ name: 'pull-request', params: { pullId: pull.id } }"
                  class="text-xs text-ink-secondary underline decoration-hairline"
                >
                  View
                </RouterLink>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </DataCard>
  </div>
</template>
