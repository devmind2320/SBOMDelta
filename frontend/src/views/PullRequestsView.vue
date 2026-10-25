<script setup>
import { toRef } from 'vue'
import { RouterLink } from 'vue-router'
import { api } from '../api/client.js'
import { useAsyncData } from '../composables/useAsyncData.js'
import DataCard from '../components/DataCard.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import PageHeader from '../components/PageHeader.vue'
import ScanStatusBadge from '../components/ScanStatusBadge.vue'
import VulnSummary from '../components/VulnSummary.vue'

const props = defineProps({ repoId: { type: String, required: true } })
const repoId = toRef(props, 'repoId')

const { data: pulls, error, loading, reload } = useAsyncData(
  ({ signal }) => api.listPullRequests(repoId.value, { signal }),
  { watch: [repoId] },
)
</script>

<template>
  <div class="flex flex-col gap-6">
    <PageHeader
      title="Pull requests"
      description="Each pull request is compared against its base commit, so the numbers show only what that pull request changes."
    >
      <template #eyebrow>
        <RouterLink :to="{ name: 'repository', params: { repoId } }" class="text-ink-muted no-underline hover:text-ink">
          Repository report
        </RouterLink>
        <span class="mx-1.5" aria-hidden="true">/</span>Pull requests
      </template>
    </PageHeader>

    <DataCard title="Open and recent pull requests" icon="pull-request" flush>
      <div v-if="loading" class="p-5"><LoadingState /></div>
      <ErrorState v-else-if="error" :error="error" @retry="reload" />
      <EmptyState
        v-else-if="!pulls?.length"
        title="No pull requests seen yet"
        note="SBOMDelta records a pull request the first time it receives an opened or synchronize event for it."
      />

      <div v-else class="overflow-x-auto">
        <table class="data-table min-w-[720px]">
          <thead>
            <tr>
              <th class="pl-4 sm:pl-5">PR</th>
              <th>Title</th>
              <th>Author</th>
              <th>Scan</th>
              <th>Vulnerabilities</th>
              <th class="text-right">Changes</th>
              <th class="pr-4 sm:pr-5"><span class="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="pull in pulls" :key="pull.id">
              <td class="nums pl-4 font-semibold text-ink sm:pl-5">#{{ pull.number }}</td>
              <td class="max-w-[34ch] text-ink-secondary">
                {{ pull.title || '—' }}
                <span v-if="pull.state && pull.state !== 'open'" class="chip ml-1 capitalize">{{ pull.state }}</span>
              </td>
              <td class="text-xs text-ink-muted">{{ pull.authorLogin || '—' }}</td>
              <td>
                <ScanStatusBadge v-if="pull.scanStatus" :status="pull.scanStatus" />
                <span v-else class="text-xs text-ink-muted">Not scanned</span>
              </td>
              <td><VulnSummary :summary="pull.vulnerabilities ?? null" show-changes /></td>
              <td class="nums text-right text-xs text-ink-secondary">
                <template v-if="pull.scanId">
                  +{{ pull.added }} ~{{ pull.updated }} −{{ pull.removed }}
                </template>
                <template v-else>—</template>
              </td>
              <td class="pr-4 text-right sm:pr-5">
                <RouterLink :to="{ name: 'pull-request', params: { pullId: pull.id } }" class="btn btn-ghost btn-sm">
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
