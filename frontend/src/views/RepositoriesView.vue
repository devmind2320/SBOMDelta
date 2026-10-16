<script setup>
import { RouterLink } from 'vue-router'
import { api } from '../api/client.js'
import { useAsyncData } from '../composables/useAsyncData.js'
import { formatDate } from '../lib/format.js'
import DataCard from '../components/DataCard.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'

const { data: repositories, error, loading, reload } = useAsyncData(({ signal }) =>
  api.listRepositories({ signal }),
)
</script>

<template>
  <div class="flex flex-col gap-6">
    <div>
      <h1 class="m-0 text-xl font-semibold tracking-tight text-ink">Repositories</h1>
      <p class="mt-1 mb-0 text-sm text-ink-muted">
        Every repository the SBOMDelta GitHub App is installed on.
      </p>
    </div>

    <DataCard title="Tracked repositories">
      <p v-if="loading" class="m-0 py-6 text-center text-sm text-ink-muted">Loading…</p>
      <ErrorState v-else-if="error" :error="error" @retry="reload" />
      <EmptyState
        v-else-if="!repositories?.length"
        title="No repositories yet"
        note="Install the GitHub App on a repository and push a commit. The first scan records a baseline; the commit after it starts the drift history."
      />

      <ul v-else class="m-0 flex list-none flex-col p-0">
        <li
          v-for="repository in repositories"
          :key="repository.id"
          class="border-b border-hairline last:border-0"
        >
          <RouterLink
            :to="{ name: 'repository', params: { repoId: repository.id } }"
            class="flex flex-wrap items-center gap-x-3 gap-y-1 py-3 no-underline"
          >
            <span class="text-sm font-medium text-ink">
              {{ repository.owner }}/{{ repository.name }}
            </span>
            <span
              v-if="repository.private"
              class="rounded border border-hairline px-1.5 py-px text-[11px] text-ink-muted"
            >
              private
            </span>
            <span class="text-xs text-ink-muted">{{ repository.defaultBranch }}</span>
            <span class="ml-auto text-xs text-ink-muted">
              added {{ formatDate(repository.createdAt) }}
            </span>
          </RouterLink>
        </li>
      </ul>
    </DataCard>
  </div>
</template>
