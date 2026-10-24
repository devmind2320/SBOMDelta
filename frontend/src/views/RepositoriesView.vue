<script setup>
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import { api } from '../api/client.js'
import { useAsyncData } from '../composables/useAsyncData.js'
import { accessLabel, formatDate, isAccessible } from '../lib/format.js'
import DataCard from '../components/DataCard.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'

// One request for both lists: the split is cheap here and keeps the two
// sections from loading out of step with each other.
const { data: repositories, error, loading, reload } = useAsyncData(({ signal }) =>
  api.listRepositories({ signal, access: 'all' }),
)

const active = computed(() => (repositories.value ?? []).filter(isAccessible))
const inactive = computed(() => (repositories.value ?? []).filter((repo) => !isAccessible(repo)))
</script>

<template>
  <div class="flex flex-col gap-6">
    <div>
      <h1 class="m-0 text-xl font-semibold tracking-tight text-ink">Repositories</h1>
      <p class="mt-1 mb-0 text-sm text-ink-muted">
        Every repository SBOMDelta can currently reach through the GitHub App.
      </p>
    </div>

    <DataCard title="Tracked repositories">
      <p v-if="loading" class="m-0 py-6 text-center text-sm text-ink-muted">Loading…</p>
      <ErrorState v-else-if="error" :error="error" @retry="reload" />
      <EmptyState
        v-else-if="!active.length"
        title="No repositories yet"
        note="Install the GitHub App on a repository and push a commit. The first scan records a baseline; the commit after it starts the drift history."
      />

      <ul v-else class="m-0 flex list-none flex-col p-0">
        <li
          v-for="repository in active"
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

    <DataCard
      v-if="!loading && !error && inactive.length"
      title="No longer accessible"
      subtitle="SBOMDelta lost access to these. Their scan history is kept and still viewable, but they are no longer scanned."
    >
      <ul class="m-0 flex list-none flex-col p-0">
        <li
          v-for="repository in inactive"
          :key="repository.id"
          class="border-b border-hairline last:border-0"
        >
          <RouterLink
            :to="{ name: 'repository', params: { repoId: repository.id } }"
            class="flex flex-wrap items-center gap-x-3 gap-y-1 py-3 no-underline"
          >
            <span class="text-sm font-medium text-ink-secondary">
              {{ repository.owner }}/{{ repository.name }}
            </span>
            <span class="rounded border border-hairline px-1.5 py-px text-[11px] text-ink-muted">
              {{ accessLabel(repository.access) }}
            </span>
            <span v-if="repository.accessRevokedAt" class="ml-auto text-xs text-ink-muted">
              since {{ formatDate(repository.accessRevokedAt) }}
            </span>
          </RouterLink>
        </li>
      </ul>
    </DataCard>
  </div>
</template>
