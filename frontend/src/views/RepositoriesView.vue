<script setup>
import { RouterLink } from 'vue-router'
import AppIcon from '../components/AppIcon.vue'
import PageHeader from '../components/PageHeader.vue'
import RepositorySections from '../components/RepositorySections.vue'

// The repository workspace: Tracked Repositories above All Repositories, with
// search, scanning and tracking. The dashboard links here rather than
// repeating these listings.
</script>

<template>
  <div class="flex flex-col gap-6 sm:gap-8">
    <PageHeader
      eyebrow="Workspace"
      title="Repositories"
      description="Scan any repository you can reach, and track the ones you want to monitor. Scanning and tracking are independent: a scan never tracks a repository, and tracking never starts a scan."
    >
      <template #actions>
        <RouterLink :to="{ name: 'last-scans' }" class="btn btn-secondary">
          <AppIcon name="history" :size="14" />
          Last Scans
        </RouterLink>
      </template>
    </PageHeader>

    <RepositorySections />
  </div>
</template>
