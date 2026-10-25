<script setup>
import DataCard from '../components/DataCard.vue'
import PageHeader from '../components/PageHeader.vue'
import RecentScansTable from '../components/RecentScansTable.vue'
import { viewerTimeZone } from '../lib/repositories.js'

const timeZone = viewerTimeZone()
</script>

<template>
  <div class="flex flex-col gap-6 sm:gap-8">
    <PageHeader
      eyebrow="History"
      title="Last Scans"
      description="Every recorded scan of your tracked repositories, newest first, across default branches and pull requests. Failed scans are listed with their reason; a failure means the analysis could not run, not that a problem was found."
    />

    <DataCard
      title="Recorded scans"
      icon="history"
      flush
      :subtitle="`The latest 100 scans. Times are shown in ${timeZone}.`"
    >
      <RecentScansTable :limit="100" />
    </DataCard>
  </div>
</template>
