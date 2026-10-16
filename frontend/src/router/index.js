import { createRouter, createWebHistory } from 'vue-router'

// Views are lazily imported so the initial bundle carries only the shell and
// the repository list.
const routes = [
  {
    path: '/',
    name: 'repositories',
    component: () => import('../views/RepositoriesView.vue'),
    meta: { title: 'Repositories' },
  },
  {
    path: '/repos/:repoId',
    name: 'repository',
    component: () => import('../views/RepositoryView.vue'),
    props: true,
    meta: { title: 'Repository' },
  },
  {
    path: '/repos/:repoId/pulls',
    name: 'pull-requests',
    component: () => import('../views/PullRequestsView.vue'),
    props: true,
    meta: { title: 'Pull requests' },
  },
  {
    path: '/pulls/:pullId',
    name: 'pull-request',
    component: () => import('../views/PullRequestView.vue'),
    props: true,
    meta: { title: 'Pull request' },
  },
  {
    path: '/scans/:scanId',
    name: 'scan',
    component: () => import('../views/ScanView.vue'),
    props: true,
    meta: { title: 'Scan' },
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: () => import('../views/NotFoundView.vue'),
  },
]

export const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior: () => ({ top: 0 }),
})

router.afterEach((to) => {
  document.title = to.meta.title ? `${to.meta.title} · SBOMDelta` : 'SBOMDelta'
})
