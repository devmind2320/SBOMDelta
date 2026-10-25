import { createRouter, createWebHistory } from 'vue-router'
import { setUnauthenticatedHandler } from '../api/client.js'
import { useSession } from '../composables/useSession.js'
import { routeDecision, takeReturnTo } from '../lib/auth.js'

// Views are lazily imported so the initial bundle carries only the shell and
// the repository list.
const routes = [
  {
    path: '/login',
    name: 'login',
    component: () => import('../views/LoginView.vue'),
    meta: { title: 'Sign in', public: true },
  },
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

const session = useSession()

function tabStorage() {
  try {
    return window.sessionStorage
  } catch {
    return null
  }
}

// Every page but the sign-in page needs a session. The API enforces this on
// its own; the guard only spares people a page of 401 errors. routeDecision
// (lib/auth.js) never sends a navigation anywhere it would redirect again.
router.beforeEach(async (to) => {
  let user = null
  try {
    user = await session.loadSession()
  } catch {
    // The API is unreachable. Let the page load and show its own error.
    return true
  }
  if (user) {
    // Back from GitHub, the callback lands on /. Continue to where the person
    // was going when they were sent to sign in (remembered by LoginView).
    const back = takeReturnTo(tabStorage())
    if (back && to.path === '/' && back !== '/') return back
  }
  return routeDecision(to, { user, disallowed: session.disallowed.value })
})

// A session that expires, or an account removed from the allowlist, surfaces
// as a 401 or 403 from any API call: go to the sign-in page, which explains,
// and remember the page to come back to.
setUnauthenticatedHandler((reason) => {
  session.reset(reason)
  const current = router.currentRoute.value
  if (current.name === 'login') return
  const decision = routeDecision(current, { user: null, disallowed: reason === 'not_allowed' })
  if (decision !== true) router.push(decision)
})

router.afterEach((to) => {
  document.title = to.meta.title ? `${to.meta.title} · SBOMDelta` : 'SBOMDelta'
})
