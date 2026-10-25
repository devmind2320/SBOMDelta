import { reactive } from 'vue'
import { api } from '../api/client.js'
import { scanOutcomeMessage } from '../lib/dashboard.js'

/**
 * Scan, track and untrack, as the dashboard performs them. A repository with
 * a request in flight cannot be submitted again from this page, and the
 * server collapses duplicate scans of one commit into one job, so repeated
 * clicks never queue duplicates. Each action is independent: scanning never
 * tracks, and tracking never scans.
 *
 * onChanged runs after every action that succeeded, to reload what the page
 * shows from the server rather than guessing the new state.
 */
export function useRepositoryActions(onChanged = async () => {}) {
  // Keyed by the SBOMDelta repository id.
  const busy = reactive(new Set())
  const notices = reactive({})

  async function act(repositoryId, action, describe) {
    if (!repositoryId || busy.has(repositoryId)) return
    busy.add(repositoryId)
    delete notices[repositoryId]
    try {
      const result = await action()
      const text = describe?.(result)
      if (text) notices[repositoryId] = { tone: 'info', text }
      await onChanged()
    } catch (error) {
      // 401 and 403 are handled by the client (back to sign-in); the rest
      // carry the server's fixed explanation.
      notices[repositoryId] = { tone: 'danger', text: error.message }
    } finally {
      busy.delete(repositoryId)
    }
  }

  function scan(repositoryId) {
    return act(repositoryId, () => api.requestScan(repositoryId), ({ outcome }) => scanOutcomeMessage(outcome))
  }

  function track(repositoryId, { hasReport = false } = {}) {
    return act(
      repositoryId,
      () => api.track(repositoryId),
      () =>
        hasReport
          ? 'Tracked. It is now in Tracked Repositories.'
          : 'Tracked. It joins Tracked Repositories after its first completed scan; select Scan to run one.',
    )
  }

  function untrack(repositoryId) {
    return act(
      repositoryId,
      () => api.untrack(repositoryId),
      () => 'No longer tracked. Its scan history and reports are kept.',
    )
  }

  function dismiss(repositoryId) {
    delete notices[repositoryId]
  }

  return { busy, notices, scan, track, untrack, dismiss }
}
