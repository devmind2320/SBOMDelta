import { onScopeDispose, watch } from 'vue'

/**
 * Calls tick every ms while active() is true, and not at all while the tab is
 * hidden: a background tab polling a scan nobody is watching is wasted
 * requests. Returning to the tab polls once straight away.
 */
export function usePolling(active, tick, ms = 5000) {
  let timer = null

  function stop() {
    clearInterval(timer)
    timer = null
  }
  function start() {
    if (timer || document.visibilityState === 'hidden') return
    timer = setInterval(tick, ms)
  }
  function onVisibility() {
    if (!active()) return
    if (document.visibilityState === 'hidden') stop()
    else {
      tick()
      start()
    }
  }

  watch(active, (on) => (on ? start() : stop()), { immediate: true })
  document.addEventListener('visibilitychange', onVisibility)
  onScopeDispose(() => {
    stop()
    document.removeEventListener('visibilitychange', onVisibility)
  })
}
