import { ref, shallowRef, watch, onScopeDispose } from 'vue'

/**
 * Runs an async loader and tracks its state.
 *
 * Refetching keeps the previous data visible (flagged by `refetching`) rather
 * than clearing it, so a poll or a filter change never blanks the screen. In
 * flight requests are aborted when the source changes or the scope is
 * disposed, which stops a slow response from overwriting a newer one.
 *
 * @param {(ctx: {signal: AbortSignal}) => Promise<any>} loader
 * @param {{ watch?: import('vue').WatchSource[], immediate?: boolean }} options
 */
export function useAsyncData(loader, { watch: sources = [], immediate = true } = {}) {
  const data = shallowRef(null)
  const error = ref(null)
  const loading = ref(false)
  const refetching = ref(false)

  let controller = null

  async function load() {
    controller?.abort()
    controller = new AbortController()
    const current = controller

    // The very first load shows a loading state; later ones hold the old data.
    if (data.value === null) loading.value = true
    else refetching.value = true
    error.value = null

    try {
      const result = await loader({ signal: current.signal })
      if (current.signal.aborted) return
      data.value = result
    } catch (cause) {
      if (cause.name === 'AbortError') return
      error.value = cause
    } finally {
      if (!current.signal.aborted) {
        loading.value = false
        refetching.value = false
      }
    }
  }

  if (sources.length > 0) {
    watch(sources, load, { immediate })
  } else if (immediate) {
    load()
  }

  onScopeDispose(() => controller?.abort())

  return { data, error, loading, refetching, reload: load }
}
