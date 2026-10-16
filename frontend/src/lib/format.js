// Presentation helpers. Kept out of components so the same number or date
// reads identically everywhere it appears.

export function shortSha(sha) {
  return typeof sha === 'string' ? sha.slice(0, 7) : ''
}

/** Compacts large counts the way stat tiles expect: 1,284 / 12.9K / 1.2M. */
export function compactNumber(value) {
  if (value === null || value === undefined) return '—'
  const n = Number(value)
  if (!Number.isFinite(n)) return '—'
  if (Math.abs(n) >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`
  if (Math.abs(n) >= 10_000) return `${(n / 1000).toFixed(1).replace(/\.0$/, '')}K`
  return n.toLocaleString()
}

export function signedNumber(value) {
  if (value === null || value === undefined) return '—'
  const n = Number(value)
  if (!Number.isFinite(n)) return '—'
  return n > 0 ? `+${n}` : String(n)
}

export function formatDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

export function formatDateTime(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function relativeTime(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'

  const seconds = Math.round((Date.now() - date.getTime()) / 1000)
  const steps = [
    [60, 'second', 1],
    [3600, 'minute', 60],
    [86400, 'hour', 3600],
    [604800, 'day', 86400],
    [2629800, 'week', 604800],
    [31557600, 'month', 2629800],
  ]
  for (const [limit, unit, divisor] of steps) {
    if (Math.abs(seconds) < limit) {
      const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
      return formatter.format(-Math.round(seconds / divisor), unit)
    }
  }
  return new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
    .format(-Math.round(seconds / 31557600), 'year')
}

/** Normalizes the severity strings OSV uses into our four status roles. */
export function severityRole(severity) {
  switch (String(severity ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'critical'
    case 'HIGH':
      return 'serious'
    case 'MODERATE':
    case 'MEDIUM':
      return 'warning'
    case 'LOW':
      return 'low'
    default:
      return 'unknown'
  }
}
